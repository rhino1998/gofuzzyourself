package fuzzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/google/skylark"
	"github.com/google/skylark/resolve"
	"github.com/pkg/errors"
)

func init() {
	resolve.AllowLambda = true
	resolve.AllowSet = true
	resolve.AllowFloat = true
	resolve.AllowNestedDef = true
}

func shallowCopyGlobals(globals skylark.StringDict) skylark.StringDict {
	cpy := make(skylark.StringDict)
	for k, v := range globals {
		cpy[k] = v
	}
	return cpy
}

//Definition describes a fuzzer test batch
type Definition struct {
	globals skylark.StringDict

	tests       []string
	runs        int
	format      string
	errorFormat string

	args   []ReaderGenerator
	vars   map[string]ReaderGenerator
	stdin  ReaderGenerator
	stdout WriterGenerator
	stderr WriterGenerator
}

type command struct {
	cmd        *exec.Cmd
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	stderrPipe io.Reader
}

//Run executes one run of the fuzzer and managers comparison
func (d *Definition) Run() error {
	wg := sync.WaitGroup{}
	sema := make(chan struct{}, runtime.NumCPU()*4)
	errChan := make(chan error, d.runs)
	closeChan := make(chan io.Closer, d.runs*2)

	go func() {
		for i := 0; i < d.runs; i++ {
			wg.Add(1)
			sema <- struct{}{}
			go func(run int) {
				err := d.oneRun(State{Run: run}, closeChan)
				if err != nil {
					errChan <- err
				}
				wg.Done()
				<-sema
			}(i)
		}
		go func() {
			wg.Wait()
			close(closeChan)
			for closer := range closeChan {
				closer.Close()
			}
			close(errChan)
		}()
	}()

	return <-errChan
}

func (d *Definition) oneRun(s State, closeChan chan io.Closer) error {
	args, err := genArgsInput(d.args, s)
	if err != nil {
		return err
	}
	vars, err := genVarsInput(d.vars, s)
	if err != nil {
		return err
	}
	tests := make(testCommands, len(d.tests))
	for i, test := range d.tests {
		tests[i], err = makeCommand(test, args, vars)
		if err != nil {
			return err
		}
	}

	mergeStdout, err := d.stdout.GenerateWriter(s)
	if err != nil {
		return err
	}
	closeChan <- mergeStdout

	mergeStderr, err := d.stderr.GenerateWriter(s)
	if err != nil {
		return err
	}
	closeChan <- mergeStderr

	diffStdoutErrChan := compareReaders(
		s.Run, d.format, d.errorFormat,
		mergeStdout, tests.stdouts()...,
	)
	diffStderrErrChan := compareReaders(
		s.Run, d.format, d.errorFormat,
		mergeStderr, tests.stderrs()...,
	)

	//Manage test execution
	for _, test := range tests {
		err = test.cmd.Start()
		if err != nil {
			return err
		}
	}

	stdinErrChan := make(chan error)
	defer close(stdinErrChan)

	if d.stdin != nil {
		mergeStdin := io.MultiWriter(tests.stdins()...)
		stdin, err := d.stdin.GenerateReader(s)
		if err != nil {
			return err
		}
		defer stdin.Close()
		go func() {
			_, err := io.Copy(mergeStdin, stdin)
			if err != nil {
				stdinErrChan <- err
			}
			tests.closeStdins()
		}()
	} else {
		tests.closeStdins()
	}

	for _, test := range tests {
		defer test.cmd.Wait()
	}

	select {
	case err := <-diffStderrErrChan:
		err2 := <-diffStdoutErrChan
		if err2 != nil {
			return errors.Wrapf(
				err2,
				"Error on tests %v given args %v and environment %v",
				d.tests,
				args,
				vars,
			)
		}
		return errors.Wrapf(
			err,
			"Error on tests %v given args %v and environment %v",
			d.tests,
			args,
			vars,
		)
	case err := <-diffStdoutErrChan:
		err2 := <-diffStderrErrChan
		if err2 != nil {
			return errors.Wrapf(
				err2,
				"Error on tests %v given input %v and environment %v",
				d.tests,
				args,
				vars,
			)
		}
		return errors.Wrapf(
			err,
			"Error on tests %v given input %v and environment %v",
			d.tests,
			args,
			vars,
		)
	case err := <-stdinErrChan:
		return errors.Wrapf(err, "Error reading from stdin generator")

	}
}

func compareReaders(run int, format, errorFormat string,
	output io.Writer, readers ...io.Reader) <-chan error {

	errChan := make(chan error)

	scanners := make([]*bufio.Scanner, len(readers))
	for i, reader := range readers {
		scanners[i] = bufio.NewScanner(reader)
	}

	go func() {
		scan := func() bool {
			out := true
			for _, scanner := range scanners {
				if !scanner.Scan() {
					out = false
				}
			}
			return out
		}
		for scan() {
			line1 := scanners[0].Text()
			same := true
			for _, scanner := range scanners[1:] {
				line2 := scanner.Text()
				if line1 != line2 {
					same = false
				}
			}

			if same {
				fmt.Fprintf(output, format, run, line1)
			} else {
				for i, scanner := range scanners {
					fmt.Fprintf(output, errorFormat, run, i, scanner.Text())
				}
				errChan <- fmt.Errorf("Text not equal")
			}
		}
		close(errChan)
	}()
	return errChan
}

func makeCommand(executable string, args, vars []string) (*command, error) {
	cmd := exec.Command(
		executable,
		args...,
	)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, vars...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	return &command{cmd, stdin, stdout, stderr}, err
}

func genArgsInput(args []ReaderGenerator, s State) ([]string, error) {
	out := make([]string, len(args))
	for i, g := range args {
		buf := new(bytes.Buffer)
		rc, err := g.GenerateReader(s)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		io.Copy(buf, rc)
		out[i] = buf.String()
	}
	return out, nil
}

func genVarsInput(vars map[string]ReaderGenerator, s State) ([]string, error) {
	out := make([]string, len(vars))
	i := 0
	for k, g := range vars {
		buf := new(bytes.Buffer)
		rc, err := g.GenerateReader(s)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		io.Copy(buf, rc)
		out[i] = fmt.Sprintf("%s=%s", k, buf.String())
		i++
	}
	return out, nil
}
