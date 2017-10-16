package fuzzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/google/skylark/resolve"
)

func init() {
	resolve.AllowLambda = true
	resolve.AllowSet = true
	resolve.AllowFloat = true
	resolve.AllowNestedDef = true
}

//Definition describes a fuzzer test batch
type Definition struct {
	tests  []string
	runs   int
	output bool

	args  []*Generator
	vars  map[string]*Generator
	stdin *Generator
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
	errChan := make(chan error)

	for i := 0; i < d.runs; i++ {
		wg.Add(1)
		sema <- struct{}{}
		go func() {
			err := d.oneRun()
			if err != nil {
				errChan <- err
			}

			wg.Done()
			<-sema
		}()
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()
	return <-errChan
}

func (d *Definition) oneRun() error {
	args, err := genArgsInput(d.args)
	if err != nil {
		return err
	}
	vars, err := genVarsInput(d.vars)
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

	mergeStdin := io.MultiWriter(tests.stdins()...)

	var mergeStdout io.Writer = os.Stdout
	var mergeStderr io.Writer = os.Stdout
	if !d.output {
		mergeStderr = ioutil.Discard
		mergeStdout = ioutil.Discard
	}

	diffStdoutErrChan := compareReaders(mergeStdout, tests.stdouts()...)
	diffStderrErrChan := compareReaders(mergeStderr, tests.stderrs()...)

	//Manage test execution
	for _, test := range tests {
		err = test.cmd.Start()
		if err != nil {
			return err
		}
	}

	stdin, err := d.stdin.Generate()
	if err != nil {
		return err
	}
	defer stdin.Close()

	go func() {
		io.Copy(mergeStdin, stdin)
		tests.closeStdins()
	}()

	for _, test := range tests {
		defer test.cmd.Wait()
	}

	select {
	case err := <-diffStderrErrChan:
		<-diffStdoutErrChan
		return err
	case err := <-diffStdoutErrChan:
		<-diffStderrErrChan
		return err
	}
}

func compareReaders(output io.Writer, readers ...io.Reader) <-chan error {
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
				fmt.Fprintf(output, "   %s\n", line1)
			} else {
				for i, scanner := range scanners {
					fmt.Fprintf(output, "%dX %s\n", i, scanner.Text())
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

func genArgsInput(args []*Generator) ([]string, error) {
	out := make([]string, len(args))
	for i, g := range args {
		buf := new(bytes.Buffer)
		rc, err := g.Generate()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		io.Copy(buf, rc)
		out[i] = buf.String()
	}
	return out, nil
}

func genVarsInput(vars map[string]*Generator) ([]string, error) {
	out := make([]string, len(vars))
	i := 0
	for k, g := range vars {
		buf := new(bytes.Buffer)
		rc, err := g.Generate()
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
