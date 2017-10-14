package fuzzer

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

var generators = make(map[string]func([]byte) (Generator, error))
var readerGenerators = make(map[string]func([]byte) (ReaderGenerator, error))

func init() {
	var prefix Prefix
	RegisterGenerator("prefix", prefix.unmarshal)

	var constant Constant
	RegisterGenerator("constant", constant.unmarshal)

	var integerRandom IntegerRandom
	RegisterGenerator("integer_random", integerRandom.unmarshal)

	var integerNormalRandom IntegerNormalRandom
	RegisterGenerator("integer_normal_random", integerNormalRandom.unmarshal)

	var floatRandom FloatRandom
	RegisterGenerator("float_random", floatRandom.unmarshal)

	var floatNormalRandom FloatNormalRandom
	RegisterGenerator("float_normal_random", floatNormalRandom.unmarshal)

	var fileReader FileReader
	RegisterReaderGenerator("file_reader", fileReader.unmarshal)

	var commandReader CommandReader
	RegisterReaderGenerator("command_reader", commandReader.unmarshal)
}

//RegisterGenerator registers a new Generator for the config parser
//Use during initialization. Determinism is lost if used later
func RegisterGenerator(t string, f func([]byte) (Generator, error)) {
	generators[t] = f
}

//RegisterReaderGenerator registers a new ReaderGenerator for the config parser
//Use during initialization. Determinism is lost if used later
func RegisterReaderGenerator(t string, f func([]byte) (ReaderGenerator, error)) {
	readerGenerators[t] = f
}

//Definition describes a fuzzer test batch
type Definition struct {
	tests  []string
	runs   int
	output bool

	args  []Generator
	vars  []Generator
	stdin ReaderGenerator
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

	args := genInput(d.args)
	vars := genInput(d.vars)
	tests := make(testCommands, len(d.tests))
	for i, test := range d.tests {
		var err error
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
		err := test.cmd.Start()
		if err != nil {
			return err
		}
	}

	stdin, err := d.stdin.GenerateReader()
	if err != nil {
		return err
	}

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

func genInput(gs []Generator) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Generate()
	}
	return out
}
