package fuzzer

import (
	"bufio"
	"fmt"
	"io"
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
	globals  skylark.StringDict
	filename string
	src      string

	tests []string
	runs  int
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
	config, err := generateRunConfig(d, s)
	if err != nil {
		return err
	}

	args, vars, stdin, mergeStdout, mergeStderr, err := config.generateState(s)
	if err != nil {
		return err
	}
	closeChan <- mergeStdout
	closeChan <- mergeStderr

	tests, err := makeCommandGroup(d.tests, args, vars)
	if err != nil {
		return err
	}

	diffStdoutErrChan := compareReaders(
		s.Run, config.format, config.errorFormat,
		mergeStdout, tests.stdouts()...,
	)
	diffStderrErrChan := compareReaders(
		s.Run, config.format, config.errorFormat,
		mergeStderr, tests.stderrs()...,
	)

	//Manage test execution
	for _, test := range tests {
		err = test.Start()
		if err != nil {
			return err
		}
	}

	stdinErrChan := make(chan error)
	defer close(stdinErrChan)

	mergeStdin := io.MultiWriter(tests.stdins()...)
	go func() {
		_, err := io.Copy(mergeStdin, stdin)
		if err != nil {
			stdinErrChan <- err
		}
		tests.closeStdins()
	}()

	for _, test := range tests {
		defer test.Wait()
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
