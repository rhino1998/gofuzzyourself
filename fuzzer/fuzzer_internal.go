package fuzzer

import (
	"io"
	"os"
	"os/exec"
)

type command struct {
	*exec.Cmd
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	stderrPipe io.Reader
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

type commandGroup []*command

func makeCommandGroup(executables []string,
	args, vars []string) (commandGroup, error) {
	cmds := make(commandGroup, len(executables))
	for i, test := range executables {
		var err error
		cmds[i], err = makeCommand(test, args, vars)
		if err != nil {
			return nil, err
		}
	}
	return cmds, nil
}

func (t commandGroup) stdins() []io.Writer {
	stdins := make([]io.Writer, len(t))
	for i, test := range t {
		stdins[i] = test.stdinPipe
	}
	return stdins
}
func (t commandGroup) closeStdins() {
	for _, test := range t {
		test.stdinPipe.Close()
	}
}
func (t commandGroup) stdouts() []io.Reader {
	stdouts := make([]io.Reader, len(t))
	for i, test := range t {
		stdouts[i] = test.stdoutPipe
	}
	return stdouts
}
func (t commandGroup) stderrs() []io.Reader {
	stderrs := make([]io.Reader, len(t))
	for i, test := range t {
		stderrs[i] = test.stderrPipe
	}
	return stderrs
}

func (t commandGroup) start() error {
	var firstErr error
	for _, cmd := range t {
		err := cmd.Start()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
func (t commandGroup) wait() error {
	var firstErr error
	for _, cmd := range t {
		err := cmd.Wait()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
