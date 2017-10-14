package fuzzer

import "io"

type testCommands []*command

func (t testCommands) stdins() []io.Writer {
	stdins := make([]io.Writer, len(t))
	for i, test := range t {
		stdins[i] = test.stdinPipe
	}
	return stdins
}
func (t testCommands) closeStdins() {
	for _, test := range t {
		test.stdinPipe.Close()
	}
}
func (t testCommands) stdouts() []io.Reader {
	stdouts := make([]io.Reader, len(t))
	for i, test := range t {
		stdouts[i] = test.stdoutPipe
	}
	return stdouts
}
func (t testCommands) stderrs() []io.Reader {
	stderrs := make([]io.Reader, len(t))
	for i, test := range t {
		stderrs[i] = test.stderrPipe
	}
	return stderrs
}
