package fuzzer

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/skylark"
)

type runConfig struct {
	format      string
	errorFormat string

	args   []ReaderGenerator
	vars   map[string]ReaderGenerator
	stdin  ReaderGenerator
	stdout WriterGenerator
	stderr WriterGenerator
}

func generateRunConfig(def *Definition, s State) (*runConfig, error) {
	config := &runConfig{}
	thread := &skylark.Thread{}
	globals := shallowCopyGlobals(def.globals)
	setupGlobals(globals, s)

	err := skylark.Exec(skylark.ExecOptions{
		Thread:   thread,
		Filename: def.filename,
		Source:   def.src,
		Globals:  globals,
	})
	if err != nil {
		return nil, err
	}

	config.format, err = getFormat(globals)
	if err != nil {
		return nil, err
	}

	config.errorFormat, err = getErrorFormat(globals)
	if err != nil {
		return nil, err
	}

	config.args, err = getArgs(globals)
	if err != nil {
		return nil, err
	}

	config.vars, err = getVars(globals)
	if err != nil {
		return nil, err
	}

	config.stdin, err = getStdin(globals)
	if err != nil {
		return nil, err
	}
	config.stdout, err = getStdout(globals)
	if err != nil {
		return nil, err
	}
	config.stderr, err = getStderr(globals)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (c *runConfig) generateState(s State) (args, vars []string,
	stdin io.Reader,
	mergeStdout, mergeStderr io.WriteCloser, err error) {
	args, err = genArgsInput(c.args, s)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	vars, err = genVarsInput(c.vars, s)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	stdin, err = c.stdin.GenerateReader()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	mergeStdout, err = c.stdout.GenerateWriter()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	mergeStderr, err = c.stderr.GenerateWriter()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return args, vars, stdin, mergeStderr, mergeStdout, err
}

func genArgsInput(args []ReaderGenerator, s State) ([]string, error) {
	out := make([]string, len(args))
	for i, g := range args {
		buf := new(bytes.Buffer)
		rc, err := g.GenerateReader()
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
		rc, err := g.GenerateReader()
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
