package fuzzer

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/google/skylark"
	"github.com/pkg/errors"
)

func parsingError(err error, filename string) error {
	return errors.Wrapf(err, "Error parsing config %q", filename)
}

/*ParseConfig parses a skylark file looking for specific global variables
* describing what binaries to fuzz and what inputs to provide
 */
func ParseConfig(filename string, src interface{}, opts ...Option) (*Definition, error) {
	thread := &skylark.Thread{}
	def := &Definition{
		globals: shallowCopyGlobals(skylark.Universe),
	}
	setupGlobals(def.globals, State{})

	var reader io.Reader
	buf := new(bytes.Buffer)
	switch st := src.(type) {
	case io.Reader:
		reader = st
	case string:
		reader = strings.NewReader(st)
	}
	r := io.TeeReader(reader, buf)

	for _, opt := range opts {
		err := opt(def)
		if err != nil {
			return nil, err
		}
	}

	err := skylark.Exec(skylark.ExecOptions{
		Thread:   thread,
		Filename: filename,
		Source:   r,
		Globals:  def.globals,
	})
	if err != nil {
		return nil, err
	}

	tests, err := getTests(def.globals)
	if err != nil {
		return nil, parsingError(err, filename)
	}
	runs, err := getRuns(def.globals)
	if err != nil {
		return nil, parsingError(err, filename)
	}

	def.tests = tests
	def.runs = runs
	def.src = buf.String()
	def.filename = filename
	return def, nil
}

func getArgs(globals skylark.StringDict) ([]ReaderGenerator, error) {
	val, found := globals["args"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of args")
	}

	args, ok := val.(*skylark.List)
	if !ok {
		return nil, fmt.Errorf(
			"Invalid type for args (Expected \"list\"; got %q)",
			val.Type(),
		)
	}

	gens := make([]ReaderGenerator, args.Len())
	for i := 0; i < args.Len(); i++ {
		a := args.Index(i)
		gens[i] = newReaderGenerator(a)
	}
	return gens, nil
}

func getVars(globals skylark.StringDict) (map[string]ReaderGenerator, error) {
	val, found := globals["vars"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of vars")
	}

	vars, ok := val.(*skylark.Dict)
	if !ok {
		return nil, fmt.Errorf(
			"Invalid type for vars (Expected \"dict\"; got %q)",
			val.Type(),
		)
	}
	gens := make(map[string]ReaderGenerator)
	for _, key := range vars.Keys() {
		val, _, err := vars.Get(key)
		if err != nil {
			return nil,
				errors.Wrapf(err, "Error getting key %q from dict vars", key)
		}

		keyStr, ok := skylark.AsString(key)
		if !ok {
			return nil, fmt.Errorf(
				"Invalid type for key at vars[%s] (Expected String; got %q)",
				key,
				key.Type(),
			)
		}
		gens[keyStr] = newReaderGenerator(val)
	}
	return gens, nil
}

func getTests(globals skylark.StringDict) ([]string, error) {
	val, found := globals["tests"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of tests")
	}

	testsList, ok := val.(*skylark.List)
	if !ok {
		return nil, fmt.Errorf(
			"Invalid type for tests (Expected \"list\"; got %q)",
			val.Type(),
		)
	}

	tests := make([]string, testsList.Len())
	for i := 0; i < testsList.Len(); i++ {
		test := testsList.Index(i)
		testStr, ok := skylark.AsString(test)
		if !ok {
			return nil, fmt.Errorf(
				"Invalid type for key at tests[%d] (Expected String; got %q)",
				i,
				test.Type(),
			)
		}
		tests[i] = testStr
	}
	return tests, nil
}

func getRuns(globals skylark.StringDict) (int, error) {
	val, found := globals["runs"]
	if !found {
		return 0, fmt.Errorf("Missing declaration of runs")
	}

	runs, err := skylark.AsInt32(val)
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"Invalid type for runs (Expected Int; got %q)",
			val.Type(),
		)
	}

	return runs, nil
}

func getStdin(globals skylark.StringDict) (ReaderGenerator, error) {
	val, found := globals["stdin"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of stdin")
	}
	return newReaderGenerator(val), nil
}

func getStderr(globals skylark.StringDict) (WriterGenerator, error) {
	val, found := globals["stderr"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of stderr")
	}
	return newWriterGenerator(val), nil
}

func getStdout(globals skylark.StringDict) (WriterGenerator, error) {
	val, found := globals["stdout"]
	if !found {
		return nil, fmt.Errorf("Missing declaration of stderr")
	}
	return newWriterGenerator(val), nil
}

func getFormat(globals skylark.StringDict) (string, error) {
	val, found := globals["format"]
	if !found {
		return "", fmt.Errorf("Missing declaration of format")
	}
	str, ok := skylark.AsString(val)
	if !ok {
		return "", fmt.Errorf("Invalid type for format string: %q", val.Type())
	}
	return str, nil
}

func getErrorFormat(globals skylark.StringDict) (string, error) {
	val, found := globals["error_format"]
	if !found {
		return "", fmt.Errorf("Missing declaration of error_format")
	}
	str, ok := skylark.AsString(val)
	if !ok {
		return "", fmt.Errorf("Invalid type for format string: %q", val.Type())
	}
	return str, nil
}
