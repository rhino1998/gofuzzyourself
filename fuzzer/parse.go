package fuzzer

import (
	"fmt"

	"github.com/google/skylark"
	"github.com/pkg/errors"
)

func parsingError(err error, filename string) error {
	return errors.Wrapf(err, "Error parsing config %q", filename)
}

/*ParseConfig parses a skylark file looking for specific global variables
* describing what binaries to fuzz and what inputs to provide
 */
func ParseConfig(filename string, src interface{}) (*Definition, error) {
	thread := &skylark.Thread{}
	globals := skylark.Universe
	globals["open"] = skylark.NewBuiltin("open", open)
	err := skylark.Exec(skylark.ExecOptions{
		Thread:   thread,
		Filename: filename,
		Source:   src,
		Globals:  globals,
	})
	if err != nil {
		return nil, err
	}

	tests, err := getTests(globals)
	runs, err := getRuns(globals)
	if err != nil {
		return nil, parsingError(err, filename)
	}
	args, err := getArgs(globals)
	if err != nil {
		return nil, parsingError(err, filename)
	}
	vars, err := getVars(globals)
	if err != nil {
		return nil, parsingError(err, filename)
	}
	def := &Definition{
		tests:  tests,
		runs:   runs,
		output: true,
		args:   args,
		vars:   vars,
	}
	return def, nil
}

func getArgs(globals skylark.StringDict) ([]*Generator, error) {
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

	gens := make([]*Generator, args.Len())
	for i := 0; i < args.Len(); i++ {
		a := args.Index(i)
		fn, ok := a.(skylark.Callable)
		if !ok {
			return nil, fmt.Errorf(
				"Invalid type for generator at args[%d] (Expected Function or Builtin; got %q)",
				i,
				a.Type(),
			)
		}
		gens[i] = NewGenerator(fn)
	}
	return gens, nil
}

func getVars(globals skylark.StringDict) (map[string]*Generator, error) {
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
	gens := make(map[string]*Generator)
	for i, key := range vars.Keys() {
		val, _, err := vars.Get(key)
		if err != nil {
			return nil,
				errors.Wrapf(err, "Error getting key %q from dict vars", key)
		}

		fn, ok := val.(skylark.Callable)
		if !ok {
			return nil, fmt.Errorf(
				"Invalid type for generator at args[%d] (Expected Function or Builtin; got %q)",
				i,
				val.Type(),
			)
		}
		keyStr, ok := skylark.AsString(key)
		if !ok {
			return nil, fmt.Errorf(
				"Invalid type for key at vars[%s] (Expected String; got %q)",
				key,
				key.Type(),
			)
		}
		gens[keyStr] = NewGenerator(fn)
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
