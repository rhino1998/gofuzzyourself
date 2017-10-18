package fuzzer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/skylark"
	"github.com/pkg/errors"
)

func setupGlobals(globals skylark.StringDict, state State) {

	osVal := NewNamespace("os")
	osVal.SetAttr("stdout", &writerValue{os.Stdout})
	osVal.SetAttr("stderr", &writerValue{os.Stderr})

	globals["open"] = skylark.NewBuiltin("open", open)
	globals["discard"] = &writerValue{ioutil.Discard}
	globals["os"] = osVal

	testVal := NewNamespace("test")
	testVal.SetAttr("run", skylark.MakeInt(state.Run))
	globals["test"] = testVal
}

func open(thread *skylark.Thread, fn *skylark.Builtin,
	args skylark.Tuple, kwargs []skylark.Tuple) (skylark.Value, error) {
	switch args.Len() {
	case 2:
		filename, _ := skylark.AsString(args.Index(0))
		mode, _ := skylark.AsString(args.Index(1))
		switch strings.ToLower(mode) {
		case "r", "r+":
			f, err := os.Open(filename)
			return &fileValue{f}, errors.Wrap(
				err,
				fmt.Sprintf("Error opening %q", args.Index(0).String()),
			)
		case "w", "w+":
			f, err := os.Create(filename)
			return &fileValue{f}, errors.Wrap(
				err,
				fmt.Sprintf("Error opening %q", args.Index(0).String()),
			)
		default:
			return nil, fmt.Errorf("Invalid file mode %q", mode)
		}
	case 1:
		filename, _ := skylark.AsString(args.Index(0))
		f, err := os.Open(filename)

		return &fileValue{f}, errors.Wrap(
			err,
			fmt.Sprintf("Error opening %q", args.Index(0).String()),
		)

	default:
		return nil, fmt.Errorf(
			"Invalid number of arguments for open (Expected 1; Got %d)",
			args.Len(),
		)
	}
}
