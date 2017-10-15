package fuzzer

import (
	"fmt"
	"os"

	"github.com/google/skylark"
	"github.com/pkg/errors"
)

func open(thread *skylark.Thread, fn *skylark.Builtin,
	args skylark.Tuple, kwargs []skylark.Tuple) (skylark.Value, error) {
	if args.Len() < 1 {
		return nil, fmt.Errorf(
			"Invalid number of arguments for open (Expected 1; Got %d)",
			args.Len(),
		)
	}
	f, err := os.Open(args.Index(0).String())

	return &ReadCloserValue{f}, errors.Wrap(
		err,
		fmt.Sprintf("Error opening %q", args.Index(0).String()),
	)
}
