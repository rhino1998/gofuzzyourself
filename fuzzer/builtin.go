package fuzzer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/skylark"
	"github.com/google/skylark/syntax"
	"github.com/pkg/errors"
)

func setupGlobals(globals skylark.StringDict) {

	osVal := NewNamespace("os")
	osVal.SetAttr("stdout", &writerValue{os.Stdout})
	osVal.SetAttr("stderr", &writerValue{os.Stderr})

	testVal := NewNamespace("test")
	testVal.SetAttr("run", NewBinaryCallable(skylark.NewBuiltin("run", getRunState)))

	globals["open"] = skylark.NewBuiltin("open", open)
	globals["discard"] = &writerValue{ioutil.Discard}
	globals["os"] = osVal
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

func getRunState(thread *skylark.Thread, _ *skylark.Builtin, _ skylark.Tuple,
	_ []skylark.Tuple) (skylark.Value, error) {
	s, ok := thread.Local("state").(State)
	if !ok {
		return nil, fmt.Errorf("Invalid state %v, don't directly call this builtin", thread.Local("state"))
	}
	return skylark.MakeInt(s.Run), nil
}

type BinaryCallable struct {
	fn skylark.Callable
}

func NewBinaryCallable(fn skylark.Callable) *BinaryCallable {
	return &BinaryCallable{fn: fn}
}

func (*BinaryCallable) Type() string {
	return "IntCallable"
}

func (*BinaryCallable) Freeze() {}

func (*BinaryCallable) Hash() (uint32, error) {
	return 0, fmt.Errorf("BinaryCallable not hashable")
}

func (b *BinaryCallable) String() string {
	return fmt.Sprintf("<BinaryCallable %v>", b.fn)
}

func (b *BinaryCallable) Truth() skylark.Bool {
	return skylark.Bool(b.fn != nil)
}

func (b *BinaryCallable) Name() string {
	return b.fn.Name()
}

func (b *BinaryCallable) Call(thread *skylark.Thread, args skylark.Tuple,
	kwargs []skylark.Tuple) (skylark.Value, error) {
	return b.fn.Call(thread, args, kwargs)
}
func (b *BinaryCallable) Binary(op syntax.Token, y skylark.Value,
	side skylark.Side) (skylark.Value, error) {
	return NewBinaryCallable(skylark.NewBuiltin("tmp", func(thread *skylark.Thread,
		_ *skylark.Builtin, args skylark.Tuple,
		kwargs []skylark.Tuple) (skylark.Value, error) {
		val, err := b.fn.Call(thread, args, kwargs)
		if err != nil {
			return nil, err
		}
		if side {
			return skylark.Binary(op, y, val)
		}
		return skylark.Binary(op, val, y)
	})), nil
}
