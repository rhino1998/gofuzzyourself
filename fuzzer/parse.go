package fuzzer

import (
	"fmt"

	"github.com/google/skylark"
)

func ParseConfig(filename string, src interface{}) (*Definition, error) {
	thread := &skylark.Thread{}
	globals := skylark.Universe
	val, err := skylark.Eval(thread, filename, src, globals)
	if err != nil {
		return nil, err
	}

	dict, ok := val.(*skylark.Dict)
	if !ok {
		return nil, fmt.Errorf("Invalid config type")
	}

	args, err := dict.Attr("args")
	if err != nil {
		return nil, err
	}
	fmt.Println(dict.String())
	fmt.Println(args)
	fmt.Println(args.String())
	return nil, nil
}
