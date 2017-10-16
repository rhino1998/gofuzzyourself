package fuzzer

import "github.com/google/skylark"

//Option describes an option to use while creating a definition
type Option = func(*Definition) error

//WithGlobal inserts a global name with value global
func WithGlobal(name string, global skylark.Value) Option {
	return func(def *Definition) error {
		def.globals[name] = global
		return nil
	}
}
