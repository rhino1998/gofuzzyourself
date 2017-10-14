package fuzzer

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/skylark"
)

//ReadCloserValue wraps an io.ReadCloser into a valid skylark.Value
type ReadCloserValue struct {
	io.ReadCloser
}

//Type returns "ReadCloser"
func (v *ReadCloserValue) Type() string {
	return "ReadCloser"
}

//String reads the whole reader and returns the output as a string
func (v *ReadCloserValue) String() string {
	data, _ := ioutil.ReadAll(v)
	v.Close()
	return string(data)
}

//Freeze is a dummy method that does nothing in this context
func (v *ReadCloserValue) Freeze() {}

//Truth checks if ReadCloserValue wraps a valid io.ReadCloser
func (v *ReadCloserValue) Truth() skylark.Bool {
	return skylark.Bool(v.ReadCloser == nil)
}

//Hash returns a non-hashable error
func (v *ReadCloserValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<ReadCloser %v> is not hashable", v.ReadCloser)
}
