package fuzzer

import (
	"fmt"
	"io"
)

type ReadCloserValue struct {
	io.ReadCloser
}

func (v *ReadCloserValue) String() string {
	return fmt.Sprintf("<ReaderCloser %v>", v.ReadCloser)
}

func (v *ReadCloserValue) Freeze() {}

func (v *ReadCloserValue) Truth() bool {
	return v.ReadCloser == nil
}

func (v *ReadCloserValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<ReadCloser %v> is not hashable", v.ReadCloser)
}
