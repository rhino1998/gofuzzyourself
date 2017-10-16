package fuzzer

import (
	"io"
	"strings"

	"github.com/google/skylark"
)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type multiReadCloser struct {
	rcs []io.ReadCloser
	io.Reader
}

func newMultiReadCloser(readers ...io.ReadCloser) *multiReadCloser {
	rcs := make([]io.ReadCloser, len(readers))
	rs := make([]io.Reader, len(readers))
	copy(rcs, readers)
	for i, r := range readers {
		rs[i] = r
	}
	return &multiReadCloser{rcs: rcs, Reader: io.MultiReader(rs...)}
}

func (m *multiReadCloser) Close() error {
	var firstErr error
	for _, rc := range m.rcs {
		err := rc.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

//Generator wraps a skylark.Callable and puts its output into an io.ReadCloser
type Generator struct {
	fn skylark.Callable
}

//NewGenerator returns a new Generator from a skylark.Callable
func NewGenerator(fn skylark.Callable) *Generator {
	return &Generator{fn: fn}
}

//Generate returns an io.ReadCloser based on the skylark.Callable value it wraps
func (g *Generator) Generate() (io.ReadCloser, error) {
	thread := &skylark.Thread{}
	val, err := g.fn.Call(thread, nil, nil)

	if err != nil {
		return nil, err
	}
	return makeReadCloser(val)
}

func makeReadCloser(val skylark.Value) (io.ReadCloser, error) {
	switch vt := val.(type) {
	case *ReadCloserValue:
		return vt, nil
	case skylark.String:
		return nopCloser{strings.NewReader(string(vt))}, nil
	case *skylark.List:
		rcs := make([]io.ReadCloser, vt.Len())
		for i := 0; i < vt.Len(); i++ {
			rc, err := makeReadCloser(vt.Index(i))
			if err != nil {
				return nil, err
			}
			rcs[i] = rc
		}
		return newMultiReadCloser(rcs...), nil
	default:
		return nopCloser{strings.NewReader(vt.String())}, nil
	}
}
