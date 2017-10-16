package fuzzer

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/skylark"
)

type nopReadCloser struct {
	io.Reader
}

func (nopReadCloser) Close() error { return nil }

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

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

type multiWriteCloser struct {
	wcs []io.WriteCloser
	io.Writer
}

func newMultiWriteCloser(writers ...io.WriteCloser) *multiWriteCloser {
	wcs := make([]io.WriteCloser, len(writers))
	ws := make([]io.Writer, len(writers))
	copy(wcs, writers)
	for i, w := range writers {
		ws[i] = w
	}
	return &multiWriteCloser{wcs: wcs, Writer: io.MultiWriter(ws...)}
}

func (m *multiWriteCloser) Close() error {
	var firstErr error
	for _, wc := range m.wcs {
		err := wc.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

//ReaderGenerator creates an io.ReadCloser
type ReaderGenerator interface {
	GenerateReader(State) (io.ReadCloser, error)
}

//WriterGenerator creates an io.WriteCloser
type WriterGenerator interface {
	GenerateWriter(State) (io.WriteCloser, error)
}

type readerGenerator struct {
	v skylark.Value
}

func newReaderGenerator(v skylark.Value) *readerGenerator {
	return &readerGenerator{v: v}
}

func (g *readerGenerator) GenerateReader(s State) (io.ReadCloser, error) {
	return makeReadCloser(g.v, s)
}

func makeReadCloser(val skylark.Value, s State) (io.ReadCloser, error) {
	switch vt := val.(type) {
	case io.ReadCloser:
		return vt, nil
	case io.Reader:
		return nopReadCloser{vt}, nil
	case skylark.Callable:
		t := &skylark.Thread{}
		t.SetLocal("state", s)
		newVal, err := vt.Call(t, nil, nil)
		if err != nil {
			return nil, err
		}
		return makeReadCloser(newVal, s)
	case skylark.String:
		return nopReadCloser{strings.NewReader(string(vt))}, nil
	case skylark.Indexable:
		rcs := make([]io.ReadCloser, vt.Len())
		for i := 0; i < vt.Len(); i++ {
			rc, err := makeReadCloser(vt.Index(i), s)
			if err != nil {
				return nil, err
			}
			rcs[i] = rc
		}
		return newMultiReadCloser(rcs...), nil
	default:
		return nopReadCloser{strings.NewReader(vt.String())}, nil
	}
}

type writerGenerator struct {
	v skylark.Value
}

func newWriterGenerator(v skylark.Value) *writerGenerator {
	return &writerGenerator{v: v}
}

func (g *writerGenerator) GenerateWriter(s State) (io.WriteCloser, error) {
	return makeWriteCloser(g.v, s)
}

func makeWriteCloser(val skylark.Value, s State) (io.WriteCloser, error) {
	switch vt := val.(type) {
	case io.WriteCloser:
		return vt, nil
	case io.Writer:
		return nopWriteCloser{vt}, nil
	case skylark.Callable:
		t := &skylark.Thread{}
		t.SetLocal("state", s)
		newVal, err := vt.Call(t, nil, nil)
		if err != nil {
			return nil, err
		}
		return makeWriteCloser(newVal, s)
	case skylark.String:
		return nil, fmt.Errorf("Invalid Type (%v) for Writer", val.Type())
	case skylark.Indexable:
		wcs := make([]io.WriteCloser, vt.Len())
		for i := 0; i < vt.Len(); i++ {
			wc, err := makeWriteCloser(vt.Index(i), s)
			if err != nil {
				return nil, err
			}
			wcs[i] = wc
		}
		return newMultiWriteCloser(wcs...), nil
	default:
		return nil, fmt.Errorf("Invalid Type (%v) for Writer", val.Type())
	}
}
