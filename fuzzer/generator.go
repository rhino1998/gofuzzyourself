package fuzzer

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/google/skylark"
)

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
	GenerateReader() (io.ReadCloser, error)
}

//WriterGenerator creates an io.WriteCloser
type WriterGenerator interface {
	GenerateWriter() (io.WriteCloser, error)
}

type readerGenerator struct {
	v skylark.Value
}

func newReaderGenerator(v skylark.Value) *readerGenerator {
	return &readerGenerator{v: v}
}

func (g *readerGenerator) GenerateReader() (io.ReadCloser, error) {
	return makeReadCloser(g.v)
}

func makeReadCloser(val skylark.Value) (io.ReadCloser, error) {
	switch vt := val.(type) {
	case skylark.NoneType:
		return ioutil.NopCloser(bytes.NewReader(nil)), nil
	case io.ReadCloser:
		return vt, nil
	case io.Reader:
		return ioutil.NopCloser(vt), nil
	case skylark.Callable:
		newVal, err := vt.Call(&skylark.Thread{}, nil, nil)
		if err != nil {
			return nil, err
		}
		return makeReadCloser(newVal)
	case skylark.String:
		return ioutil.NopCloser(strings.NewReader(string(vt))), nil
	case skylark.Indexable:
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
		return ioutil.NopCloser(strings.NewReader(vt.String())), nil
	}
}

type writerGenerator struct {
	v skylark.Value
}

func newWriterGenerator(v skylark.Value) *writerGenerator {
	return &writerGenerator{v: v}
}

func (g *writerGenerator) GenerateWriter() (io.WriteCloser, error) {
	return makeWriteCloser(g.v)
}

func makeWriteCloser(val skylark.Value) (io.WriteCloser, error) {
	switch vt := val.(type) {
	case io.WriteCloser:
		return vt, nil
	case io.Writer:
		return nopWriteCloser{vt}, nil
	case skylark.Callable:
		newVal, err := vt.Call(&skylark.Thread{}, nil, nil)
		if err != nil {
			return nil, err
		}
		return makeWriteCloser(newVal)
	case skylark.String:
		return nil, fmt.Errorf("Invalid Type (%v) for Writer", val.Type())
	case skylark.Indexable:
		wcs := make([]io.WriteCloser, vt.Len())
		for i := 0; i < vt.Len(); i++ {
			wc, err := makeWriteCloser(vt.Index(i))
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
