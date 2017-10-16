package fuzzer

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/skylark"
)

//ReaderValue implements both skylark.Value and io.Reader
type ReaderValue interface {
	skylark.Value
	io.Reader
}

//ReadCloserValue implements both skylark.Value and io.ReadCloser
type ReadCloserValue interface {
	skylark.Value
	io.ReadCloser
}

//WriterValue implements both skylark.Value and io.Writer
type WriterValue interface {
	skylark.Value
	io.Writer
}

//WriteCloserValye implements both skylark.Value and io.WriteCloser
type WriteCloserValue interface {
	skylark.Value
	io.WriteCloser
}

//ReadWriterValue implements both skylark.Value and io.ReadWriter
type ReadWriterValue interface {
	skylark.Value
	io.ReadWriter
}

//readCloserValue wraps an io.ReadCloser into a valid skylark.Value
type readCloserValue struct {
	io.ReadCloser
}

//Type returns "readCloser"
func (v *readCloserValue) Type() string {
	return "ReadCloser"
}

//String reads the whole reader and returns the output as a string
func (v *readCloserValue) String() string {
	data, _ := ioutil.ReadAll(v)
	v.Close()
	return string(data)
}

//Freeze is a dummy method that does nothing in this context
func (v *readCloserValue) Freeze() {}

//Truth checks if readCloserValue wraps a valid io.ReadCloser
func (v *readCloserValue) Truth() skylark.Bool {
	return skylark.Bool(v.ReadCloser == nil)
}

//Hash returns a non-hashable error
func (v *readCloserValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<ReadCloser %v> is not hashable", v.ReadCloser)
}

//writerValue wraps an io.Writer into a valid skylark.Value
type writerValue struct {
	io.Writer
}

//Type returns "writer"
func (v *writerValue) Type() string {
	return "writer"
}

//String reads the whole reader and returns the output as a string
func (v *writerValue) String() string {
	return fmt.Sprintf("<writer %v>", v.Writer)
}

//Freeze is a dummy method that does nothing in this context
func (v *writerValue) Freeze() {}

//Truth checks if writerValue wraps a valid io.Writer
func (v *writerValue) Truth() skylark.Bool {
	return skylark.Bool(v.Writer == nil)
}

//Hash returns a non-hashable error
func (v *writerValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<writer %v> is not hashable", v.Writer)
}

type fileValue struct {
	*os.File
}

func (v *fileValue) Type() string {
	return "File"
}

func (v *fileValue) String() string {
	data, _ := ioutil.ReadAll(v)
	v.Close()
	return string(data)
}

func (v *fileValue) Freeze() {}

func (v *fileValue) Truth() skylark.Bool {
	return skylark.Bool(v.File == nil)
}

func (v *fileValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<File %v> is not hashable", v.File)
}

//NamespaceValue wraps an map into a valid skylark.Value
type NamespaceValue struct {
	name  string
	attrs map[string]skylark.Value
}

func NewNamespace(name string) *NamespaceValue {
	return &NamespaceValue{
		name:  name,
		attrs: make(map[string]skylark.Value),
	}
}

func (v *NamespaceValue) Attr(name string) (skylark.Value, error) {
	return v.attrs[name], nil
}

func (v *NamespaceValue) AttrNames() []string {
	names := make([]string, len(v.attrs))
	i := 0
	for k, _ := range v.attrs {
		names[i] = k
		i++
	}
	return names
}

func (v *NamespaceValue) SetAttr(attr string, val skylark.Value) {
	v.attrs[attr] = val
}

//Type returns "Namespace"
func (v *NamespaceValue) Type() string {
	return "Namespace"
}

//String reads the whole reader and returns the output as a string
func (v *NamespaceValue) String() string {
	return fmt.Sprintf("<%s>", v.name)
}

//Freeze is a dummy method that does nothing in this context
func (v *NamespaceValue) Freeze() {}

//Truth checks if FileValue wraps a valid io.writer
func (v *NamespaceValue) Truth() skylark.Bool {
	return skylark.Bool(len(v.attrs) == 0)
}

//Hash returns a non-hashable error
func (v *NamespaceValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("<Namespace %v> is not hashable", v.name)
}
