package fuzzer

import (
	"io"

	"github.com/google/skylark"
)

type Generator struct {
	fn skylark.Callable
}

func (g *Generator) Generate() (io.ReadCloser, error) {

}
