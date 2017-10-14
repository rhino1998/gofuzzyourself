package fuzzer

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
)

type readCloserWrapper struct {
	rc io.ReadCloser
}

func (r *readCloserWrapper) Read(p []byte) (n int, err error) {
	n, err = r.rc.Read(p)
	if err != nil {
		r.rc.Close()
	}
	return n, err
}

//ReaderGenerator generates a reader based on some internal properties
type ReaderGenerator interface {
	GenerateReader() (io.Reader, error)
}

type FileReader struct {
	File string `json:"file"`
}

//GenerateReader returns a file reader
func (g *FileReader) GenerateReader() (io.Reader, error) {
	r, err := os.Open(g.File)
	return &readCloserWrapper{r}, err
}

func (FileReader) unmarshal(data []byte) (ReaderGenerator, error) {
	var g *FileReader
	err := json.Unmarshal(data, &g)
	return g, err
}

type CommandReader struct {
	Command string `json:"command"`
}

//GenerateReader returns a command reader
func (g *CommandReader) GenerateReader() (io.Reader, error) {
	parts := strings.Split(g.Command, " ")
	cmd := exec.Command(parts[0], parts[1:]...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	go func() {
		cmd.Wait()
	}()
	return &readCloserWrapper{r}, err
}

func (CommandReader) unmarshal(data []byte) (ReaderGenerator, error) {
	var g *CommandReader
	err := json.Unmarshal(data, &g)
	return g, err
}
