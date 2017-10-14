package fuzzer

import (
	"encoding/json"
	"fmt"
	"io"
)

//Config describes the structure of the file to be consumed
type Config struct {
	Tests  []string `json:"tests"`
	Runs   int      `json:"runs"`
	Output bool     `json:"output"`

	Args  []json.RawMessage `json:"args"`
	Vars  []json.RawMessage `json:"vars"`
	Stdin json.RawMessage   `json:"stdin"`
}

//ParseConfig digests a reader
func ParseConfig(r io.Reader) (*Definition, error) {
	conf, err := readFile(r)
	if err != nil {
		return nil, err
	}

	args, err := parseGenerators(conf.Args)
	if err != nil {
		return nil, err
	}

	vars, err := parseGenerators(conf.Vars)
	if err != nil {
		return nil, err
	}

	stdin, err := parseReaderGenerator(conf.Stdin)
	if err != nil {
		return nil, err
	}

	def := &Definition{
		tests:  conf.Tests,
		runs:   conf.Runs,
		args:   args,
		vars:   vars,
		stdin:  stdin,
		output: conf.Output,
	}
	return def, nil
}

func parseReaderGenerator(data json.RawMessage) (ReaderGenerator, error) {
	var objmap map[string]*json.RawMessage
	err := json.Unmarshal(data, &objmap)
	if err != nil {
		return nil, err
	}

	var s string
	err = json.Unmarshal(*objmap["type"], &s)
	if err != nil {
		return nil, err
	}

	parser, ok := readerGenerators[s]
	if !ok {
		return nil, fmt.Errorf("Unrecognized generator type: %q", s)
	}

	return parser(data)
}

func parseGenerators(data []json.RawMessage) ([]Generator, error) {
	gens := make([]Generator, len(data))
	for i, genData := range data {
		var objmap map[string]*json.RawMessage
		err := json.Unmarshal(genData, &objmap)
		if err != nil {
			return nil, err
		}

		var s string
		err = json.Unmarshal(*objmap["type"], &s)
		if err != nil {
			return nil, err
		}

		parser, ok := generators[s]
		if !ok {
			return nil, fmt.Errorf("Unrecognized generator type: %q", s)
		}

		gen, err := parser(genData)
		if err != nil {
			return nil, err
		}
		gens[i] = gen
	}

	return gens, nil
}

func readFile(r io.Reader) (Config, error) {
	var c Config
	decoder := json.NewDecoder(r)

	err := decoder.Decode(&c)

	return c, err
}
