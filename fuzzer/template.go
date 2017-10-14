package fuzzer

//Template describes file-based template
type Template struct {
	File     string               `json:"file"`
	Fields   map[string]Generator `json:"fields"`
	generate func() string
}

func (g *Template) Generate() string {
	return g.generate()
}

func (Template) parseFile(fields map[string]Generator) func() string {

}

func (Template) parseField(field string, ) (Generator, error) {

}

func (Template) unmarshal(data []byte) (Generator, error) {

}
