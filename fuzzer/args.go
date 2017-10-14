package fuzzer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
)

//Generator creates a string using some internal properties
type Generator interface {
	Generate() string
}

//Prefix simply returns a specified value followed by the value of a
//specified generator
type Prefix struct {
	Value     string    `json:"value"`
	Generator Generator `json:"generator"`
}

//Generate returns a constant value
func (g *Prefix) Generate() string {
	return g.Value + g.Generator.Generate()
}

func (Prefix) unmarshal(data []byte) (Generator, error) {
	g := &Prefix{}

	var genData *struct {
		Value     string          `json:"value"`
		Generator json.RawMessage `json:"generator"`
	}
	err := json.Unmarshal(data, &genData)
	if err != nil {
		return nil, err
	}

	g.Value = genData.Value

	var objmap map[string]*json.RawMessage
	err = json.Unmarshal(genData.Generator, &objmap)
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

	gen, err := parser(genData.Generator)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	g.Generator = gen
	return g, err
}

//Constant simply returns a specified value
type Constant struct {
	Value string `json:"value"`
}

//Generate returns a constant value
func (g *Constant) Generate() string {
	return g.Value
}

func (Constant) unmarshal(data []byte) (Generator, error) {
	var g *Constant
	err := json.Unmarshal(data, &g)
	return g, err
}

//IntegerRandom returns a uniformly random number
type IntegerRandom struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

//Generate returns a uniformly random number
func (g *IntegerRandom) Generate() string {
	return strconv.Itoa(rand.Intn(g.Max-g.Min) + g.Min)
}

func (IntegerRandom) unmarshal(data []byte) (Generator, error) {
	var g *IntegerRandom
	err := json.Unmarshal(data, &g)
	return g, err
}

//IntegerNormalRandom generates a random integer from a normal distribution
type IntegerNormalRandom struct {
	Mean              float64 `json:"mean"`
	StandardDeviation float64 `json:"std_dev"`
}

//Generate returns a random number from a normal distribution
func (g *IntegerNormalRandom) Generate() string {
	return strconv.Itoa(int(rand.NormFloat64()*g.StandardDeviation + g.Mean))
}

func (IntegerNormalRandom) unmarshal(data []byte) (Generator, error) {
	var g *IntegerNormalRandom
	err := json.Unmarshal(data, &g)
	return g, err
}

//FloatRandom generates a random floating point number given min, max and
//precision
type FloatRandom struct {
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	Precision int     `json:"precision"`
}

//Generate returns a random floating point number
func (g *FloatRandom) Generate() string {
	return strconv.FormatFloat(rand.Float64()*(g.Max-g.Min)+g.Min, 'f', g.Precision, 64)
}

func (FloatRandom) unmarshal(data []byte) (Generator, error) {
	var g *FloatRandom
	err := json.Unmarshal(data, &g)
	return g, err
}

//FloatNormalRandom generates a random number from a normal distribution
type FloatNormalRandom struct {
	Mean              float64 `json:"mean"`
	StandardDeviation float64 `json:"standard_deviation"`
	Precision         int     `json:"precision"`
}

//Generate returns a random number from a normal distribution
func (g *FloatNormalRandom) Generate() string {
	return strconv.FormatFloat(rand.NormFloat64()*g.StandardDeviation+g.Mean, 'f', g.Precision, 64)
}

func (FloatNormalRandom) unmarshal(data []byte) (Generator, error) {
	var g *FloatNormalRandom
	err := json.Unmarshal(data, &g)
	return g, err
}
