package fuzzer

import (
	"fmt"

	"github.com/google/skylark"
)

//TODO make this actually load modules
func load(thread *skylark.Thread, module string) (skylark.StringDict, error) {
	return nil, fmt.Errorf("Cannot load module %q; loading not yet implemented", module)
}
