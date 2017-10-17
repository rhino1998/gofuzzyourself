# Lanugo

Lanugo is a fuzzer and regression tester. It compares the behaviors of
binaries given various inputs

## Usage
Simply call lanugo with a valid configuration written in [skylark](https://github.com/google/skylark)
```
lanugo <config.sky>
```

### Configuration
```python
# List of binaries to compare
tests = []

# Number of times to run the binaries with generated input
runs = 1

# Format strings to describe logging output.
# Each line of output is run through the format strings
fmt = " %d\t%s\n"
err_fmt = "X%d\t%s\n"

# Value to be used as the stdin for each test run
# Valid Types:
#  String: simply fed into the stdin of each test
#  Indexable: will compose other valid values in order
#  Callable: called to generate one of the above types
stdin = []

# Value to be used as the stdin for each test run
# Valid Types:
#  Writer: will simply write to this. Examples include files 
#          and the main executable stderr and stdout
#  Indexable: will write to all values in the indexable type
#  Callable: called to generate one of the above types
stdin = []
stderr = []

# Values to be passed to the test binary as arguments in a list
# Valid Types:
#  Callable: anything that can be called to generate a valid value 
#  Stringer: anything that can be represented as a string
args = []

# Values to be passed to the test binary as arguments in a dictionary with string keys
# Valid Types:
#  Callable: anything that can be called to generate a valid value 
#  Stringer: anything that can be represented as a string
vars = dict()
```
