# BigWeiner MicroVM Makefile
# Build: make
# Python: make python

CC = clang
CFLAGS = -Wall -Wextra -Wpedantic -fPIC -shared -O3 -DNDEBUG
CFLAGS_DEBUG = -Wall -Wextra -Wpedantic -fPIC -g -O0 -DDEBUG

# Python paths
PYTHON_INC = $(shell python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
PYTHON_LIB = $(shell python3 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDFLAGS = $(shell python3 -c "import sysconfig; print(sysconfig.get_config_var('LDFLAGS'))")
PYTHON_SITEARCH = $(shell python3 -c "import site; print(site.getsitepackages()[0] if site.getsitepackages() else site.getusersitepackages())")

# Source files
MICROVM_SRC = src/microvm.c
MICROVM_HDR = include/microvm.h
PYTHON_SRC = src/microvm_python.c

# Output
LIB_OUT = libmicrovm.a
PYTHON_OUT = microvm.so
TEST_OUT = microvm_test

.PHONY: all clean python test install info

all: $(LIB_OUT)

$(LIB_OUT): $(MICROVM_SRC) $(MICROVM_HDR)
	$(CC) $(CFLAGS) -c $(MICROVM_SRC) -o $(LIB_OUT)

python: $(PYTHON_OUT)

$(PYTHON_OUT): $(PYTHON_SRC) $(MICROVM_SRC) $(MICROVM_HDR)
	$(CC) $(CFLAGS) -Iinclude -I$(PYTHON_INC) \
		$(PYTHON_SRC) $(MICROVM_SRC) \
		-o $(PYTHON_OUT) $(PYTHON_LDFLAGS) -lpthread

test: $(TEST_OUT)

$(TEST_OUT): tests/test.c $(MICROVM_SRC) $(MICROVM_HDR)
	$(CC) $(CFLAGS_DEBUG) -Iinclude tests/test.c $(MICROVM_SRC) -o $(TEST_OUT) -lpthread

run-test: test
	./$(TEST_OUT)

clean:
	rm -f $(LIB_OUT) $(PYTHON_OUT) $(TEST_OUT)
	rm -rf build/ *.o

install: $(PYTHON_OUT)
	cp $(PYTHON_OUT) $(PYTHON_SITEARCH)/
	@echo "Installed to $(PYTHON_SITEARCH)"

debug: CFLAGS = $(CFLAGS_DEBUG)
debug: clean all

info:
	@echo "Python include: $(PYTHON_INC)"
	@echo "Python lib: $(PYTHON_LIB)"
	@echo "Python LDFLAGS: $(PYTHON_LDFLAGS)"
	@echo "Python site-packages: $(PYTHON_SITEARCH)"
	@echo "CC: $(CC)"
