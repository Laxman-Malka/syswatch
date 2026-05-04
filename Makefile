CXX = g++
CXXFLAGS = -Wall -Wextra -ggdb -std=c++20 -Werror
LDFLAGS = -ljson-c

# source files
SRC = main.cpp \
      core/dispatcher.cpp\
	  core/cli.cpp

OUT = tracer

SYSCALLS = syscalls/*
TEMPLATES = core/*.hpp

PYTHON = python3
VENV = temp

all: $(OUT)

$(OUT): $(SRC) $(SYSCALLS) $(TEMPLATES) syscalls/generated_syscalls.hpp
	$(CXX) $(CXXFLAGS) -o $(OUT) $(SRC) $(LDFLAGS)

syscalls/generated_syscalls.hpp: tools/gensyscalls.py
	$(PYTHON) -m venv $(VENV)
	. $(VENV)/bin/activate && pip install bs4 requests
	. $(VENV)/bin/activate && python tools/gensyscalls.py
	rm -rf $(VENV)

clean:
	rm -f $(OUT)
	rm -f syscalls/generated_syscalls.hpp