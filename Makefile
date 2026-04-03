CXX = g++
CXXFLAGS = -Wall -Wextra -ggdb -std=c++20 -Werror

# source files
SRC = main.cpp \
      core/dispatcher.cpp

# output binary
OUT = tracer

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(OUT) $(SRC)

clean:
	rm -f $(OUT)