CXX = g++
CXXFLAGS = -std=c++11 -Wall -I"D:/C++/cryptopp890"
LDFLAGS = -L"D:/C++/cryptopp890" -lcryptopp

SRC = main.cpp Vehicle.cpp RSU.cpp ES.cpp MyElgamal.cpp FN_Allocation.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = main

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
