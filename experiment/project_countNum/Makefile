# CXX = g++
# CXXFLAGS = -std=c++11 -Wall -I"D:/C++/cryptopp890" -I"D:/C++/gmp-6.2.1/build/include" -I"D:/C++/libpaillier-master"
# LDFLAGS = -L"D:/C++/cryptopp890" -L"D:/C++/gmp-6.2.1/build/lib" -L"D:/C++/libpaillier-master" -lgmp -lgmpxx  -lcryptopp -lpaillier

#  SRC = main.cpp Vehicle.cpp RSU.cpp ES.cpp MyElgamal.cpp FN_Allocation.cpp 
# OBJ = $(SRC:.cpp=.o)
# EXEC = main

# all: $(EXEC)

# $(EXEC): $(OBJ)
# 	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# %.o: %.cpp
# 	$(CXX) $(CXXFLAGS) -c $< -o $@

# clean:
# 	rm -f $(OBJ) $(EXEC)
CXX = g++
CXXFLAGS = -std=c++17 -Wall \
    -I"D:/C++/cryptopp890" \
    -I"D:/gmp-6.2.1/build/include" \
    -I"D:/C++/libpaillier-master"

LDFLAGS = -L"D:/C++/cryptopp890" \
    -L"D:/gmp-6.2.1/build/lib" \
    -L"D:/C++/libpaillier-master" \
    -lgmp -lgmpxx \
    -lcryptopp -lpaillier

SRC = main.cpp Vehicle.cpp RSU.cpp ES.cpp MyElgamal.cpp FN_Allocation.cpp SP.cpp CS.cpp paillier1.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = main

# Target to build the executable
all: $(EXEC)

# Link object files into the executable
$(EXEC): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile .cpp files to .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Target to clean up object files and the executable
clean:
	rm -f $(OBJ) $(EXEC)
