# Specify the compiler
CC = g++

# Specify the object files
OBJECTS = AESProject.cpp AESFunctions.cpp

# Specify the executable file
EXECUTABLE = AES_Encryption

# Rule to build the executable
$(EXECUTABLE): $(OBJECTS)
    $(CC) -v -o $@ $^

# Rule to build object files
%.o: %.cpp $(HEADER)
    $(CC) -c -o $@ $<

# Specify the header file
HEADER = AESFunctions.