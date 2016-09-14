# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall

# the build target executable:
CLIENT = client
SERVER = server

all: $(CLIENT)

$(CLIENT): $(CLIENT).c
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT).c

clean:
	$(RM) $(CLIENT)
