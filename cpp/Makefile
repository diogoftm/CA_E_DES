# Compiler and compiler flags
CC = g++
CFLAGS = -Wall -g

TARGETS = encrypt decrypt test speed

OPENSSL = -lssl -lcrypto

SRCS = EDES.cpp encrypt.cpp test.cpp decrypt.cpp speed.cpp

OBJS = $(SRCS:.cpp=.o)


all: $(TARGETS)

encrypt: EDES.o encrypt.o 
	$(CC) $(CFLAGS) -o encrypt EDES.o encrypt.o $(OPENSSL)

decrypt: EDES.o decrypt.o
	$(CC) $(CFLAGS) -o decrypt EDES.o decrypt.o $(OPENSSL)

test: EDES.o test.o
	$(CC) $(CFLAGS) -o test EDES.o test.o $(OPENSSL)

speed: EDES.o speed.o
	$(CC) $(CFLAGS) -o speed EDES.o speed.o $(OPENSSL)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGETS)

# Phony targets
.PHONY: all clean