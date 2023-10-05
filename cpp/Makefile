# Compiler and compiler flags
CC = g++
CFLAGS = -Wall -g -w

TARGETS = encrypt decrypt test speed test_edes

OPENSSL = -lssl -lcrypto

GTEST = -lgtest -lgtest_main

SRCS =  EDES.cpp encrypt.cpp test.cpp decrypt.cpp speed.cpp test_edes.cpp

OBJS = $(SRCS:.cpp=.o)


all: $(TARGETS)

encrypt: EDES.o encrypt.o
	$(CC) $(CFLAGS) -o encrypt EDES.o encrypt.o $(OPENSSL)

decrypt: EDES.o decrypt.o
	$(CC) $(CFLAGS) -o decrypt EDES.o decrypt.o $(OPENSSL)

test: EDES.o test.o
	$(CC) $(CFLAGS) -o test EDES.o test.o $(OPENSSL)

test_edes: EDES.o test_edes.o
	$(CC) $(CFLAGS) -o test_edes EDES.o test_edes.o $(OPENSSL) $(GTEST)

speed: EDES.o speed.o
	$(CC) $(CFLAGS) -o speed EDES.o speed.o $(OPENSSL)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGETS)

# Phony targets
.PHONY: all clean