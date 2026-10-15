CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2
CPPFLAGS = -Iinclude
LDFLAGS = 
LDLIBS = -lcrypto -lm
OPENSSL_CPPFLAGS = -IC:/msys64/ucrt64/include
OPENSSL_LDFLAGS = -LC:/msys64/ucrt64/lib

SRC = src/main.c src/ledger.c src/sha256.c src/ecdsa.c
OBJ = $(SRC:.c=.o)
TARGET = library
TEST_TARGET = tests/test_runner

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OPENSSL_CPPFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(OPENSSL_LDFLAGS) $(LDLIBS)

%.o: %.c include/*.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OPENSSL_CPPFLAGS) -c $< -o $@

$(TEST_TARGET): tests/test_runner.c src/ledger.c src/sha256.c src/ecdsa.c include/*.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OPENSSL_CPPFLAGS) -o $@ tests/test_runner.c src/ledger.c src/sha256.c src/ecdsa.c $(OPENSSL_LDFLAGS) $(LDLIBS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_TARGET)

.PHONY: all clean test
