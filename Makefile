CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2
CPPFLAGS = -Iinclude
LDFLAGS = 
LDLIBS = -lm

SRC = src/main.c src/ledger.c src/sha256.c src/ecdsa.c
OBJ = $(SRC:.c=.o)
TARGET = library

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LDLIBS)

%.o: %.c include/*.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
