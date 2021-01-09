CC=gcc
INCLUDE_DIR=/include
CFLAGS=-I$(INCLUDE_DIR)
OBJ=src/main.o
OUTPUT=userkit

build: $(OUTPUT)

$(OUTPUT): $(OBJ)
	$(CC) -o $(OUTPUT) $^ $(CFLAGS)

%.o: %.c
	$(CC) -Wall -c -o $@ $< $(CFLAGS)

.PHONY: clean build debug

debug: $(OBJ)
	$(CC) -o $(OUTPUT) $^ $(CFLAGS) -ggdb
	gdb $(OUTPUT)

clean:
	rm -f $(OUTPUT) *.o **/*.o
