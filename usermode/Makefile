CC?=gcc
OUTPUT?=userkit

INCLUDE_DIR?=include
LIB_DIR?=lib

PICOTCP_DIR?=$(LIB_DIR)/picotcp
PICOTCP_HEADERS?=$(PICOTCP_DIR)/include
PICOTCP_LIB?=$(PICOTCP_DIR)/build/lib/libpicotcp.a

CFLAGS?=-I$(INCLUDE_DIR) -I$(PICOTCP_HEADERS)

OBJ=src/main.o src/pico.obj

build: $(OUTPUT)

lib:
	mkdir lib

# I don't use PICOTCP_LIB here in case the user wants to override it, 
# in which case we do not want to compile picotcp again.
$(PICOTCP_DIR)/build/lib/libpicotcp.a:
	$(MAKE) -C $(PICOTCP_DIR) PREFIX=build

$(OUTPUT): $(PICOTCP_LIB) $(OBJ)
	$(CC) -o $(OUTPUT) $^ $(CFLAGS)

%.o: %.c
	$(CC) -Wall -c -o $@ $< $(CFLAGS)

.PHONY: clean build debug install

install: lib
	git clone git@github.com:tass-belgium/picotcp.git $(PICOTCP_DIR) --depth 1

debug: $(OBJ)
	$(CC) -o $(OUTPUT) $^ $(CFLAGS) -ggdb
	gdb $(OUTPUT)

clean:
	rm -rf $(OUTPUT) *.o **/*.o lib/*/build
