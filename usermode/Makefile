CC?=gcc

INCLUDE_DIR?=include
LIB_DIR?=lib

PICOTCP_DIR?=$(LIB_DIR)/picotcp
PICOTCP_HEADERS?=$(PICOTCP_DIR)/build/include
PICOTCP_LIB?=$(PICOTCP_DIR)/build/lib/libpicotcp.a

CFLAGS?=-I$(INCLUDE_DIR) -I$(PICOTCP_HEADERS)

OBJ=src/pico.o src/pico_dev_ipc.o src/pico_dev_sock.o src/utils.o
CLI_OBJ=src/client.o $(OBJ)
SRV_OBJ=src/server.o $(OBJ)

CLIENT?=client
SERVER?=server

build: $(CLIENT) $(SERVER)

lib:
	mkdir lib

# I don't use PICOTCP_LIB here in case the user wants to override it, 
# in which case we do not want to compile picotcp again.
$(PICOTCP_DIR)/build/lib/libpicotcp.a:
	$(MAKE) -C $(PICOTCP_DIR) PREFIX=build IPC=1 IPV6=0 ICMP4=0

$(CLIENT): $(PICOTCP_LIB) $(CLI_OBJ)
	$(CC) -o $@ -L$(PICOTCP_DIR)/build/lib $(CLI_OBJ) -lpicotcp

$(SERVER): $(PICOTCP_LIB) $(SRV_OBJ)
	$(CC) -o $@ -L$(PICOTCP_DIR)/build/lib $(SRV_OBJ) -lpicotcp

%.o: %.c
	$(CC) -Wall -c -o $@ $< $(CFLAGS)

.PHONY: clean build debug install

install: lib
	git clone git@github.com:tass-belgium/picotcp.git $(PICOTCP_DIR) --depth 1

# debug: $(OBJ)
# 	$(CC) -o $(CLIENT) $^ $(CFLAGS) -ggdb
# 	gdb $(OUTPUT)

clean:
	rm -rf $(CLIENT) $(SERVER) *.o **/*.o lib/*/build
