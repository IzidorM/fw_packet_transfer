
APP_REV=0.1
APP_SERVER_NAME=pt_test_server_$(APP_REV)
APP_CLIENT_NAME=pt_test_client_$(APP_REV)

BOARD=linux
CPU=intel

DEFINES= \
	-D _GNU_SOURCE \
	-D PT_DEBUG \
	-D PT_EXTENDED_PACKET_SUPPORT \

#LIBS= \
#	-lpthread


BUILD_DIR=/tmp/$(shell whoami)/build
BIN_DIR=bin

CFLAGS_USER = -Wall -g -ggdb3 -Os -std=gnu11 -pedantic #-nostdlib

APP_SERVER_SRC= \
	../fw_packet_transfer_server.c \

APP_CLIENT_SRC= \
	../fw_packet_transfer_client.c \

#	delay.c \


PT_DIR=../../src/
PT_EXTERNAL=../../external
SRCS_RELATIVE_PATH= $(PT_DIR)/bsd_checksum.c \
	$(PT_DIR)/pt.c \
	$(PT_DIR)/pt_extended.c \
	$(PT_DIR)/pt_pico.c \
	$(PT_EXTERNAL)/fw_byte_fifo/src/byte_fifo.c \
	../socket_interface.c \
	../utils.c \


SRCS_SERVER_RELATIVE_PATH = $(APP_SERVER_SRC)
SRCS_CLIENT_RELATIVE_PATH = $(APP_CLIENT_SRC) 
INCLUDE_DIRS = . ../ \
	$(PT_DIR) \
	$(PT_EXTERNAL)/fw_byte_fifo/src/

#DLP=$(ULIB_DIR)/libs/data_link_protocol_dlp/
#include $(DLP)/dlp.mk


CC=gcc

INCS_RELATIVE_PATH:= $(patsubst %, -I%, $(INCLUDE_DIRS))
SRCS_FULL_PATH:=$(shell readlink -f $(SRCS_RELATIVE_PATH))
SRCS_SERVER_FULL_PATH:=$(shell readlink -f $(SRCS_SERVER_RELATIVE_PATH))
SRCS_CLIENT_FULL_PATH:=$(shell readlink -f $(SRCS_CLIENT_RELATIVE_PATH))

all: \
	$(BIN_DIR)/$(APP_CLIENT_NAME).elf \
	$(BIN_DIR)/$(APP_SERVER_NAME).elf \


$(BIN_DIR)/$(APP_SERVER_NAME).elf: 
	@if [ ! -d $(BIN_DIR) ] ; then mkdir $(BIN_DIR); fi
	@$(CC) \
	$(CFLAGS_USER) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_FULL_PATH) \
	$(SRCS_SERVER_FULL_PATH) -o $@

$(BIN_DIR)/$(APP_CLIENT_NAME).elf: 
	@if [ ! -d $(BIN_DIR) ] ; then mkdir $(BIN_DIR); fi
	@$(CC) \
	$(CFLAGS_USER) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_FULL_PATH) \
	$(SRCS_CLIENT_FULL_PATH) -o $@


clean:
	@rm $(BIN_DIR)/$(APP_SERVER_NAME).elf $(BIN_DIR)/$(APP_CLIENT_NAME).elf

rtags:
	@echo "Updating rtags..."
	@rc --project-root  . -c gcc \
	$(CFLAGS_USER) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_FULL_PATH) \
	$(SRCS_SERVER_FULL_PATH) \
	$(SRCS_CLIENT_FULL_PATH) \
