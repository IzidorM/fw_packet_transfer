ifndef $(TARGET)
TARGET=pt
endif


ifndef TOOLS_DIR
TOOLS_DIR = ../../../tools/
#TOOLS_DIR = ./
endif

ifndef BUILD_DIR
BUILD_DIR=/tmp/$(TARGET)
#BUILD_DIR=./build/
endif 

SRC_DIR = ../src/


PROJECT_BASE_DIR = .

LIBS_SRC= \
	../../../fw_byte_fifo/src/byte_fifo.c \
	$(SRC_DIR)/bsd_checksum.c \


FILES_TO_TEST_SRC= \
	$(SRC_DIR)/pt.c \
	$(SRC_DIR)/pt_pico.c \
	$(SRC_DIR)/pt_extended.c \

TESTS_SRC= Test_$(TARGET).c

C_FLAGS+=-g -ggdb3 \
	-Wall -Wextra -Werror -Wshadow \
	-Wundef \
	-Wconversion -Wno-sign-conversion \
	-std=c11 -pedantic \
	-fprofile-arcs -ftest-coverage \
	-fstack-protector-all
	-fsanitize=address,undefined \

DEFINES+=-D UNIT_TESTS \
	-D PT_EXTENDED_PACKET_SUPPORT \
	-D PT_DEBUG \

UNITY_INC_FILES = $(TOOLS_DIR)/Unity/src/
UNITY_SRC_FILES = $(TOOLS_DIR)/Unity/src/unity.c

TARGET_SRC_TEST_RUNNER_FILES= $(patsubst %.c, $(BUILD_DIR)/%_Runner.c, $(TESTS_SRC))

TARGET_SRC_ALL=$(FILES_TO_TEST_SRC) \
	$(TESTS_SRC) \
	$(TARGET_SRC_TEST_RUNNER_FILES) \
	$(UNITY_SRC_FILES) \
	$(LIBS_SRC)

INC_DIRS= \
	$(SRC_DIR) \
	$(UNITY_INC_FILES) \
	../../../fw_byte_fifo/src/ \
	. 

COVERAGE_FILES=$(FILES_TO_TEST_SRC:.c=.gcda)
COVERAGE_FILES_NO_PATH=$(notdir $(COVERAGE_FILES))

C_COMPILER=gcc

all: run

INC_DIRS_GCC = $(patsubst %,-I%, $(INC_DIRS))

run: $(BUILD_DIR)/$(TARGET)
	@echo "Running tests"
	@$(BUILD_DIR)/$(TARGET)
#	@time --format="\nTest run time: %E, Max memory: %M Kb" $(BUILD_DIR)/$(TARGET)
	@printf "\nGCOV:\n"
	@gcov -n $(BUILD_DIR)/$(COVERAGE_FILES_NO_PATH) |\
		sed 's/^\s*$$/Sum/' |\
		grep -E "Lines executed|File|Sum"


$(BUILD_DIR)/%_Runner.c: $(TESTS_SRC)
	@echo "generating $<"
	mkdir -p $(BUILD_DIR)/
	@ruby $(TOOLS_DIR)/Unity/auto/generate_test_runner.rb $< $@


$(BUILD_DIR)/$(TARGET): $(TARGET_SRC_ALL)
	@$(C_COMPILER) -dumpbase '' $(C_FLAGS) $(DEFINES) $(INC_DIRS_GCC) $(TARGET_SRC_ALL) -o $(BUILD_DIR)/$(TARGET)

#	@echo ""
#	@size $(BUILD_DIR)/$(TARGET)
#	@echo ""

clean:
	@rm -f $(BUILD_DIR)/$(TARGET) \
	$(BUILD_DIR)/*_Runner.c \
	$(BUILD_DIR)/*.gcno \
	*.gcda *.info *.gcov


ifeq ($(MAKECMDGOALS),rtags)
include $(TOOLS_DIR)/rtags/rtags.mk
endif

