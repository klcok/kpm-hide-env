ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set. Example: make TARGET_COMPILE=aarch64-linux-gnu-)
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
STRIP = $(TARGET_COMPILE)strip

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS += -Wall -Wno-unused-variable -O2 -fno-stack-protector -fno-builtin

objs := hide_env.o

all: hide_env.kpm

hide_env.kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -Thide_env.lds -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm *.o
