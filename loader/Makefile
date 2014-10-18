TARGET = TN
OBJS = main.o ../common/lib.o

CC = psp-gcc
AS = psp-as

CFLAGS = -O2 -G0 -Wall -I../include -I$(shell psp-config --pspsdk-path)/include -fno-pic -fno-strict-aliasing -fno-zero-initialized-in-bss -fomit-frame-pointer -mno-abicalls

all: $(TARGET).BIN

%.BIN: %.elf
	psp-strip -s -O binary -o $@ $<

$(TARGET).elf: $(OBJS)
	psp-ld -O1 -G0 --no-keep-memory -nostartfiles -nostdlib -T linker.x -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).BIN
