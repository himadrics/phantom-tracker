CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g
INCLUDES = -I../../../include

TARGET = register_vm_backend
SRCS = register_vm_backend.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS)

clean:
	rm -f $(TARGET)
