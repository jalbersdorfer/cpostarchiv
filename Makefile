CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

all: mysql_probe

mysql_probe: mysql_probe.o mysql_wire.o
	$(CC) $(CFLAGS) -o $@ mysql_probe.o mysql_wire.o

mysql_probe.o: mysql_probe.c mysql_wire.h
	$(CC) $(CFLAGS) -c mysql_probe.c

mysql_wire.o: mysql_wire.c mysql_wire.h
	$(CC) $(CFLAGS) -c mysql_wire.c

clean:
	rm -f mysql_probe *.o

.PHONY: all clean
