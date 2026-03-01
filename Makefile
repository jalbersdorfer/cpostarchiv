CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

all: mysql_probe postarchiv

mysql_probe: mysql_probe.o mysql_wire.o
	$(CC) $(CFLAGS) -o $@ mysql_probe.o mysql_wire.o

postarchiv: app.o mysql_wire.o template_engine.o
	$(CC) $(CFLAGS) -o $@ app.o mysql_wire.o template_engine.o

mysql_probe.o: mysql_probe.c mysql_wire.h
	$(CC) $(CFLAGS) -c mysql_probe.c

mysql_wire.o: mysql_wire.c mysql_wire.h
	$(CC) $(CFLAGS) -c mysql_wire.c

app.o: app.c mysql_wire.h
	$(CC) $(CFLAGS) -c app.c

template_engine.o: template_engine.c template_engine.h
	$(CC) $(CFLAGS) -c template_engine.c

clean:
	rm -f mysql_probe postarchiv *.o

.PHONY: all clean
