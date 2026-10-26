CC = gcc
LD = ld
RM = rm -f
CFLAGS = -Wall -m486 -O2
LDFLAGS = -s -O2
OBJS = rrconf.o md5.o
LIBS =

rrconf: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

all: rrconf

depend:
	gcc -MM $(OBJS:.o=.c)

clean:
	$(RM) *.o rrconf core

install: rrconf
	 install -c -m 755 rrconf /sbin

rrconf.o: rrconf.c rrconf.h md5.h

md5.o: md5.c md5.h
