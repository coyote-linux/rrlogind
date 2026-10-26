CC = gcc
LD = ld
RM = rm -f
CFLAGS = -Wall -m486 -O2 -I../rrconf
LDFLAGS = -s -O2
OBJS = rrlogind.o rrauth.o rrlogin.o rrlogout.o md5.o rrstatus.o \
	rrcomm.o daemon.o rrproto.o
LIBS =

rrlogind: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

all: rrlogind

depend:
	gcc -MM $(OBJS:.o=.c)

clean:
	$(RM) *.o rrlogind core

install: rrlogind
	 install -c -m 755 rrlogind /sbin
	 install -c -m 644 rrlogind.8 /usr/man/man8

rrlogind.o: rrlogind.c roadrunner.h md5.h

rrauth.o: rrauth.c roadrunner.h md5.h

rrlogin.o: rrlogin.c roadrunner.h md5.h

rrlogout.o: rrlogout.c roadrunner.h md5.h

md5.o: md5.c md5.h

rrstatus.o: rrstatus.c roadrunner.h

rrcomm.o: rrcomm.c roadrunner.h

daemon.o: daemon.c

rrproto.o: rrproto.c roadrunner.h md5.h
