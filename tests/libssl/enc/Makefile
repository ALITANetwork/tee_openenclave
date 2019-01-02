CC=gcc
CXX=g++
RM=rm	-f
CPPFLAGS=-g $(shell root-config --cflags)
LDFLAGS=-g $(shell root-config --ldflags)
LDLIBS=-lssl -lcrypto

SRCS=sslexampe2.c \
     sslconnect.c

OBJS=$(subst .c,.o,$(SRCS))

all:	sslexampe2 sslconnect

sslexampe2: sslexampe2.o
	$(CC) $(LDFLAGS) -o sslexampe2 sslexampe2.o $(LDLIBS) 

sslconnect: sslconnect.o
	$(CC) $(LDFLAGS) -o sslconnect sslconnect.o $(LDLIBS) 

depend:	.depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CPPFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)

distclean:	clean
	$(RM) *~ .depend

include	.depend
