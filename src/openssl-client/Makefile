OPENSSLDIR = ../openssl
BINDIR     = ../../bin

CC = gcc
RM = /bin/rm

CFLAGS = -g -Wall
LFLAGS = -lssl -lcrypto -ldl -g

INCDIR = -I. -I$(OPENSSLDIR)/include
LIBDIR = -L$(OPENSSLDIR)

OBJ = cmpclient.o cmpclient_help.o
BIN = cmpclient

all: $(BIN)

strip: all
	strip $(BIN)

$(BIN): $(OBJ) $(OPENSSLDIR)/libcrypto.a
	$(CC) -Wall -o $(BIN) $(OBJ) $(LFLAGS) $(INCDIR) $(LIBDIR)

cmpclient.o: cmpclient.c cmpclient.h cmpclient_help.h 
	$(CC) -Wall -c $(INCDIR) $(CFLAGS) -o cmpclient.o cmpclient.c

cmpclient_help.o: cmpclient_help.c cmpclient_help.h
	$(CC) -Wall -c $(INCDIR) $(CFLAGS) -o cmpclient_help.o cmpclient_help.c

clean:
	$(RM) -f $(OBJ) $(BIN)

install:
	cp $(BIN) $(BINDIR)

distclean: clean

.PHONY: distclean clean all strip
