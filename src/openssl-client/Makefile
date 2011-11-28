ROOT       = ../..
OPENSSLDIR = $(ROOT)/src/openssl
BINDIR     = $(ROOT)/bin

CC = gcc
RM = /bin/rm

CFLAGS = -g -Wall
# -lcurl and -lrt is for curl
LFLAGS = -lssl -lcrypto -ldl -g -lcurl -lrt -lidn

INCDIR = -I. -I$(OPENSSLDIR)/include -I$(ROOT)/include
LIBDIR = -L$(OPENSSLDIR) -L$(ROOT)/lib

OBJ = cmpclient.o cmpclient_help.o
BIN = cmpclient

all: $(BIN)

strip: all
	strip $(BIN)

$(BIN): $(OBJ) $(OPENSSLDIR)/libcrypto.a
	$(CC) -Wall -o $(BIN) $(OBJ) $(LFLAGS) $(INCDIR) $(LIBDIR)

cmpclient.o: cmpclient.c cmpclient.h cmpclient_help.h $(OPENSSLDIR)/include/openssl/cmp.h
	$(CC) -Wall -c $(INCDIR) $(CFLAGS) -o cmpclient.o cmpclient.c

cmpclient_help.o: cmpclient_help.c cmpclient_help.h
	$(CC) -Wall -c $(INCDIR) $(CFLAGS) -o cmpclient_help.o cmpclient_help.c

clean:
	$(RM) -f $(OBJ) $(BIN)

install:
	mkdir -p $(BINDIR)
	cp $(BIN) $(BINDIR)

distclean: clean

.PHONY: all distclean clean all strip
