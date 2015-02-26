CC=gcc

CLPATH=../cryptlib
BINDIR=../../bin

CA=cmpserver-cl
FUNCTIONS=functions
DEFINES=defines.h

INCLUDEPATH=-I$(CLPATH)
LDFL=-L$(CLPATH) -lcl -lresolv -lpthread -ldl

CASRC=$(CA).c
CAOBJ=$(CA).o

FUNCSRC=$(FUNCTIONS).c
FUNCHDR=$(FUNCTIONS).h
FUNCOBJ=$(FUNCTIONS).o

OBJECTS=$(FUNCOBJ)

all: $(CA)

$(CA): $(CAOBJ) $(FUNCOBJ)
	$(CC) -g -o $(CA) -ldl $(CAOBJ) $(LDFL) $(OBJECTS)

$(CAOBJ): $(CASRC) $(FUNCHDR) $(DEFINES)
	$(CC) $(INCLUDEPATH) -g -c $(CASRC) -o $(CAOBJ)

$(FUNCOBJ): $(FUNCSRC) $(FUNCHDR) $(DEFINES)
	$(CC) $(INCLUDEPATH) -g -c $(FUNCSRC) -o $(FUNCOBJ)

dbclean:
	@echo '# Cleaning may fail #'
	-mysql -u'odbc' -p'CqRXRKm39uQUrN:2' odbc < ./tools/mysqldroptables.txt 2>/dev/null

clean:
	-rm -f $(CA) $(CAOBJ) $(FUNCOBJ)

distclean: clean dbclean

install:
	cp $(CA) $(BINDIR)

.PHONY: all distclean clean dbclean install
