SOURCES = main.c ../microstack/ILibLMS.c
SOURCES += ../microstack/ILibAsyncServerSocket.c ../microstack/ILibAsyncSocket.c ../microstack/ILibWebServer.c ../microstack/ILibWebClient.c ../microstack/ILibParsers.c ../microstack/md5.c ../microstack/sha1.c
SOURCES += ../heci/HECILinux.c ../heci/LMEConnection.c ../heci/PTHICommand.c
SOURCES += $(ADDITIONALSOURCES)

OBJECTS = $(patsubst %.c,%.o, $(SOURCES))

EXENAME = microlms

# Compiler command name
CC = gcc

# need to be separate for dependency generation	
INCDIRS = -I. -I../../microstack -I../../core

CFLAGS  ?= -g -Wall -D_POSIX -D_DEBUG -DMICROSTACK_NOTLS -fno-strict-aliasing $(INCDIRS)
LDFLAGS ?= -g -L. -lpthread -ldl -lutil -lrt

.PHONY: all clean

all: $(EXENAME)

$(EXENAME): $(OBJECTS)
	$(V)$(CC) $^ $(LDFLAGS) -o $@

release:
	$(MAKE) $(MAKEFILE) CFLAGS="-O2 -Wall -D_POSIX -D_DEBUG -DMICROSTACK_NOTLS -D_DEBUGLMS -fno-strict-aliasing $(INCDIRS)" LDFLAGS="-L. -lpthread -ldl -lutil"
	strip ./$(EXENAME)

linux32:
	$(MAKE) $(MAKEFILE) CFLAGS="-m32 -O2 -Wall -D_POSIX -D_DEBUG -DMICROSTACK_NOTLS -D_DEBUGLMS -fno-strict-aliasing $(INCDIRS)" LDFLAGS="-L. -lpthread -ldl -lutil -lrt -m32"
	strip ./$(EXENAME)

linux64:
	$(MAKE) $(MAKEFILE) CFLAGS="-O2 -Wall -D_POSIX -D_DEBUG -DMICROSTACK_NOTLS -D_DEBUGLMS -fno-strict-aliasing $(INCDIRS)" LDFLAGS="-L. -lpthread -ldl -lrt -lutil"
	strip ./$(EXENAME)

clean:
	rm -f *.o
	rm -f *.o *~ microlms
	rm -f ../heci/*.o
	rm -f ../microstack/*.o

depend: $(SOURCES)
	$(CC) -M $(CFLAGS) $(SOURCES) $(HEADERS) > depend

run:all
	rm -f mtrax
	set MALLOC_TRACE=mtrax
	export MALLOC_TRACE;
	./$(EXENAME)
	mtrace ./$(EXENAME) mtrax

vrun:all
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --track-origins=yes ./signer_linux

trace:
	mtrace ./$(EXENAME) mtrax
