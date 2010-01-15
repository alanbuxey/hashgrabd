RM=/bin/rm
CC=gcc

INCLUDEDIR=-I../include

SOURCES=main.c capture.c edonkey.c bittorrent.c network.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=hashgrab

build: all

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) ${LDFLAGS} -lpcap -o ../$@ $(OBJECTS)

clean:
	$(RM) -f $(OBJECTS) *~ 

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) $< -c

