ROOT = /home/feiluo/workspace/cplusplus/pcaptest
DIR_INC = -I $(ROOT)/libpcap
LIBS = $(ROOT)/libpcap/libpcap.a
CFLAG_DEBUG = -D_DEBUG -ggdb -O0 -static -static-libgcc -static-libstdc++ -g3 -std=gnu99 -Wall 
CFLAGS = $(CFLAG_DEBUG) $(DIR_INC) $(DIR_LIB)

objects = main.o

.PHONY : clean

all: test

test: $(objects) $(USERLIB)
	g++ $(CFLAGS) -o test $(objects) $(LIBS)

$(objects): %.o: %.cc
	$(CC) -c $(CFLAGS) $< -o $@

clean: 
	rm test $(objects)
