CC=gcc

all:stamach

stamach:stamach.o getmachine.o http.o fileop.o assoclist.o 
	$(CC) $^ -lpcap -liwinfo -lpthread -o $@

clean:
	rm -f *.o
	rm -f stamach
