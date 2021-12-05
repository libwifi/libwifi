CC=clang
CFLAGS=-Wall -Werror -O3 -o generate_rtscts
LDFLAGS=-lpcap -lwifi

parse_eapol: generate_rtscts.o
	$(CC) $(CFLAGS) generate_rtscts.c $(LDFLAGS)

clean:
	rm generate_rtscts *.o
