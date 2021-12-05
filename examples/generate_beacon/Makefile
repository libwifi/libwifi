CC=clang
CFLAGS=-Wall -Werror -O3 -o generate_beacon
LDFLAGS=-lpcap -lwifi

parse_eapol: generate_beacon.o
	$(CC) $(CFLAGS) generate_beacon.c $(LDFLAGS)

clean:
	rm generate_beacon *.o
