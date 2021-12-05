CC=clang
CFLAGS=-Wall -Werror -O3 -o parse_beacon
LDFLAGS=-lpcap -lwifi

parse_eapol: parse_beacon.o
	$(CC) $(CFLAGS) parse_beacon.c $(LDFLAGS)

clean:
	rm parse_beacon *.o
