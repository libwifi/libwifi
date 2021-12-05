CC=clang
CFLAGS=-Wall -Werror -O3 -o parse_eapol
LDFLAGS=-lpcap -lwifi

parse_eapol: parse_eapol.o
	$(CC) $(CFLAGS) parse_eapol.c $(LDFLAGS)

clean:
	rm parse_eapol *.o
