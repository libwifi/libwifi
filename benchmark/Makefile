CC=clang
CFLAGS=-Wall -Werror -O3 -o benchmark_beacon
LDFLAGS=-lpcap -lwifi

benchmark_beacon: benchmark_beacon.o
	$(CC) $(CFLAGS) benchmark_beacon.c $(LDFLAGS)

clean:
	rm benchmark_beacon *.o
