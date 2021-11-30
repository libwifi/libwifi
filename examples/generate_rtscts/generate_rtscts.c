#include <libwifi.h>

#include <pcap.h>

#include <bits/types/struct_timeval.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

pcap_dumper_t *filedumper = NULL;

void create_write_rtscts() {
    printf("[*] Creating RTS Frame\n");
    struct libwifi_rts rts = {0};
    unsigned char transmitter[6] = "\x00\x20\x91\xAA\xBB\xCC";
    unsigned char receiver[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
    libwifi_create_rts(&rts, transmitter, receiver, 32);

    printf("[*] Writing RTS Frame to pcap\n");
    struct pcap_pkthdr pkt_hdr = {0};
    struct timeval tv = {0};
    pkt_hdr.caplen = sizeof(struct libwifi_rts);
    pkt_hdr.len = sizeof(struct libwifi_rts);
    gettimeofday(&tv, NULL);
    pkt_hdr.ts = tv;
    pcap_dump((unsigned char *) filedumper, &pkt_hdr, (const unsigned char *) &rts);

    printf("[*] Creating CTS Frame\n");
    struct libwifi_cts cts = {0};
    libwifi_create_cts(&cts, receiver, 32);

    printf("[*] Writing CTS Frame to pcap\n");
    memset(&pkt_hdr, 0, sizeof(struct pcap_pkthdr));
    memset(&tv, 0, sizeof(struct timeval));
    pkt_hdr.caplen = sizeof(struct libwifi_cts);
    pkt_hdr.len = sizeof(struct libwifi_cts);
    gettimeofday(&tv, NULL);
    pkt_hdr.ts = tv;
    pcap_dump((unsigned char *) filedumper, &pkt_hdr, (const unsigned char *) &cts);
}

void helpexit() {
    fprintf(stderr, "[!] Usage: ./generate_beacon --file <file.pcap>\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    FILE *pcapfile = NULL;

    if (argc < 2) {
        helpexit();
    }
    if (strcmp(argv[1], "--file") == 0) {
        pcapfile = fopen(argv[2], "w+");
        if ((handle = pcap_open_dead(DLT_IEEE802_11, BUFSIZ)) == NULL) {
            fprintf(stderr, "[!] Error opening dead capture (%s)\n", errbuf);
            exit(EXIT_FAILURE);
        }
        if ((filedumper = pcap_dump_fopen(handle, pcapfile)) == NULL) {
            fprintf(stderr, "[!] Error opening file %s (%s)\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        helpexit();
    }

    printf("[+] Setup Complete\n");

    create_write_rtscts();

    pcap_dump_close(filedumper);
    pcap_close(handle);
    return 0;
}
