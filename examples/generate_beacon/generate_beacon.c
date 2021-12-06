#include <libwifi.h>

#include <pcap.h>

#include <bits/types/struct_timeval.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

pcap_dumper_t *filedumper = NULL;

void create_write_beacon() {
    printf("[*] Creating Beacon Frame\n");
    struct libwifi_beacon beacon = {0};
    unsigned char transmitter[6] = {0};

    libwifi_random_mac(transmitter, NULL);
    unsigned char receiver[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";

    libwifi_create_beacon(&beacon, receiver, transmitter, "libwifi-beacon", 6);
    libwifi_quick_add_tag(&beacon.tags, TAG_VENDOR_SPECIFIC,
                         (unsigned char *) "libwifi-tag", strlen("libwifi-tag"));

    unsigned char *buf = NULL;
    size_t buf_len = libwifi_get_beacon_length(&beacon);
    buf = malloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "[!] Couldn't allocate buffer for beacon dump.\n");
        exit(EXIT_FAILURE);
    }
    memset(buf, 0, buf_len);
    libwifi_dump_beacon(&beacon, buf, buf_len);

    printf("[*] Writing Beacon Frame to pcap\n");
    struct pcap_pkthdr pkt_hdr = {0};
    struct timeval tv = {0};
    pkt_hdr.caplen = buf_len;
    pkt_hdr.len = buf_len;
    gettimeofday(&tv, NULL);
    pkt_hdr.ts = tv;
    pcap_dump((unsigned char *) filedumper, &pkt_hdr, buf);
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

    create_write_beacon();

    pcap_dump_close(filedumper);
    pcap_close(handle);
    return 0;
}
