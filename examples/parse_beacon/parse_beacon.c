#include <libwifi.h>

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int has_radiotap = 0;

int print_tag_info(unsigned char *tag_data, size_t tag_data_len) {
    // Initialise a libwifi_tag_iterator
    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, tag_data, tag_data_len) != 0) {
        return -1;
    }

    do {
        printf("\tTag: %d (%s) (Size: %d)\n", it.tag_header->tag_num,
                                              libwifi_get_tag_name(it.tag_header->tag_num),
                                              it.tag_header->tag_len);

        int max_size = 16;
        if (it.tag_header->tag_len < 16) {
            max_size = it.tag_header->tag_len;
        }
        printf("\t\t%d bytes of Tag Data: ", max_size);
        for (size_t i = 0; i < max_size; i++) {
            printf("%02x ", it.tag_data[i]);
        }
        printf("\n");
    } while (libwifi_tag_iterator_next(&it) != -1);

    return 0;
}

void handle_pkt(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    unsigned long data_len = header->caplen;
    unsigned char *data = (unsigned char *) packet;

    // Initialise a libwifi_frame struct and populate it
    struct libwifi_frame frame = {0};
    int ret = libwifi_get_wifi_frame(&frame, data, data_len, has_radiotap);
    if (ret != 0) {
        return;
    }

    // Ensure the frame is a Beacon frame
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
        // Initalise a libwifi_bss struct and populate it with the data from the sniffed frame
        struct libwifi_bss bss = {0};
        ret = libwifi_parse_beacon(&bss, &frame);
        if (ret != 0) {
            return;
        }

        // Print basic information from the new struct
        printf("ESSID: %s\n", bss.hidden ? "(hidden)" : bss.ssid);
        printf("BSSID: " MACSTR "\n", MAC2STR(bss.bssid));
        printf("Receiver: " MACSTR "\n", MAC2STR(bss.receiver));
        printf("Transmitter: " MACSTR "\n", MAC2STR(bss.transmitter));
        printf("Channel: %d\n", bss.channel);
        printf("WPS: %s\n", bss.wps ? "Yes" : "No");

        // Initialse a char buffer of length LIBWIFI_SECURITY_BUF_LEN, and use libwifi to
        // write the security suite (WEP, WPA, etc) to it, before printing it.
        char sec_buf[LIBWIFI_SECURITY_BUF_LEN];
        libwifi_get_security_type(&bss, sec_buf);
        printf("Encryption: %s\n", sec_buf);

        // We can re-use the sec_buf buffer for other security related items, since libwifi
        // will take care of the memory for us.
        // We'll use the same buffer to get the WPA/2/3 group ciphers from the beacon, if any.
        libwifi_get_group_ciphers(&bss, sec_buf);
        printf("\tGroup Ciphers: %s\n", sec_buf);

        // ... and the same for the pairwise ciphers
        libwifi_get_pairwise_ciphers(&bss, sec_buf);
        printf("\tPairwise Ciphers: %s\n", sec_buf);

        // ... and the same for the authentication maagement key suites
        libwifi_get_auth_key_suites(&bss, sec_buf);
        printf("\tAuth Key Suites: %s\n", sec_buf);

        // Check for enabled RSN Capabilities. In this example, we will check for the
        // presence of Management Frame Protection (802.11w)
        if (bss.rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_CAPABLE) {
            printf("\tMFP Capable: Yes\n");
        }
        if (bss.rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_REQUIRED) {
            printf("\tMFP Required: Yes\n");
        }

        // If any tagged parameters are available for this frame, we can iterate through them
        // since libwifi will automatically find them.
        if (bss.tags.length) {
            printf("Tagged Parameters:\n");
            print_tag_info(bss.tags.parameters, bss.tags.length);
        } else {
            printf("Tagged Parameters: None\n");
        }

        // Cleanup the libwifi bss
        libwifi_free_bss(&bss);
    }

    printf("\n");

    // Clean up the libwifi frame
    libwifi_free_wifi_frame(&frame);
}

void helpexit() {
    fprintf(stderr, "[!] Usage: ./parse_beacon --file <file.pcap>\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    pcap_dumper_t *dumper = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 2) {
        helpexit();
    }
    if (strcmp(argv[1], "--file") == 0) {
        if ((handle = pcap_open_offline(argv[2], errbuf)) == NULL) {
            fprintf(stderr, "[!] Error opening file %s (%s)\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        helpexit();
    }

    int linktype = pcap_datalink(handle);
    if (linktype == DLT_IEEE802_11_RADIO) {
        has_radiotap = 1;
    }
    if (linktype != DLT_IEEE802_11 && linktype != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "[!] 802.11 and radiotap headers not provided (%d)\n", pcap_datalink(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("[+] Setup Complete\n");

    dumper = pcap_dump_open(handle, "/tmp/parse_beacon.pcap");
    pcap_loop(handle, -1 /*INFINITY*/, &handle_pkt, (unsigned char *) dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
