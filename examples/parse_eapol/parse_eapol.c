#include <libwifi.h>

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int has_radiotap = 0;

void handle_pkt(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    unsigned long data_len = header->caplen;
    unsigned char *data = (unsigned char *) packet;

    // Initialise a libwifi_frame struct and populate it
    struct libwifi_frame frame = {0};
    int ret = libwifi_get_wifi_frame(&frame, data, data_len, has_radiotap);
    if (ret != 0) {
        return;
    }

    // Ensure the parsed frame is a data frame
    if (frame.frame_control.type == TYPE_DATA) {
        // Ensure the parsed data frame is a WPA handshake
        if (libwifi_check_wpa_handshake(&frame) > 0) {
            // Use libwifi to get the EAPOL message part, and also pretty-print it
            int part = libwifi_check_wpa_message(&frame);
            printf("WPA Handshake Message: %d (%s)\n", part, libwifi_get_wpa_message_string(&frame));

            // Initlaise a WPA Authentication Data struct and populate it
            struct libwifi_wpa_auth_data data = {0};
            libwifi_get_wpa_data(&frame, &data);

            // Print all of the available WPA Auth data
            printf("EAPOL: Version: %d\n", data.version);
            printf("EAPOL: Type: %d\n", data.type);
            printf("EAPOL: Length: %d\n", data.length);
            printf("EAPOL: Descriptor: %d\n", data.descriptor);
            printf("EAPOL: Key Info: Information: 0x%04x\n", data.key_info.information);
            printf("EAPOL: Key Info: Key Length: %d\n", data.key_info.key_length);
            printf("EAPOL: Key Info: Replay Counter: %" PRIu64 "\n", data.key_info.replay_counter);
            printf("EAPOL: Key Info: Nonce: ");
            for (size_t i = 0; i < sizeof(data.key_info.nonce); ++i) {
                printf("%02x ", data.key_info.nonce[i]);
            }
            printf("\n");

            printf("EAPOL: Key Info: IV: ");
            for (size_t i = 0; i < sizeof(data.key_info.iv); ++i) {
                printf("%02x ", data.key_info.iv[i]);
            }
            printf("\n");

            printf("EAPOL: Key Info: RSC: ");
            for (size_t i = 0; i < sizeof(data.key_info.rsc); ++i) {
                printf("%02x ", data.key_info.rsc[i]);
            }
            printf("\n");

            printf("EAPOL: Key Info: ID: ");
            for (size_t i = 0; i < sizeof(data.key_info.id); ++i) {
                printf("%02x ", data.key_info.id[i]);
            }
            printf("\n");

            printf("EAPOL: Key Info: MIC: ");
            for (size_t i = 0; i < sizeof(data.key_info.mic); ++i) {
                printf("%02x ", data.key_info.mic[i]);
            }
            printf("\n");

            printf("EAPOL: Key Info: Key Data Length: %d\n", data.key_info.key_data_length);
            if (data.key_info.key_data_length) {
                printf("EAPOL: Key Info: Key Data: ");
                for (size_t i = 0; i < data.key_info.key_data_length; ++i) {
                    printf("%02x ", data.key_info.key_data[i]);
                }
                printf("\n");
            }

            // Cleanup the WPA Data
            libwifi_free_wpa_data(&data);

            printf("\n");
        }
    }

    // Clean up the libwifi frame
    libwifi_free_wifi_frame(&frame);
}

void helpexit() {
    fprintf(stderr, "[!] Usage: ./parse_eapol --file <file.pcap>\n");
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

    dumper = pcap_dump_open(handle, "/tmp/parse_eapol.pcap");
    pcap_loop(handle, -1 /*INFINITY*/, &handle_pkt, (unsigned char *) dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);

    return 0;
}
