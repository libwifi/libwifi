#include <libwifi.h>

#include <stdio.h>
#include <time.h>

// A simple 802.11 Beacon with an SSID and a Channel tag
#define BEACON_FRAME "\x80\x00\x00\x00\xff\xff\xff\xff" \
                     "\xff\xff\x00\x20\x91\x11\x22\x33" \
                     "\x00\x00\x00\x00\x00\x00\x70\x56" \
                     "\xc6\x90\x20\xe7\x7b\x01\x00\x00" \
                     "\x88\x00\x01\x00\x00\x0e\x6c\x69" \
                     "\x62\x77\x69\x66\x69\x2d\x62\x65" \
                     "\x61\x63\x6f\x6e\x03\x01\x0b"

int main(void) {
    float times[12] = {0};

    for (int i = 0; i < 12; i++) {
        float startTime = (float)clock() / CLOCKS_PER_SEC;

        struct libwifi_frame frame;
        struct libwifi_bss bss;
        libwifi_get_wifi_frame(&frame, (const unsigned char *)BEACON_FRAME, 56, 0);
        libwifi_parse_beacon(&bss, &frame);

        float endTime = (float) clock() / CLOCKS_PER_SEC;
        times[i] = (endTime - startTime);

        libwifi_free_bss(&bss);
        libwifi_free_wifi_frame(&frame);
    }

    for (int i = 0; i < 12; i++) {
        printf("Run %d:\t%9.7f Seconds\n", i+1, times[i]);
    }
}

