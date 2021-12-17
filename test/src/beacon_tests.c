#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_beacon_gen_full() {
    struct libwifi_beacon beacon = {0};

    int ret = libwifi_create_beacon(&beacon, bcast, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create beacon: %s\n", strerror(ret));
        return ret;
    }

    int beacon_len = libwifi_get_beacon_length(&beacon);
    if (beacon_len <= 0) {
        fprintf(stderr, "Invalid beacon length: %d\n", beacon_len);
        return beacon_len;
    }

    unsigned char *buf = malloc(beacon_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_beacon(&beacon, buf, beacon_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump beacon\n");
        return ret;
    }

    return 0;
}

int test_beacon_add_tag() {
    struct libwifi_beacon beacon = {0};

    int ret = libwifi_create_beacon(&beacon, bcast, to, "Some SSID", 11);
    if (ret != 0) {
        fprintf(stderr, "Failed to create beacon: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_quick_add_tag(&beacon.tags, TAG_VENDOR_SPECIFIC, (const unsigned char *) "\x00\x11\x22\xAAHello World", 15);
    if (ret != 0) {
        fprintf(stderr, "Failed to add beacon tagged parameter: %s\n", strerror(ret));
        return ret;
    }

    int beacon_len = libwifi_get_beacon_length(&beacon);
    if (beacon_len <= 0) {
        fprintf(stderr, "Invalid beacon length: %d\n", beacon_len);
        return beacon_len;
    }

    unsigned char *buf = malloc(beacon_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_beacon(&beacon, buf, beacon_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump beacon\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--beacon-gen-full") == 0) {
        return test_beacon_gen_full();
    } else if (strcmp(argv[1], "--beacon-gen-tags") == 0) {
        return test_beacon_add_tag();
    }

    return -1;
}
