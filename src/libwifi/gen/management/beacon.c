/* Copyright 2021 The libwifi Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "beacon.h"
#include "../../core/frame/tag.h"
#include "../../core/frame/tag_iterator.h"
#include "../../core/misc/byteswap.h"
#include "../../core/misc/epoch.h"
#include "common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/**
 * The length of a beacon frame is the sum of the header length, the fixed parameters length, and the tagged
 * parameters length.
 */
size_t libwifi_get_beacon_length(struct libwifi_beacon *beacon) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_beacon_fixed_parameters) + beacon->tags.length;
}

/**
 * Simple helper to set the beacon SSID tag by removing it and then adding it back with the new value.
 */
void libwifi_set_beacon_ssid(struct libwifi_beacon *beacon, const char *ssid) {
    if (beacon->tags.length != 0) {
        libwifi_remove_tag(&beacon->tags, TAG_SSID);
    }

    libwifi_quick_add_tag(&beacon->tags, TAG_SSID, (void *) ssid, strlen(ssid));
}

/**
 * Simple helper to set the beacon DS tag by removing it and then adding it back with the new value.
 */
void libwifi_set_beacon_channel(struct libwifi_beacon *beacon, uint8_t channel) {
    if (beacon->tags.length != 0) {
        libwifi_remove_tag(&beacon->tags, TAG_DS_PARAMETER);
    }

    const unsigned char *chan = (const unsigned char *) &channel;

    libwifi_quick_add_tag(&beacon->tags, TAG_DS_PARAMETER, chan, 1);
}

/**
 * The generated beacon frame is made with sane defaults defined in common.h.
 * Three tagged parameters are also added to the beacon: SSID, Channel and Supported Rates.
 */
void libwifi_create_beacon(struct libwifi_beacon *beacon, const unsigned char receiver[6],
                           const unsigned char transmitter[6], const char *ssid, uint8_t channel) {
    memset(beacon, 0, sizeof(struct libwifi_beacon));

    beacon->frame_header.frame_control.type = TYPE_MANAGEMENT;
    beacon->frame_header.frame_control.subtype = SUBTYPE_BEACON;
    memcpy(&beacon->frame_header.addr1, receiver, 6);
    memcpy(&beacon->frame_header.addr2, transmitter, 6);
    beacon->frame_header.seq_control.sequence_number = (rand() % 4096);

    beacon->fixed_parameters.timestamp = BYTESWAP64(libwifi_get_epoch());
    beacon->fixed_parameters.beacon_interval = BYTESWAP16(LIBWIFI_DEFAULT_BEACON_INTERVAL);
    beacon->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);

    libwifi_set_beacon_ssid(beacon, ssid);
    libwifi_set_beacon_channel(beacon, channel);

    const unsigned char supported_rates[] = LIBWIFI_DEFAULT_SUPP_RATES;
    libwifi_quick_add_tag(&beacon->tags, TAG_SUPP_RATES, supported_rates, sizeof(supported_rates) - 1);
}

/**
 * Copy a libwifi_beacon into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_beacon(struct libwifi_beacon *beacon, unsigned char *buf, size_t buf_len) {
    size_t beacon_len = libwifi_get_beacon_length(beacon);
    if (beacon_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &beacon->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &beacon->fixed_parameters, sizeof(struct libwifi_beacon_fixed_parameters));
    offset += sizeof(struct libwifi_beacon_fixed_parameters);

    memcpy(buf + offset, beacon->tags.parameters, beacon->tags.length);
    offset += beacon->tags.length;

    return beacon_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_beacon(struct libwifi_beacon *beacon) {
    free(beacon->tags.parameters);
}
