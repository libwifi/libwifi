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

#include "probe_response.h"
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
 * The length of a probe response frame is the sum of the header length, the fixed parameters length, and the
 * tagged parameters length.
 */
size_t libwifi_get_probe_resp_length(struct libwifi_probe_resp *probe_resp) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_probe_resp_fixed_parameters) + probe_resp->tags.length;
}

/**
 * Simple helper to set the probe response SSID tag by removing it and then adding it back with the new value.
 */
void libwifi_set_probe_resp_ssid(struct libwifi_probe_resp *probe_resp, const char *ssid) {
    if (probe_resp->tags.length != 0) {
        libwifi_remove_tag(&probe_resp->tags, TAG_SSID);
    }

    libwifi_quick_add_tag(&probe_resp->tags, TAG_SSID, (void *) ssid, strlen(ssid));
}

/**
 * Simple helper to set the probe response DS tag by removing it and then adding it back with the new value.
 */
void libwifi_set_probe_resp_channel(struct libwifi_probe_resp *probe_resp, uint8_t channel) {
    if (probe_resp->tags.length != 0) {
        libwifi_remove_tag(&probe_resp->tags, TAG_DS_PARAMETER);
    }

    const unsigned char *chan = (const unsigned char *) &channel;

    libwifi_quick_add_tag(&probe_resp->tags, TAG_DS_PARAMETER, chan, 1);
}

/**
 * The generated probe response frame is made with sane defaults defined in common.h.
 * Three tagged parameters are also added to the probe response: SSID, Channel and Supported Rates.
 */
void libwifi_create_probe_resp(struct libwifi_probe_resp *probe_resp, const unsigned char receiver[6],
                               const unsigned char transmitter[6], const char *ssid, uint8_t channel) {
    memset(probe_resp, 0, sizeof(struct libwifi_probe_resp));

    probe_resp->frame_header.frame_control.type = TYPE_MANAGEMENT;
    probe_resp->frame_header.frame_control.subtype = SUBTYPE_PROBE_RESP;
    memcpy(&probe_resp->frame_header.addr1, receiver, 6);
    memcpy(&probe_resp->frame_header.addr2, transmitter, 6);

    probe_resp->frame_header.seq_control.sequence_number = (rand() % 4096);
    probe_resp->fixed_parameters.timestamp = BYTESWAP64(libwifi_get_epoch());
    uint16_t probe_resp_interval = 50 + (rand() % 100);
    probe_resp->fixed_parameters.probe_resp_interval = BYTESWAP16(probe_resp_interval);
    probe_resp->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);

    libwifi_set_probe_resp_ssid(probe_resp, ssid);
    libwifi_set_probe_resp_channel(probe_resp, channel);

    const unsigned char supported_rates[] = LIBWIFI_DEFAULT_SUPP_RATES;
    libwifi_quick_add_tag(&probe_resp->tags, TAG_SUPP_RATES, supported_rates, sizeof(supported_rates) - 1);
}

/**
 * Copy a libwifi_probe_resp into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_probe_resp(struct libwifi_probe_resp *probe_resp, unsigned char *buf, size_t buf_len) {
    size_t probe_resp_len = libwifi_get_probe_resp_length(probe_resp);
    if (probe_resp_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &probe_resp->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &probe_resp->fixed_parameters, sizeof(struct libwifi_probe_resp_fixed_parameters));
    offset += sizeof(struct libwifi_probe_resp_fixed_parameters);

    memcpy(buf + offset, probe_resp->tags.parameters, probe_resp->tags.length);
    offset += probe_resp->tags.length;

    return probe_resp_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_probe_resp(struct libwifi_probe_resp *probe_resp) {
    free(probe_resp->tags.parameters);
}
