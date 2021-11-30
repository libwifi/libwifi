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

#include "tag.h"
#include "tag_iterator.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int libwifi_add_tag(struct libwifi_tagged_parameters *tags, struct libwifi_tagged_parameter *tag) {
    // Calculate the total length of the new tag
    size_t parameter_len = sizeof(struct libwifi_tag_header) + tag->header.tag_len;

    // Initalise the supplied tagged parameters list, if not already done.
    // Otherwise, extend the allocation to fit the new tag.
    if (tags->length == 0) {
        tags->parameters = malloc(parameter_len);
        if (tags->parameters == NULL) {
            return -ENOMEM;
        }
    } else {
        void *buf = realloc(tags->parameters, tags->length + parameter_len);
        if (buf == NULL) {
            return -ENOMEM;
        }
        tags->parameters = buf;
    }

    // Append the new tag to the list
    memcpy(tags->parameters + tags->length, &tag->header, sizeof(struct libwifi_tag_header));
    memcpy(tags->parameters + tags->length + sizeof(struct libwifi_tag_header), tag->body,
           tag->header.tag_len);

    // Update total tagged parameters length
    tags->length += parameter_len;

    return 0;
}

int libwifi_remove_tag(struct libwifi_tagged_parameters *tags, int tag_number) {
    // Initalise a tag iterator
    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, tags->parameters, tags->length) != 0) {
        return -EINVAL;
    }

    // Loop through the tagged parameters list until landing on the supplied tag number
    do {
        if (it.tag_header->tag_num == tag_number) {
            // Calculate the length of the tag we're removing, so that we know
            // how many bytes to shrink the tagged parameter list by
            size_t copy_len = tags->length -
                              (it.tag_data - tags->parameters) -
                              (it.tag_header->tag_len + sizeof(struct libwifi_tag_header));
            memcpy(tags->parameters, it.tag_data + it.tag_header->tag_len, copy_len);
            size_t new_len = tags->length - it.tag_header->tag_len - sizeof(struct libwifi_tag_header);
            tags->parameters = realloc(tags->parameters, new_len);
            tags->length = new_len;
            break;
        }
    } while (libwifi_tag_iterator_next(&it) != -1);

    return 0;
}

size_t libwifi_create_tag(struct libwifi_tagged_parameter *tagged_parameter, int tag_number,
                          const unsigned char *tag_data, size_t tag_length) {
    // Initalise the supplied tagged parameter struct
    memset(tagged_parameter, 0, sizeof(struct libwifi_tagged_parameter));
    tagged_parameter->header.tag_len = tag_length;
    tagged_parameter->header.tag_num = tag_number;
    tagged_parameter->body = malloc(tag_length);
    if (tagged_parameter->body == NULL) {
        return -ENOMEM;
    }
    memset(tagged_parameter->body, 0, tag_length);

    // Copy the supplied data into the new tag body
    memcpy(tagged_parameter->body, tag_data, tag_length);

    return sizeof(struct libwifi_tag_header) + tag_length;
}

void libwifi_free_tag(struct libwifi_tagged_parameter *tagged_parameter) {
    free(tagged_parameter->body);
}

size_t libwifi_dump_tag(struct libwifi_tagged_parameter *tag, unsigned char *buf, size_t buf_len) {
    if (tag->header.tag_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;

    memcpy(buf, &tag->header, sizeof(struct libwifi_tag_header));
    offset += sizeof(struct libwifi_tag_header);
    memcpy(buf + offset, tag->body, tag->header.tag_len);
    offset += tag->header.tag_len;

    return sizeof(struct libwifi_tag_header) + tag->header.tag_len;
}

int libwifi_quick_add_tag(struct libwifi_tagged_parameters *tags, int tag_number,
                          const unsigned char *tag_data, size_t tag_length) {
    struct libwifi_tagged_parameter tagged_parameter = {0};

    size_t ret = libwifi_create_tag(&tagged_parameter, tag_number, tag_data, tag_length);
    if (ret <= 0) {
        return ret;
    }

    libwifi_add_tag(tags, &tagged_parameter);
    libwifi_free_tag(&tagged_parameter);

    return 0;
}
