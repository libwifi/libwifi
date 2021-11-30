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

#ifndef LIBWIFI_GEN_REASSOCREQUEST_H
#define LIBWIFI_GEN_REASSOCREQUEST_H

#include "../../core/frame/frame.h"
#include "../../core/frame/management/common.h"
#include "../../core/frame/management/reassoc_request.h"

int libwifi_create_reassoc_req(struct libwifi_reassoc_req *reassoc_req, const unsigned char receiver[6],
                               const unsigned char transmitter[6], const unsigned char current_ap[6],
                               const char *ssid, uint8_t channel);
size_t libwifi_get_reassoc_req_length(struct libwifi_reassoc_req *reassoc_req);
size_t libwifi_dump_reassoc_req(struct libwifi_reassoc_req *reassoc_req, unsigned char *buf, size_t buf_len);
void libwifi_free_reassoc_req(struct libwifi_reassoc_req *reassoc_req);

#endif /* LIBWIFI_GEN_REASSOCREQUEST_H */
