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

#ifndef LIBWIFI_GEN_TIMINGAD_H
#define LIBWIFI_GEN_TIMINGAD_H

#include "../../core/frame/management/timing_ad.h"

int libwifi_create_timing_advert(struct libwifi_timing_advert *adv, const unsigned char destination[6],
                                  const unsigned char transmitter[6], struct libwifi_timing_advert_fields *adv_fields,
                                  const char country[3], uint16_t max_reg_power, uint8_t max_tx_power, uint8_t tx_power_used,
                                  uint8_t noise_floor);

size_t libwifi_get_timing_advert_length(struct libwifi_timing_advert *adv);

size_t libwifi_dump_timing_advert(struct libwifi_timing_advert *adv, unsigned char *buf, size_t buf_len);

void libwifi_free_timing_advert(struct libwifi_timing_advert *adv);

#endif /* LIBWIFI_GEN_TIMINGAD_H */
