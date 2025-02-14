/*
 * SPDX-FileCopyrightText: 2024 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BSD_CHECKSUM_H
#define BSD_CHECKSUM_H

uint8_t bsd_checksum8(uint8_t *data, size_t data_size);
uint16_t bsd_checksum16(uint8_t *data, size_t data_size);
uint8_t bsd_checksum8_from(uint8_t start_checksum, uint8_t *data, size_t data_size);

#endif
