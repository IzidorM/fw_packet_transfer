/*
 * SPDX-FileCopyrightText: 2024 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

uint8_t bsd_checksum8_from(uint8_t start_checksum, uint8_t *data, size_t data_size)
{
        uint8_t checksum = start_checksum;
        uint32_t i;
        for (i = 0; data_size > i; i++)
        {
                checksum = (uint8_t) ((checksum >> 1) + ((checksum & 0x1) << 7));
                checksum = checksum + data[i];
        }
        return checksum;
}

uint8_t bsd_checksum8(uint8_t *data, size_t data_size)
{
        return bsd_checksum8_from(0, data, data_size);
}

uint16_t bsd_checksum16(uint8_t *data, size_t data_size)
{
        uint16_t checksum = 0;
        uint32_t i;
        for (i = 0; data_size > i; i++)
        {
                checksum = (uint16_t )((checksum >> 1) + ((checksum & 1) << 15));
                checksum += data[i];
        }
        return checksum;
}
