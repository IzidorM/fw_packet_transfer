/*
 * SPDX-FileCopyrightText: 2024 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PT_H
#define PT_H

#include <inttypes.h>
#include <stdbool.h>

enum pt_errors {
        PT_NO_ERROR = 0,
        PT_ERROR_IMPLEMENTATION = -1,
        PT_ERROR_ARGS = -2,
        PT_ERROR_GENERIC = -3,
        PT_ERROR_TO_MANY_RETRIES = -4,
        PT_ERROR_TIMEOUT = -5,
        PT_ERROR_BUSY = -6,
	PT_ERROR_CHECKSUM_FAILED = -7,
	PT_ERROR_PACKET_NUMBER_FAILED = -8,
	PT_ERROR_UNKNOWN_PACKET_TYPE = -9,
	PT_ERROR_OUT_OF_MEMORY = -10,
};

struct pt_settings {
        void *(*malloc)(size_t);

	struct byte_fifo *tx_fifo;
	struct byte_fifo *rx_fifo;

        uint16_t rx_timeout_ms;

#ifdef PT_EXTENDED_PACKET_SUPPORT
        uint8_t tx_retries;
        uint16_t tx_rsp_timeout_ms;
	uint8_t *(*request_memory)(size_t data_size);
#endif

};

struct pt;

struct pt *pt_init(struct pt_settings *s);

enum pt_errors pt_receiver_run(struct pt *p, 
			       uint32_t time_from_last_call_ms);

int32_t pt_pico_send(struct pt *p, uint8_t *data, size_t data_size);

void pt_pico_register_rx_callback(
	struct pt *p,
	void *high_layer_data, 
	void (*high_layer_callback)(void *, uint8_t *, size_t));

#endif
