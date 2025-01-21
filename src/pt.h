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
        PT_ERROR_ARGS = -1,
        PT_ERROR_GENERIC = -2,
        PT_ERROR_TO_MANY_RETRIES = -3,
        PT_ERROR_TIMEOUT = -4,
        PT_ERROR_BUSY = -5,
	PT_ERROR_CHECKSUM_FAILED = -6,
};

#ifdef PT_EXTENDED_PACKET_SUPPORT

struct pt_extended_settings {
        uint8_t *full_data_buff;
        uint32_t full_data_buff_size;
        int32_t (*rx_callback)(uint8_t *data, size_t data_size);
        uint8_t max_rx_payload_size_per_packet;

        //void (*tx_done_callback)(enum pt_micro_full_packet_status);
};
#endif

struct pt_settings {
        void *(*malloc)(size_t);

	struct byte_fifo *tx_fifo;
	struct byte_fifo *rx_fifo;

        uint8_t tx_retries;
        uint16_t tx_rsp_timeout_ms;
        uint16_t rx_timeout_ms;
};

struct pt;

struct pt *pt_init(struct pt_settings *s);
void pt_receiver_run(struct pt *p, uint32_t time_from_last_call_ms);

int32_t pt_pico_send(struct pt *p, uint8_t *data, size_t data_size);

void pt_pico_register_rx_callback(
	struct pt *p,
	void *high_layer_data, 
	void (*high_layer_callback)(void *, uint8_t *, size_t));
	

#ifdef PT_DEBUG
#include <stdarg.h>
void pt_debug(const char *format, ...);
#else
#include "debug_io.h"
#define  pt_debug dmsg
#endif

#endif
