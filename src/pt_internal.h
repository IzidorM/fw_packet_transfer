/*
 * SPDX-FileCopyrightText: 2024 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PT_INTERNAL_H
#define PT_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "pt_pico.h"

#ifdef PT_EXTENDED_PACKET_SUPPORT
#include "pt_extended.h"
#endif

enum pt_receive_state {
        PT_RX_WAITING_FIRST_BYTE,
        PT_RX_RECEIVING_PICO_PACKET,
        PT_RX_RECEIVING_EXTENDED_PACKET,
        PT_DROP_DATA_UNTIL_TIMEOUT,
};

struct pt {
	struct byte_fifo *tx_fifo;
	struct byte_fifo *rx_fifo;

        uint16_t timeout_rx_ms;
        uint16_t timeout_rsp_tx_ms;
        uint32_t time_from_last_tx_packet_ms;
        uint32_t time_from_last_rx_packet_ms;

        enum pt_receive_state pt_receive_state;
	struct pt_pico_receiver_data pico_rx_data;

#ifdef PT_EXTENDED_PACKET_SUPPORT

#endif
};

#endif
