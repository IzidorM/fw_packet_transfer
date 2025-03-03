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

#define PT_EXT_TYPE_POS 4
#define PT_EXT_TYPE_MASK 0x3

enum pt_extended_packet_types {
        PT_EXT_PACKAGE_TYPE_START = 1,
        PT_EXT_PACKAGE_TYPE_PAYLOAD = 2,
        PT_EXT_PACKAGE_TYPE_RESPONSE = 3,
};

#define PT_EXT_RESPONSE_PACKET_HEADER_SIZE 4
struct pt_extended_response_packet_header {
	uint8_t header;
	uint16_t last_received_packet_number;
	uint8_t bsd8_cs;
};

#define PT_EXT_START_PACKET_HEADER_SIZE 13
struct pt_extended_start_packet_header {
	uint8_t header;
	uint8_t packet_payload_max_size; // should we increase this?
	uint16_t start_packet_payload_cs;
	uint32_t full_payload_size;
	uint32_t full_payload_cs;
	uint8_t header_bsd8_cs;
};

#define PT_EXT_PAYLOAD_PACKET_HEADER_SIZE 6
struct pt_extended_payload_packet_header {
	uint8_t header;
	uint16_t packet_number;
	uint16_t payload_cs;
	uint8_t header_bsd8_cs;
};

//struct pt_extended_last_packet_header {
//	uint8_t header;
//	uint16_t payload_cs;
//	uint8_t header_bsd8_cs;
//};

#endif

#define PT_HEADER_TYPE_POS 6
#define PT_HEADER_TYPE_PICO 2
#define PT_HEADER_TYPE_EXTENDED 3

#define PT_EXT_MAX_PACKET_SIZE 240

enum pt_receive_state {
        PT_RX_WAITING_FIRST_BYTE,
        PT_RX_RECEIVING_PICO_PACKET,
        PT_RX_RECEIVING_EXTENDED_PACKET,
        PT_DROP_DATA_UNTIL_TIMEOUT,
};

enum pt_ext_tx_state {
	PT_EXT_TX_STATE_IDLE,
	PT_EXT_TX_STATE_SEND_START_PACKET,
	PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
	PT_EXT_TX_STATE_WAIT_RSP,
};

struct pt_extended_data_tx {
	uint32_t time_passed_in_state_ms;
	enum pt_ext_tx_state tx_state;
	uint8_t *data;
	size_t data_size;

	size_t data_already_sent;
	//uint32_t current_packet_number;

	void (*tx_done_callback)(enum pt_ext_tx_rsp_status status);
};


enum pt_ext_rx_state {
	//PT_EXT_RX_STATE_IDLE,
	PT_EXT_RX_WAITING_PACKET_HEADER,
	PT_EXT_RX_WAITING_PACKET_PAYLOAD,
};

struct pt_extended_data_rx {
	uint32_t time_passed_in_state_ms;

	enum pt_extended_packet_types ext_packet_type;
	enum pt_ext_rx_state rx_state;

	uint8_t packet_payload_max_size;
	uint8_t packet_payload_expected_size;

	uint16_t current_packet_payload_cs;

	uint32_t full_payload_size;
	uint32_t full_payload_cs;

	// TODO: Remove this
	uint8_t payload_buffer[PT_EXT_MAX_PACKET_SIZE];

	uint8_t header;

	uint32_t 
	(*pt_extended_receive_packet)(struct pt *p, 
				      uint32_t time_from_last_call_ms,
				      bool *packet_done);

	// TODO: Implement this
	uint8_t full_payload_buffer[4096];
	size_t full_payload_buffer_size;

	
	uint32_t last_received_packet_number;
	size_t full_payload_buffer_fill_index;

	size_t current_packet_payload_rx_cnt;

	void (*full_packet_received_cb)(uint8_t *data, size_t data_size);

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
	uint8_t max_packet_payload_size;
	struct pt_extended_data_tx pt_ext_tx;

	struct pt_extended_data_rx pt_ext_rx;
#endif

};

void pt_extended_rx_header(struct pt *p, uint8_t header);


#endif
