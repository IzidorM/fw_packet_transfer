/*
 * SPDX-FileCopyrightText: 2023 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <inttypes.h>
#include <stdbool.h>
//#include <stdio.h>
#include <string.h>

#include "pt.h"
#include "pt_extended.h"
#include "pt_internal.h"

#include "bsd_checksum.h"

#include "byte_fifo.h"

#ifdef STATIC
#error "STATIC declared outside of the .c file"
#endif

#ifdef UNIT_TESTS
#define STATIC
#else
#define STATIC static
#endif

/* 
 * extended packets
 ** TX
 *** packets
1-> start packet
[header (extended type=start), 
full payload size (4bytes),
payload extended packet payload size (4bytes),
bsd_cs]

2-> payload packet
[header (extended type=payload),
packet number (2bytes),
payload bsd cs 2bytes]
header bsd_cs (1bytes),
payload (Nbytes),

3-> last packet
[header (extended type=last),
payload checksum (2bytes),
header bsd_cs (1bytes),
payload (Nbytes)]

*** state machine 

**** normal transfer

To accomplish the transfer of the payload, first the start packet is
sent, following the payload packets with last packet finishing the
transfer of the payload. The speed of sending the packets out is
defined by lower network layer. 

**** packet lost/corrupted case

If there is an error detected by the receiver, the receiver will send
back the response packet with nack flag set and the last successfull
received packet number. The sender should stop sending out packets,
wait for the connection idle time to pass and the start sending out
from the last successfully received packet number. 

***** special case 1: start packet lost/corrupted or receiver receives garbage

If the start packet is damaged/lost or the receiver will receive some
garbage, the receiver will replay with the response packet with nack
flag and the packet number 0. When the sender receives this response,
it should stop transmitting for 2x connection idle time.

***** special case 2: stop packet received before all payload packets

If receiver will receive the last packet before all the payload packts
are received, it will discharge it and send back the response packet
with nack and the last received block number. The sender response
should be the same as in special case 1.

***** special case 3: last packet lost or last few packets lost

If the receiver stops receiving packets for connection idle time after
the reception of start packet and before the last packet is received,
it will send out the response packet with nack and last successfully
received block number. In this cast sender doesnt need to wait for the
idle time.


*/
#ifdef PT_EXTENDED_PACKET_SUPPORT

STATIC void pt_ext_write_uint32_to_fifo(struct pt *p, uint32_t data)
{
	uint8_t *d = (uint8_t *) &data;
	byte_fifo_write(p->tx_fifo, d[0]);
	byte_fifo_write(p->tx_fifo, d[1]);
	byte_fifo_write(p->tx_fifo, d[2]);
	byte_fifo_write(p->tx_fifo, d[3]);
}

STATIC void pt_ext_write_uint16_to_fifo(struct pt *p, uint16_t data)
{
	uint8_t *d = (uint8_t *) &data;
	byte_fifo_write(p->tx_fifo, d[0]);
	byte_fifo_write(p->tx_fifo, d[1]);
}


STATIC uint32_t pt_ext_read_uint32_from_fifo(struct pt *p)
{
	uint32_t data = 0;
	uint8_t *d = (uint8_t *) &data;

	d[0] = byte_fifo_read(p->rx_fifo);
	d[1] = byte_fifo_read(p->rx_fifo);
	d[2] = byte_fifo_read(p->rx_fifo);
	d[3] = byte_fifo_read(p->rx_fifo);

	return data;
}

STATIC uint16_t pt_ext_read_uint16_from_fifo(struct pt *p)
{
	uint16_t data = 0;
	uint8_t *d = (uint8_t *) &data;

	d[0] = byte_fifo_read(p->rx_fifo);
	d[1] = byte_fifo_read(p->rx_fifo);

	return data;
}


STATIC size_t pt_ext_get_packet_payload_size(struct pt *p)
{
	size_t data_left_to_send = p->pt_ext_tx.data_size 
		- p->pt_ext_tx.data_already_sent;

	if (data_left_to_send > p->max_packet_payload_size)
	{
		return p->max_packet_payload_size;
	}
	else
	{
		return data_left_to_send;
	}
}

STATIC enum pt_errors pt_extended_send_start_packet(struct pt *p)
{
	// calculate the size of the packet and 
	// check if there is enough space in the fifo
	// start packet max size

	size_t start_packet_payload_size = 
		pt_ext_get_packet_payload_size(p);

	size_t full_packet_size = start_packet_payload_size 
		+ sizeof(struct pt_extended_start_packet_header);

	if (byte_fifo_get_free_space(p->tx_fifo) < full_packet_size)
	{
		return PT_ERROR_BUSY;
	}

	struct pt_extended_start_packet_header h;
        h.header = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXT_PACKAGE_TYPE_START << PT_EXT_TYPE_POS);

	h.header_bsd8_cs = bsd_checksum8_from(0, &h.header, 1);
	byte_fifo_write(p->tx_fifo, h.header);

	h.packet_payload_max_size = p->max_packet_payload_size;
	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		&h.packet_payload_max_size, 1);
	byte_fifo_write(p->tx_fifo, h.packet_payload_max_size);

	h.start_packet_payload_cs = bsd_checksum16(
		p->pt_ext_tx.data, start_packet_payload_size);
	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.start_packet_payload_cs, 2);
		
	pt_ext_write_uint16_to_fifo(p, h.start_packet_payload_cs);


	h.full_payload_size = (uint32_t) p->pt_ext_tx.data_size;
	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.full_payload_size, 4);
	pt_ext_write_uint32_to_fifo(p, h.full_payload_size);

	h.full_payload_cs = bsd_checksum16(p->pt_ext_tx.data, 
					   p->pt_ext_tx.data_size);
	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.full_payload_cs, 4);
	pt_ext_write_uint32_to_fifo(p, h.full_payload_cs);

	byte_fifo_write(p->tx_fifo, h.header_bsd8_cs);

	for (uint32_t i = 0; start_packet_payload_size > i; i++)
	{
		byte_fifo_write(p->tx_fifo, p->pt_ext_tx.data[i]);
	}

	return PT_NO_ERROR;
}


STATIC enum pt_errors pt_extended_send_next_payload_packet(struct pt *p)
{
	// calculate the size of the packet and 
	// check if there is enough space in the fifo
	// start packet max size
	// NOTE: struct pt_extended_payload_packet_header size is not packed!

	size_t packet_payload_size = 
		pt_ext_get_packet_payload_size(p);

	size_t full_packet_size = packet_payload_size 
		+ sizeof(struct pt_extended_payload_packet_header);

	if (byte_fifo_get_free_space(p->tx_fifo) < full_packet_size)
	{
		return PT_ERROR_BUSY;
	}

	struct pt_extended_payload_packet_header h = {
		.header = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXT_PACKAGE_TYPE_PAYLOAD),
		.packet_number = (uint16_t) (p->pt_ext_tx.data_already_sent
					     / p->max_packet_payload_size),
		.payload_cs = bsd_checksum16(
			p->pt_ext_tx.data + p->pt_ext_tx.data_already_sent,
			packet_payload_size),
		.header_bsd8_cs = 0,
	};


	h.header_bsd8_cs = bsd_checksum8_from(0, &h.header, 1);
	byte_fifo_write(p->tx_fifo, h.header);

	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.packet_number, 2);
	pt_ext_write_uint16_to_fifo(p, h.packet_number);

	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.payload_cs, 2);
	pt_ext_write_uint16_to_fifo(p, h.payload_cs);

	byte_fifo_write(p->tx_fifo, h.header_bsd8_cs);

	for (uint32_t i = 0; packet_payload_size > i; i++)
	{
		byte_fifo_write(p->tx_fifo, 
				p->pt_ext_tx.data[p->pt_ext_tx.data_already_sent + i]);
	}

	p->pt_ext_tx.data_already_sent += packet_payload_size;

	return PT_NO_ERROR;
}



// NOTE: caller must hold data valid until the callback is called
enum pt_errors 
pt_extended_send(struct pt *p, 
		 uint8_t *data, 
		 size_t data_size,
		 void (*done_callback)(enum pt_ext_tx_rsp_status))
{
	// NOTE: Check the state of tx_state if it is busy...
	if (PT_EXT_TX_STATE_IDLE != p->pt_ext_tx.tx_state)
	{
		return PT_ERROR_BUSY;
	}
		
	if (NULL == data || 0 == data_size)
	{
		return PT_ERROR_ARGS;
	}

	p->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	p->pt_ext_tx.data = data;
	p->pt_ext_tx.data_size = data_size;	
	p->pt_ext_tx.tx_done_callback = done_callback;

	return PT_NO_ERROR;
}

STATIC void pt_ext_move_tx_state(struct pt *p, 
				 enum pt_ext_tx_state new_state)
{
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;
	pd->tx_state = new_state;
	pd->time_passed_in_state_ms = 0;
}

void pt_extended_tx_run(struct pt *p, uint32_t time_from_last_call_ms)
{
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;
	pd->time_passed_in_state_ms += time_from_last_call_ms;

	if (PT_EXT_TX_STATE_IDLE == pd->tx_state)
	{
		// dont do anything :)
	}
	else if (PT_EXT_TX_STATE_SEND_START_PACKET == pd->tx_state)
	{
		enum pt_errors r = 
			pt_extended_send_start_packet(p);

		if (PT_NO_ERROR == r)
		{
			pt_ext_move_tx_state(
				p, 
				PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET);
		}
		else
		{
			// add to timeout

		}
	}
	else if (PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET == pd->tx_state)
	{
		// send payload packet
		
		enum pt_errors r = 
			pt_extended_send_next_payload_packet(p);

		if (PT_NO_ERROR == r)
		{
			if (pd->data_already_sent == pd->data_size)
			{
				pt_ext_move_tx_state(
					p,
					PT_EXT_TX_STATE_WAIT_RSP);
			}

		}
		else
		{

		}
	}
	else if (PT_EXT_TX_STATE_WAIT_RSP == pd->tx_state)
	{
		// wait for response, which will be handled in rx task
		// if timeout happens 
		if (pd->time_passed_in_state_ms > p->timeout_rx_ms)
		{
			pd->tx_done_callback(PT_EXT_TX_TIMEOUT);

			pt_ext_move_tx_state(
				p,
				PT_EXT_TX_STATE_IDLE);
		}
	}
	else
	{
		// should never be here :)
		// TODO: Add assert
		//ASSERT_FAIL();
	}
}

// RX implementation

void pt_extended_receiver_reset(struct pt *p)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	pe_rx->current_packet_payload_rx_cnt = 0;
	pe_rx->last_received_packet_number = 0;
}

STATIC void pt_extended_receiver_prepare_for_new_packet(struct pt *p)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	pe_rx->current_packet_payload_rx_cnt = 0;
}

STATIC int32_t pt_extended_receive_packets_payload(struct pt *p, bool *packet_done)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;

	size_t packet_payload_expected_size = 
		pe_rx->full_payload_size 
		- pe_rx->full_payload_buffer_fill_index;

	if (packet_payload_expected_size > pe_rx->full_payload_size)
	{
		packet_payload_expected_size = pe_rx->full_payload_size;
	}

	while(!byte_fifo_is_empty(p->rx_fifo))
	{
		// TODO: Save to buffer
		uint8_t b = byte_fifo_read(p->rx_fifo);

		pe_rx->payload_buffer[pe_rx->current_packet_payload_rx_cnt] = b;
		pe_rx->current_packet_payload_rx_cnt += 1;

		if (pe_rx->current_packet_payload_rx_cnt >= packet_payload_expected_size)
		{
			// packet received
			//check packet checksum
			uint16_t full_payload_cs = 
				bsd_checksum16(
					pe_rx->payload_buffer,
					pe_rx->current_packet_payload_rx_cnt);

			if (pe_rx->full_payload_cs == full_payload_cs)
			{
				// packet received successfully
				*packet_done = true;
				pe_rx->rx_state = PT_EXT_RX_WAITING_PACKET_HEADER;
				pe_rx->last_received_packet_number += 1;

				// TODO: Add paylaod to the full packet buffer
				pe_rx->full_payload_buffer_fill_index += 
					pe_rx->current_packet_payload_rx_cnt;

				// is the full packet transfer done?
				if (pe_rx->full_payload_buffer_fill_index 
				    >= pe_rx->full_payload_size)
				{
					// full packet received
					// call the callback
					if (pe_rx->full_packet_received_cb)
					{
						pe_rx->full_packet_received_cb(
							pe_rx->full_payload_buffer, 
							pe_rx->full_payload_size);
					}
				}


				return PT_NO_ERROR;
			}
			else
			{
				// TODO: Add error handling
				// packet checksum error
				return PT_ERROR_CHECKSUM_FAILED;
			}
		}
	}

	return PT_NO_ERROR;
}

STATIC uint32_t 
pt_extended_receiver_start_packet(struct pt *p, 
				  uint32_t time_from_last_call_ms,
				  bool *packet_done)
{
	(void) time_from_last_call_ms;

	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;

	if (PT_EXT_RX_WAITING_PACKET_HEADER == pe_rx->rx_state)
	{
		// first use the payload buffer to store the header
		pe_rx->payload_buffer[pe_rx->current_packet_payload_rx_cnt] = 
			byte_fifo_read(p->rx_fifo);

		pe_rx->current_packet_payload_rx_cnt += 1;

		if (pe_rx->current_packet_payload_rx_cnt
		    >= (PT_EXT_START_PACKET_HEADER_SIZE-1))
		{
			// every start packet resets the state of the receiver
			pt_extended_receiver_reset(p);

			// we have enough data to read the header
			uint8_t header_cs = 0;
			header_cs = bsd_checksum8_from(
				header_cs, &pe_rx->header, 1);

			pe_rx->packet_payload_max_size = 
				pe_rx->payload_buffer[0];

			header_cs = bsd_checksum8_from(
				header_cs, 
				&pe_rx->packet_payload_max_size, 1);

			pe_rx->current_packet_payload_cs = 
				pe_rx->payload_buffer[1] 
				| pe_rx->payload_buffer[2] << 8;

			header_cs = bsd_checksum8_from(
				header_cs, 
				(uint8_t *) &pe_rx->current_packet_payload_cs,
				2);

			pe_rx->full_payload_size= 
				pe_rx->payload_buffer[3]
				| pe_rx->payload_buffer[4] << 8
				| pe_rx->payload_buffer[5] << 16
				| pe_rx->payload_buffer[6] << 24;

			header_cs = bsd_checksum8_from(
				header_cs, 
				(uint8_t *) &pe_rx->full_payload_size,
				4);

			pe_rx->full_payload_cs= 
				pe_rx->payload_buffer[7]
				| pe_rx->payload_buffer[8] << 8
				| pe_rx->payload_buffer[9] << 16
				| pe_rx->payload_buffer[10] << 24;

			header_cs = bsd_checksum8_from(
				header_cs, 
				(uint8_t *) &pe_rx->full_payload_cs,
				4);

			uint8_t expected_header_cs = 
				pe_rx->payload_buffer[11];

			pe_rx->current_packet_payload_rx_cnt = 0;

			if (header_cs != expected_header_cs)
			{
				//header checksum error
				return PT_ERROR_CHECKSUM_FAILED;
			}


			pe_rx->rx_state = 
				PT_EXT_RX_WAITING_PACKET_PAYLOAD;
		}
	}
	else if (PT_EXT_RX_WAITING_PACKET_PAYLOAD == pe_rx->rx_state)
	{
		return pt_extended_receive_packets_payload(
			p, packet_done);
	}
	else
	{
		return PT_ERROR_IMPLEMENTATION;
	}

	return PT_NO_ERROR;
}

STATIC uint32_t 
pt_extended_receiver_payload_packet(struct pt *p, 
				  uint32_t time_from_last_call_ms,
				  bool *packet_done)
{
	(void) p;
	(void) time_from_last_call_ms;

	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;

	if (PT_EXT_RX_WAITING_PACKET_HEADER == pe_rx->rx_state)
	{
		pe_rx->payload_buffer[pe_rx->current_packet_payload_rx_cnt] = 
			byte_fifo_read(p->rx_fifo);

		pe_rx->current_packet_payload_rx_cnt += 1;
		
		if (pe_rx->current_packet_payload_rx_cnt
		    >= (PT_EXT_START_PACKET_HEADER_SIZE-1))
		{
			// we have enough data to read the header
			uint8_t header_cs = 0;
			header_cs = bsd_checksum8_from(
				header_cs, &pe_rx->header, 1);

			uint16_t packet_number = 
				pe_rx->payload_buffer[0] 
				| pe_rx->payload_buffer[1] << 8;

			header_cs = bsd_checksum8_from(
				header_cs, 
				(uint8_t *) &packet_number,
				2);

			pe_rx->current_packet_payload_cs = 
				pe_rx->payload_buffer[2] 
				| pe_rx->payload_buffer[3] << 8;


			header_cs = bsd_checksum8_from(
				header_cs, 
				(uint8_t *) &packet_number,
				2);

			uint8_t expected_header_cs = 
				pe_rx->payload_buffer[4];

			if (header_cs != expected_header_cs)
			{
				//header checksum error
				return PT_ERROR_CHECKSUM_FAILED;
			}

			if (pe_rx->last_received_packet_number != packet_number)
			{
				// packet number error
				return PT_ERROR_PACKET_NUMBER_FAILED;
			}

			pe_rx->rx_state = 
				PT_EXT_RX_WAITING_PACKET_PAYLOAD;
		}
	}
	else if (PT_EXT_RX_WAITING_PACKET_PAYLOAD == pe_rx->rx_state)
	{
		return pt_extended_receive_packets_payload(p, 
							   packet_done);
	}

	return PT_NO_ERROR;
}

STATIC uint32_t 
pt_extended_receiver_response_packet(struct pt *p, 
				  uint32_t time_from_last_call_ms,
				  bool *packet_done)
{
	(void) p;
	(void) time_from_last_call_ms;
	(void) packet_done;

	return PT_NO_ERROR;
}

void pt_extended_rx_header(struct pt *p, uint8_t header)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;

	pt_extended_receiver_prepare_for_new_packet(p);

	pe_rx->header = header;

	pe_rx->ext_packet_type = (header >> PT_EXT_TYPE_POS) 
		& PT_EXT_TYPE_MASK;

	if (PT_EXT_PACKAGE_TYPE_START == pe_rx->ext_packet_type)
	{
		pe_rx->pt_extended_receive_packet = 
			pt_extended_receiver_start_packet;
	}
	else if (PT_EXT_PACKAGE_TYPE_PAYLOAD == pe_rx->ext_packet_type)
	{
		pe_rx->pt_extended_receive_packet = 
			pt_extended_receiver_payload_packet;
	}
	else if (PT_EXT_PACKAGE_TYPE_RESPONSE == pe_rx->ext_packet_type)
	{
		pe_rx->pt_extended_receive_packet = 
			pt_extended_receiver_response_packet;
	}
	else
	{
		// TODO: Add assert
		return;
	}
}

void pt_extended_register_packet_received_callback(struct pt *p, void (*cb)(uint8_t *data, size_t data_size))
{
	p->pt_ext_rx.full_packet_received_cb = cb;
}


#endif