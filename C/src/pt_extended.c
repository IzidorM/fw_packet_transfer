/*
 * SPDX-FileCopyrightText: 2023 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "pt.h"
#include "pt_internal.h"
#include "pt_extended.h"

#include "bsd_checksum.h"

#include "byte_fifo.h"

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

STATIC uint32_t pt_ext_read_uint32_from_buff(uint8_t *buff)
{
	uint32_t data = buff[0] | (buff[1] << 8)
		| (buff[2] << 16) | (buff[3] << 24);

	return data;
}

STATIC uint16_t pt_ext_read_uint16_from_buff(uint8_t *buff)
{
	return (uint16_t) (buff[0] | buff[1] << 8);
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

STATIC void pt_ext_move_tx_state(struct pt *p, 
				 enum pt_ext_tx_state new_state)
{
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;

	pd->tx_state = new_state;
	pd->time_passed_in_state_ms = 0;
}

STATIC void pt_extended_tx_full_packet_done_cleanup(struct pt *p)
{
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;

	memset(pd, 0, sizeof(struct pt_extended_data_tx));

	// unblock the tx state
	// this is redundant, because memset already did it...
	//pt_ext_move_tx_state(
	//	p,
	//	PT_EXT_TX_STATE_IDLE);
}

STATIC void 
pt_extended_fill_start_packet_header(
	struct pt *p,
	struct pt_extended_start_packet_header *h,
	size_t start_packet_payload_size)
{
        h->header = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXT_PACKAGE_TYPE_START << PT_EXT_TYPE_POS);

	h->header_bsd8_cs = bsd_checksum8_from(0, &h->header, 1);


	h->subpacket_payload_max_size = p->max_packet_payload_size;
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		&h->subpacket_payload_max_size, 1);

	h->start_packet_payload_cs = bsd_checksum16(
		p->pt_ext_tx.data, start_packet_payload_size);
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		(uint8_t *) &h->start_packet_payload_cs, 2);

	h->full_payload_size = (uint32_t) p->pt_ext_tx.data_size;
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		(uint8_t *) &h->full_payload_size, 4);

	h->full_payload_cs = bsd_checksum16(p->pt_ext_tx.data, 
					   p->pt_ext_tx.data_size);
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		(uint8_t *) &h->full_payload_cs, 4);
}

STATIC void 
pt_extended_sent_start_packet(
	struct pt *p,
	struct pt_extended_start_packet_header *h,
	size_t start_packet_payload_size)
{
	pt_debug("Sending start packet wp: %i\n", start_packet_payload_size);
	byte_fifo_write(p->tx_fifo, h->header);
	byte_fifo_write(p->tx_fifo, h->subpacket_payload_max_size);
	pt_ext_write_uint16_to_fifo(p, h->start_packet_payload_cs);
	pt_ext_write_uint32_to_fifo(p, h->full_payload_size);
	pt_ext_write_uint32_to_fifo(p, h->full_payload_cs);
	byte_fifo_write(p->tx_fifo, h->header_bsd8_cs);

	for (uint32_t i = 0; start_packet_payload_size > i; i++)
	{
		byte_fifo_write(p->tx_fifo, p->pt_ext_tx.data[i]);
	}

	p->pt_ext_tx.data_already_sent += start_packet_payload_size;
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
		//pt_debug("*");
		return PT_ERROR_BUSY;
	}

	struct pt_extended_start_packet_header h;

	pt_extended_fill_start_packet_header(
		p, &h, start_packet_payload_size);

	pt_extended_sent_start_packet(
		p, &h, start_packet_payload_size);

	return PT_NO_ERROR;
}

STATIC void 
pt_extended_fill_payload_packet_header(
	struct pt *p,
	struct pt_extended_payload_packet_header *h,
	size_t packet_payload_size)
{
	h->header = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXT_PACKAGE_TYPE_PAYLOAD << PT_EXT_TYPE_POS);
		
	h->packet_number = (uint16_t) (p->pt_ext_tx.data_already_sent
				       / p->max_packet_payload_size);
	h->payload_cs = bsd_checksum16(
		p->pt_ext_tx.data + p->pt_ext_tx.data_already_sent,
		packet_payload_size);
	h->header_bsd8_cs = 0;

	h->header_bsd8_cs = bsd_checksum8_from(0, &h->header, 1);
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		(uint8_t *) &h->packet_number, 2);
	h->header_bsd8_cs = bsd_checksum8_from(
		h->header_bsd8_cs, 
		(uint8_t *) &h->payload_cs, 2);
}

STATIC void 
pt_extended_sent_payload_packet(
	struct pt *p,
	struct pt_extended_payload_packet_header *h,
	size_t packet_payload_size)
{

	byte_fifo_write(p->tx_fifo, h->header);
	pt_ext_write_uint16_to_fifo(p, h->packet_number);
	pt_ext_write_uint16_to_fifo(p, h->payload_cs);
	byte_fifo_write(p->tx_fifo, h->header_bsd8_cs);

	for (uint32_t i = 0; packet_payload_size > i; i++)
	{
		size_t index = p->pt_ext_tx.data_already_sent + i;
		byte_fifo_write(p->tx_fifo, 
			p->pt_ext_tx.data[index]);
	}

	p->pt_ext_tx.data_already_sent += packet_payload_size;
}

STATIC enum pt_errors 
pt_extended_send_next_payload_packet(struct pt *p)
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
		//pt_debug("*");
		return PT_ERROR_BUSY;
	}

	struct pt_extended_payload_packet_header h;
	pt_extended_fill_payload_packet_header(
		p, &h, packet_payload_size);

	pt_debug("Sending payload packet %i\n", h.packet_number);

	pt_extended_sent_payload_packet(
		p, &h, packet_payload_size);

	return PT_NO_ERROR;
}

STATIC enum pt_errors pt_extended_send_response_packet(struct pt *p)
{

	if (byte_fifo_get_free_space(p->tx_fifo) < PT_EXT_RESPONSE_PACKET_HEADER_SIZE)
	{
		return PT_ERROR_BUSY;
	}

	struct pt_extended_response_packet_header h;
        h.header = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXT_PACKAGE_TYPE_RESPONSE << PT_EXT_TYPE_POS)
		| (p->pt_ext_tx.response_flags ? PT_EXT_ACK_FLAG : 0);

	h.header_bsd8_cs = bsd_checksum8_from(0, &h.header, 1);
	byte_fifo_write(p->tx_fifo, h.header);

	h.last_received_packet_number = p->pt_ext_tx.response_packet_number;
	pt_ext_write_uint16_to_fifo(p, h.last_received_packet_number);

	h.header_bsd8_cs = bsd_checksum8_from(
		h.header_bsd8_cs, 
		(uint8_t *) &h.last_received_packet_number, 2);

	pt_debug("Sending response packet %s -> %i \n", 
		 (p->pt_ext_tx.response_flags ? "ACK" : "NACK"),
		 h.last_received_packet_number);
		
	byte_fifo_write(p->tx_fifo, h.header_bsd8_cs);

	return PT_NO_ERROR;
}


void pt_extended_tx_run(struct pt *p, uint32_t time_from_last_call_ms)
{
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;
	pd->time_passed_in_state_ms += time_from_last_call_ms;

	if (PT_EXT_TX_STATE_WAIT_IDLE_TIMEOUT == pd->tx_state)
	{
		if (pd->time_passed_in_state_ms >= p->timeout_tx_ms)
		{
			pt_debug("waited for idle timeout!");
			pd->tx_state = pd->tx_state_before_nack;
		}
		else
		{
			return;
		}
	}

	if (p->pt_ext_tx.send_response)
	{
		pt_debug("Set response flag\n");
		enum pt_errors r = 
			pt_extended_send_response_packet(p);

		if (PT_NO_ERROR == r)
		{
			p->pt_ext_tx.send_response = false;
		}
		return;
	}

	if (PT_EXT_TX_STATE_IDLE == pd->tx_state)
	{
		// dont do anything :)
		return;
	}

	if (PT_EXT_TX_STATE_SEND_START_PACKET == pd->tx_state)
	{
		enum pt_errors r = 
			pt_extended_send_start_packet(p);

		if (PT_NO_ERROR == r)
		{
			enum pt_ext_tx_state next_state = 
				PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET;

			if (pd->data_already_sent == pd->data_size)
			{
				next_state = PT_EXT_TX_STATE_WAIT_RSP;
			}

			pt_ext_move_tx_state(
				p, 
				next_state);
		}
		else
		{
			// add to timeout

		}
	}

	if (PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET == pd->tx_state)
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

	if (PT_EXT_TX_STATE_WAIT_RSP == pd->tx_state)
	{
		// wait for response, which will be handled in rx task
		// if timeout happens 
		if (pd->time_passed_in_state_ms > p->timeout_rsp_tx_ms)
		{
			pd->tx_done_callback(PT_EXT_TX_TIMEOUT);

			// TODO: ? Add retries ?
			pt_ext_move_tx_state(
				p,
				PT_EXT_TX_STATE_IDLE);
		}
	}
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

	pt_ext_move_tx_state(p, PT_EXT_TX_STATE_SEND_START_PACKET);

	p->pt_ext_tx.data = data;
	p->pt_ext_tx.data_size = data_size;	
	p->pt_ext_tx.tx_done_callback = done_callback;
	p->pt_ext_tx.data_already_sent = 0;

	return PT_NO_ERROR;
}

STATIC void pt_extended_send_response(struct pt *p, bool ack)
{
	pt_debug("request sending response\n");
	p->pt_ext_tx.response_packet_number =
		p->pt_ext_rx.last_received_packet_number ;
	p->pt_ext_tx.response_flags = ack;
	p->pt_ext_tx.send_response = true;
}

// RX implementation
void pt_extended_receiver_prepare_for_new_subpacket(struct pt *p)
{
	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&p->pt_ext_rx.subpacket_rx;

	memset(subpack_rx, 0, sizeof(struct pt_extended_data_rx_subpacket));
}

STATIC void pt_extended_rx_full_packet_done_cleanup(struct pt *p)
{
	//pt_extended_receiver_prepare_for_new_packet(p);

	struct pt_extended_data_rx *pd = &p->pt_ext_rx;

	memset(pd, 0, sizeof(struct pt_extended_data_rx));

}

STATIC int32_t 
pt_extended_receive_packets_payload_next_byte(
	struct pt *p, 
	uint8_t b,
	size_t packet_payload_expected_size,
	bool *packet_done)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&p->pt_ext_rx.subpacket_rx;

	subpack_rx->payload_buffer[subpack_rx->current_packet_payload_rx_cnt] = b;
	subpack_rx->current_packet_payload_rx_cnt += 1;

	if (subpack_rx->current_packet_payload_rx_cnt >= packet_payload_expected_size)
	{
		// packet received
		//check packet checksum
		uint16_t subpacket_payload_cs = 
			bsd_checksum16(
				subpack_rx->payload_buffer,
				subpack_rx->current_packet_payload_rx_cnt);

		if (subpack_rx->subpacket_payload_cs == subpacket_payload_cs)
		{
			// packet received successfully
			*packet_done = true;

			pt_debug("subpacket recived\n");

			subpack_rx->subpacket_rx_state = 
				PT_EXT_RX_WAITING_PACKET_HEADER;

			pe_rx->last_received_packet_number += 1;

			// adding paylaod to the full packet buffer
			if (pe_rx->full_payload_buffer)
			{
				memcpy(
					pe_rx->full_payload_buffer + 
					pe_rx->full_payload_buffer_fill_index,
					subpack_rx->payload_buffer,
					subpack_rx->current_packet_payload_rx_cnt);
			}

			pe_rx->full_payload_buffer_fill_index += 
				subpack_rx->current_packet_payload_rx_cnt;

			// is the full packet transfer done?
			if (pe_rx->full_payload_buffer_fill_index 
			    >= pe_rx->full_payload_size)
			{
				pt_debug("full payload received\n");
				// send back ack
				// TODO: check the final crc before sending ack
				pt_extended_send_response(p, 
							  true);
				// full packet received
				// call the callback
				if (p->full_packet_received_cb)
				{
					p->full_packet_received_cb(
						pe_rx->full_payload_buffer, 
						pe_rx->full_payload_size);
				}

				// reset RX
				pt_extended_rx_full_packet_done_cleanup(p);
			}

			return PT_NO_ERROR;
		}
		else
		{
			// TODO: Add error handling
			// packet checksum error
			pt_debug("E: payload checksum failed: r=%i != c=%i\n",
				 subpack_rx->subpacket_payload_cs, 
				 subpacket_payload_cs);
			return PT_ERROR_CHECKSUM_FAILED;
		}
	}
	return PT_NO_ERROR;
}

STATIC int32_t pt_extended_receive_packets_payload(struct pt *p, 
						   bool *packet_done)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;

	size_t packet_payload_expected_size = 
		pe_rx->full_payload_size 
		- pe_rx->full_payload_buffer_fill_index;

	if (packet_payload_expected_size > pe_rx->subpacket_payload_max_size)
	{
		packet_payload_expected_size = 
			pe_rx->subpacket_payload_max_size;
	}

	while(!byte_fifo_is_empty(p->rx_fifo))
	{
		// TODO: Save to buffer
		uint8_t b = byte_fifo_read(p->rx_fifo);

		int32_t r = pt_extended_receive_packets_payload_next_byte(
			p, b, packet_payload_expected_size, packet_done);

		if (PT_NO_ERROR != r || *packet_done)
		{
			return r;
		}
	}

	return PT_NO_ERROR;
}

STATIC uint8_t pt_ext_calc_header_cs(uint8_t header, uint8_t *data, size_t data_size)
{
	uint8_t header_cs = 0;
	header_cs = bsd_checksum8_from(
		header_cs, &header, 1);

	header_cs = bsd_checksum8_from(
		header_cs, data, data_size);

//	pt_debug("pt_ext_calc_header_cs bytes: ");
//	pt_debug("%02x ", header);
//	for (uint32_t i = 0; i < data_size; i++)
//	{
//		pt_debug("%02x ", data[i]);
//	}
//	pt_debug("\n");

	return header_cs;
}

STATIC uint32_t 
pt_extended_rx_start_packet(struct pt *p, 
			    uint32_t time_from_last_call_ms,
			    bool *packet_done)
{
	(void) time_from_last_call_ms;

	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	struct pt_extended_data_rx_subpacket *subpack_rx = &p->pt_ext_rx.subpacket_rx;

	if (PT_EXT_RX_WAITING_PACKET_HEADER == subpack_rx->subpacket_rx_state)
	{
		// first use the payload buffer to store the header
		subpack_rx->payload_buffer[subpack_rx->current_packet_payload_rx_cnt] = 
			byte_fifo_read(p->rx_fifo);

		subpack_rx->current_packet_payload_rx_cnt += 1;

		if (subpack_rx->current_packet_payload_rx_cnt
		    >= (PT_EXT_START_PACKET_HEADER_SIZE-1))
		{
			uint8_t actual_header_cs = pt_ext_calc_header_cs(
				subpack_rx->header, 
				subpack_rx->payload_buffer, 
				subpack_rx->current_packet_payload_rx_cnt-1);

			uint8_t expected_header_cs = 
				subpack_rx->payload_buffer[11];

			if (actual_header_cs != expected_header_cs)
			{
				//header checksum error
				return PT_ERROR_CHECKSUM_FAILED;
			}

			// parse header
			pe_rx->subpacket_payload_max_size = 
				subpack_rx->payload_buffer[0];

			subpack_rx->subpacket_payload_cs = 
				pt_ext_read_uint16_from_buff(
					&subpack_rx->payload_buffer[1]);

			pe_rx->full_payload_size = 
				pt_ext_read_uint32_from_buff(
					&subpack_rx->payload_buffer[3]);

			pe_rx->full_payload_cs = 
				pt_ext_read_uint32_from_buff(
					&subpack_rx->payload_buffer[7]);


			// ask higher layer for the buffer 
			// to store the full packet payload
			pe_rx->full_payload_buffer = 
				p->request_memory(pe_rx->full_payload_size);

			if (NULL == pe_rx->full_payload_buffer)
			{
				// out of memory
				// TODO: send back the nack :)
				return PT_ERROR_OUT_OF_MEMORY;
			}

			subpack_rx->current_packet_payload_rx_cnt = 0;

			subpack_rx->subpacket_rx_state = 
				PT_EXT_RX_WAITING_PACKET_PAYLOAD;
		}
	}
	else //(PT_EXT_RX_WAITING_PACKET_PAYLOAD == subpack_rx->subpacket_rx_state)
	{
		return pt_extended_receive_packets_payload(
			p, packet_done);
	}

	return PT_NO_ERROR;
}

STATIC uint32_t 
pt_extended_rx_payload_packet(struct pt *p, 
				  uint32_t time_from_last_call_ms,
				  bool *packet_done)
{
	(void) p;
	(void) time_from_last_call_ms;

	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	struct pt_extended_data_rx_subpacket *subpack_rx = &p->pt_ext_rx.subpacket_rx;

	if (PT_EXT_RX_WAITING_PACKET_HEADER == subpack_rx->subpacket_rx_state)
	{
		subpack_rx->payload_buffer[subpack_rx->current_packet_payload_rx_cnt] = 
			byte_fifo_read(p->rx_fifo);

		subpack_rx->current_packet_payload_rx_cnt += 1;
		
		if (subpack_rx->current_packet_payload_rx_cnt
		    >= (PT_EXT_PAYLOAD_PACKET_HEADER_SIZE-1))
		{
			// we have enough data to read the header

			uint8_t actual_header_cs = pt_ext_calc_header_cs(
				subpack_rx->header, 
				subpack_rx->payload_buffer, 
				subpack_rx->current_packet_payload_rx_cnt-1);

			uint8_t expected_header_cs = 
				subpack_rx->payload_buffer[4];

			if (actual_header_cs != expected_header_cs)
			{
				//header checksum error
				pt_debug("E: payload header cs failed\n");
				pt_extended_send_response(p, 
							  false);


				return PT_ERROR_CHECKSUM_FAILED;
			}

			uint16_t packet_number = 
				pt_ext_read_uint16_from_buff(
					&subpack_rx->payload_buffer[0]); 

			subpack_rx->subpacket_payload_cs = 
				pt_ext_read_uint16_from_buff(
					&subpack_rx->payload_buffer[2]);

			if (pe_rx->last_received_packet_number != packet_number)
			{
				// send back nack
				pt_extended_send_response(p, false);
				return PT_ERROR_PACKET_NUMBER_FAILED;
			}

			subpack_rx->current_packet_payload_rx_cnt = 0;
			subpack_rx->subpacket_rx_state = 
				PT_EXT_RX_WAITING_PACKET_PAYLOAD;
		}
	}
	else //(PT_EXT_RX_WAITING_PACKET_PAYLOAD == subpack_rx->subpacket_rx_state)
	{
		return pt_extended_receive_packets_payload(p, 
							   packet_done);
	}

	return PT_NO_ERROR;
}

STATIC void
pt_extended_rx_handle_nack(struct pt *p)
{
	struct pt_extended_data_rx *pe_rx = &p->pt_ext_rx;
	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&p->pt_ext_rx.subpacket_rx;
	
	uint16_t last_packet_number = 
		subpack_rx->payload_buffer[0] 
		| subpack_rx->payload_buffer[1] << 8;

	pt_debug("nack received: %i, %i\n", last_packet_number,
		 pe_rx->last_received_packet_number);
	if (last_packet_number > 
	    pe_rx->last_received_packet_number)
	{
		pt_debug("E: Foo nack packet due packet number to big\n");
		// TODO: What to do here?
		// we should probably reset the packet transfer
		return;
	}

	// correct the tx to go back to last valid data
	p->pt_ext_tx.data_already_sent = last_packet_number
		* p->max_packet_payload_size;

	if (last_packet_number)
	{
		p->pt_ext_tx.tx_state_before_nack = 
			p->pt_ext_tx.tx_state;
	}
	else
	{
		// if nack is for the start packet,
		// go back to state sending start after timeout
		p->pt_ext_tx.tx_state_before_nack = 
			PT_EXT_TX_STATE_SEND_START_PACKET;
	}
	pt_ext_move_tx_state(p, PT_EXT_TX_STATE_WAIT_IDLE_TIMEOUT);

}

STATIC uint32_t 
pt_extended_rx_response_packet(struct pt *p, 
				  uint32_t time_from_last_call_ms,
				  bool *packet_done)
{
	(void) time_from_last_call_ms;

	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&p->pt_ext_rx.subpacket_rx;

	size_t i = subpack_rx->current_packet_payload_rx_cnt;
	subpack_rx->payload_buffer[i] = 
		byte_fifo_read(p->rx_fifo);

	subpack_rx->current_packet_payload_rx_cnt += 1;
		
	if (subpack_rx->current_packet_payload_rx_cnt
	    >= (PT_EXT_RESPONSE_PACKET_HEADER_SIZE-1))
	{
		// we have enough data to read the header
		uint8_t actual_header_cs = pt_ext_calc_header_cs(
			subpack_rx->header, 
			subpack_rx->payload_buffer, 
			subpack_rx->current_packet_payload_rx_cnt-1);

		uint8_t expected_header_cs = 
			subpack_rx->payload_buffer[2];

		if (actual_header_cs != expected_header_cs)
		{
			//header checksum error
			return PT_ERROR_CHECKSUM_FAILED;
		}

		*packet_done = true;

		// we dont expect rsp packet, so just drop it
		if (PT_EXT_TX_STATE_IDLE == p->pt_ext_tx.tx_state)
		{
			return PT_NO_ERROR;
		}

		if (subpack_rx->header & PT_EXT_ACK_FLAG)
		{
			// ack received
			pt_debug("Ack received\n");
			if (p->pt_ext_tx.tx_done_callback)
			{
				p->pt_ext_tx.tx_done_callback(
					PT_EXT_TX_DONE);
			}

			pt_extended_tx_full_packet_done_cleanup(p);
		}
		else
		{
			// nack received
			pt_debug("Nack received\n");
			pt_extended_rx_handle_nack(p);
		}

		subpack_rx->subpacket_rx_state = 
			PT_EXT_RX_WAITING_PACKET_HEADER;
	}

	return PT_NO_ERROR;
}

enum pt_errors pt_extended_rx_header(struct pt *p, uint8_t header)
{
	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&p->pt_ext_rx.subpacket_rx;

	// every income packet resets the tx timer
	struct pt_extended_data_tx *pd = &p->pt_ext_tx;
	pd->time_passed_in_state_ms = 0;

	pt_extended_receiver_prepare_for_new_subpacket(p);

	subpack_rx->header = header;

	enum pt_extended_subpacket_types ext_subpacket_type = 
		(header >> PT_EXT_TYPE_POS) & PT_EXT_TYPE_MASK;

	if (PT_EXT_PACKAGE_TYPE_START == ext_subpacket_type)
	{
		pt_debug("Receiving start packet\n");

		subpack_rx->pt_extended_receive_subpacket = 
			pt_extended_rx_start_packet;
	}
	else if (PT_EXT_PACKAGE_TYPE_PAYLOAD == ext_subpacket_type)
	{
		pt_debug("Receiving payload packet\n");

		subpack_rx->pt_extended_receive_subpacket = 
			pt_extended_rx_payload_packet;
	}
	else if (PT_EXT_PACKAGE_TYPE_RESPONSE == ext_subpacket_type)
	{
		pt_debug("Receiving response packet\n");

		subpack_rx->pt_extended_receive_subpacket = 
			pt_extended_rx_response_packet;
	}
	else
	{
		// TODO: Add assert
		pt_debug("E: Unknown packet\n");
		return PT_ERROR_UNKNOWN_PACKET_TYPE;
	}

	return PT_NO_ERROR;
}

void pt_extended_register_packet_received_callback(
	struct pt *p, 
	void (*cb)(uint8_t *data, size_t data_size))
{
	p->full_packet_received_cb = cb;
}

#endif