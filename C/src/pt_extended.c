/*
 * SPDX-FileCopyrightText: 2023 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* pico packets are small packets with payload up to 16b with
 * additional 1b header and 1b checksum at the end of the packet
 *
 * Structure of the packet header:
 * dlp version (2bit), dlp type (2bit), payload size - 1 (4bit)
 */

#include <inttypes.h>
#include <stdbool.h>
//#include <stdio.h>
#include <string.h>

#include "pt.h"
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
flag and the block number 0. When the sender receives this response,
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
enum pt_errors pt_extended_send(struct pt *p, 
				uint8_t *data, 
				size_t data_size,
				void (*done_callback)(uint8_t status))
{
		
        uint8_t h = (PT_HEADER_TYPE_EXTENDED << PT_HEADER_TYPE_POS)
		| (PT_EXTENDED_PACKAGE_TYPE_START);

	if (PT_EXT_START_PACKET_SIZE > byte_fifo_get_free_space(p->tx_fifo))
	{
		return PT_ERROR_BUSY;
	}

	//byte_fifo_write(p->tx_fifo, h);


//	uint8_t cs = bsd_checksum8_from(0, &h, 1);
//	cs = bsd_checksum8_from(cs, &data_size_l, 1);
//	cs = bsd_checksum8_from(cs, &data_size_h, 1);
//	byte_fifo_write(p->tx_fifo, cs);
//
//	for (uint32_t i = 0; data_size > i; i++)
//	{
//		byte_fifo_write(p->tx_fifo, data[i]);		
//	}
//
//	uint16_t data_cs = bsd_checksum16(data, data_size);
//
//	byte_fifo_write(p->tx_fifo, (uint8_t) (data_cs >> 8) & 0xff);
//	byte_fifo_write(p->tx_fifo, (uint8_t) data_cs & 0xff);
//
	return PT_NO_ERROR;
}
//
//static bool pt_fast_is_packet_respons(uint8_t header)
//{
//	return header & (PT_FAST_RESPONSE << PT_FAST_HANDSHAKE_POS);
//}
//
//static enum pt_fast_status pt_fast_get_ack_nack(uint8_t header)
//{
//	uint8_t nack = (header 
//			& (PT_FAST_NACK << PT_FAST_ACK_NACK_POS));
//	return nack ? PT_FAST_PACKET_NACK : PT_FAST_PACKET_ACK;
//}
//
//void pt_fast_rx_header(struct pt *p, uint8_t header)
//{
//	// we only support receiving of response frames
//	if (pt_fast_is_packet_respons(header))
//	{
//		if (p->fp.tx_done_callback)
//		{
//			p->fp.tx_done_callback(
//				pt_fast_get_ack_nack(header));
//		}
//	}
//}
//enum pt_errors pt_fast_receive(struct pt *p)
//{
//	if (byte_fifo_get_fill_count(p->tx_fifo) >= 3)
//	{
//
//	}
//	return PT_NO_ERROR;	
//}
#endif