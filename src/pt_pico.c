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


STATIC uint8_t pt_make_pico_header(size_t data_size)
{
        uint8_t h;
        h = ((PT_HEADER_TYPE_PICO  << PT_HEADER_TYPE_POS)
             | ((data_size-1) & (PT_PICO_MAX_PAYLOAD_LENGTH - 1)));
        return h;
}

void pico_rx_reset(struct pt *p)
{
        p->pico_rx_data.pico_rx_state = PT_PICO_RX_STATE_WAITING_HEADER;
        p->pico_rx_data.buff_data_already_received_cnt = 0;
        p->pico_rx_data.buff_expected_data_size = 0;
}

int32_t pt_pico_send(struct pt *p, uint8_t *data, size_t data_size)
{
        if (NULL == p || NULL == data || 0 == data_size
            || PT_PICO_MAX_PAYLOAD_LENGTH < data_size)
        {
                return PT_ERROR_ARGS;
        }

	uint8_t header = pt_make_pico_header(data_size);
	byte_fifo_write(p->tx_fifo, header);

        uint32_t i;
	for (i = 0; data_size > i; i++)
	{
		byte_fifo_write(p->tx_fifo, data[i]);
	}

	uint8_t cs = bsd_checksum8_from(0, &header, 1);
	cs = bsd_checksum8_from(cs, data, data_size);		
	byte_fifo_write(p->tx_fifo, cs);

	return PT_NO_ERROR;
}

void pt_pico_receiver_process_header(struct pt *p, uint8_t header)
{
        pico_rx_reset(p);
        p->pico_rx_data.buff[0] = header;
        p->pico_rx_data.buff_data_already_received_cnt = 1;

        // +1 is because payload size in the header is payload size - 1
        p->pico_rx_data.buff_expected_data_size = 
		(header & (PT_PICO_MAX_PAYLOAD_LENGTH-1)) + 1
		+ PT_PICO_PACKET_HEADER_SIZE
		+ PT_PICO_PACKET_TAIL_SIZE;
}

int32_t pt_pico_receiver_process_payload(struct pt *p, bool *done)
{
        struct pt_pico_receiver_data *prx = &p->pico_rx_data;

        while(!byte_fifo_is_empty(p->rx_fifo))
        {
		uint8_t new_byte = byte_fifo_read(p->rx_fifo);

		prx->buff[prx->buff_data_already_received_cnt] = new_byte;
		prx->buff_data_already_received_cnt += 1;

		if ((prx->buff_data_already_received_cnt) == prx->buff_expected_data_size)
		{
			// crc received
			uint8_t cs = bsd_checksum8(prx->buff, 
						   prx->buff_expected_data_size-1);
			if (cs != new_byte)
			{
				pt_debug("checksum failed\n");
				return PT_ERROR_CHECKSUM_FAILED;
			}
			else
			{
				if (prx->callback)
				{
					prx->callback(prx->rx_callback_handler , 
						      &prx->buff[1],
						      prx->buff_expected_data_size-2);
				}
				prx->pico_rx_state = PT_PICO_RX_STATE_WAITING_HEADER;
			}

			*done = true;
			break;
		}
        }

        return PT_NO_ERROR;
}

void pt_pico_register_rx_callback(
	struct pt *p,
	void *high_layer_data, 
	void (*high_layer_callback)(void *, uint8_t *, size_t))
{
        p->pico_rx_data.callback = high_layer_callback;
        p->pico_rx_data.rx_callback_handler = high_layer_data;
}
