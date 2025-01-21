/*
 * SPDX-FileCopyrightText: 2024 Izidor Makuc <izidor@makuc.info>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <inttypes.h>
#include <stdbool.h>
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

#include <stdarg.h>
#ifdef PT_DEBUG
#include <stdio.h>
void pt_debug(const char *format, ...)
{
        //printf("[PT] ");
        va_list va;
        va_start(va, format);
        vprintf(format, va);
        va_end(va);
}
#else

//void pt_debug(const char *format, ...)
//{
//
//}
#endif // PT_DEBUG

static void pt_receiver_check_header(struct pt *p, uint8_t header)
{

	uint8_t packet_type = (header >> PT_HEADER_TYPE_POS) & 0x3;
	if (PT_HEADER_TYPE_PICO == packet_type)
	{
		pt_debug("Receiving pico packet\n");

		pt_pico_receiver_process_header(p, header);
		p->pt_receive_state = 
			PT_RX_RECEIVING_PICO_PACKET;
	}
#ifdef PT_EXTENDED_PACKET_SUPPORT
//	else if (PT_HEADER_TYPE_EXTENDED == packet_type)
//	{
//		pt_debug("Receiving extended packet\n");
//
//		pt_extended_rx_header(p, header);
//		p->pt_receive_state = 
//			PT_RX_RECEIVING_EXTENDED_PACKET;
//	}
#endif
	else
	{
                pt_debug("E: Unknown header type, dropping data\n");
		p->pt_receive_state = 
			PT_DROP_DATA_UNTIL_TIMEOUT;
	}
}

void pt_receiver_run(struct pt *p, uint32_t time_from_last_call_ms)
{
        uint32_t r = PT_NO_ERROR;

        if (NULL == p)
        {
                pt_debug("E: pt_receive args error\n");
                return;
        }

        p->time_from_last_rx_packet_ms += time_from_last_call_ms;

        if ((p->timeout_rx_ms) < p->time_from_last_rx_packet_ms)
        {
                pt_debug("Timeout, dropping stored data\n");
                p->pt_receive_state = PT_RX_WAITING_FIRST_BYTE;
	
                pico_rx_reset(p);
        }
	
        p->time_from_last_rx_packet_ms = 0;

        while(!byte_fifo_is_empty(p->rx_fifo))
        {
                if (PT_RX_WAITING_FIRST_BYTE == p->pt_receive_state)
                {
			uint8_t header = byte_fifo_read(p->rx_fifo);
			pt_receiver_check_header(p, header);
		}

                else if (PT_RX_RECEIVING_PICO_PACKET == p->pt_receive_state)
                {
                        bool pico_processing_done = false;
                        r = pt_pico_receiver_process_payload(
				p, 
				&pico_processing_done);

                        if (PT_NO_ERROR != r)
                        {
                                p->pt_receive_state = 
					PT_DROP_DATA_UNTIL_TIMEOUT;
                        }
			else if (pico_processing_done)
			{
                                p->pt_receive_state = 
					PT_RX_WAITING_FIRST_BYTE;
			}
                }
#ifdef PT_EXTENDED_PACKET_SUPPORT
                else if (PT_RX_RECEIVING_EXTENDED_PACKET == p->pt_receive_state)
                {
                        bool processing_done = false;
                        r = pt_extended_receiver_process_payload(
				p, 
				&processing_done);

                        if (PT_NO_ERROR != r)
                        {
                                p->pt_receive_state = 
					PT_DROP_DATA_UNTIL_TIMEOUT;
                        }
			else if (processing_done)
			{
                                p->pt_receive_state = 
					PT_RX_WAITING_FIRST_BYTE;
			}

                }
#endif
		else if (PT_DROP_DATA_UNTIL_TIMEOUT == p->pt_receive_state)
		{
			return;
		}
        }
}

struct pt *pt_init(struct pt_settings *s)
{
        if (NULL == s || NULL == s->rx_fifo 
	    || NULL == s->tx_fifo || NULL == s->malloc)
        {
                return NULL;
        }
        
        struct pt *tmp = s->malloc(sizeof(struct pt));
        if (NULL == tmp)
        {
                return NULL;
        }
        memset(tmp, 0, sizeof(struct pt));
        
        tmp->tx_fifo = s->tx_fifo;
        tmp->rx_fifo = s->rx_fifo;

        tmp->timeout_rsp_tx_ms = s->tx_rsp_timeout_ms;
        tmp->timeout_rx_ms = s->rx_timeout_ms;

        return tmp;
}
