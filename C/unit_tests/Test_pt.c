#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "unity.h"

#include "pt.h"
#include "pt_internal.h"

#include "bsd_checksum.h"
#include "byte_fifo.h"

#include <stdarg.h>
#include <stdio.h>

static bool disable_output = false;
void pt_debug(const char *format, ...)
{
	if (disable_output)
	{
		return;
	}
        //printf("[PT] ");
        va_list va;
        va_start(va, format);
        vprintf(format, va);
        va_end(va);
}


struct pt *pt = NULL;

struct byte_fifo *ftx = NULL;
uint8_t ftx_buff[32*1024];

static uint32_t callback_cnt = 0;
static uint8_t callback_rx_data[2*PT_PICO_MAX_PAYLOAD_LENGTH];
static size_t callback_rx_data_size = 0;

uint32_t tp_ext_tx_done_callback_test_call_cnt = 0;
enum pt_ext_tx_rsp_status last_tx_done_status = 0;
void tp_ext_tx_done_callback_test(enum pt_ext_tx_rsp_status s)
{
	tp_ext_tx_done_callback_test_call_cnt += 1;
	last_tx_done_status = s;
	pt_debug("tx done called %i times, status %i\n",
	       tp_ext_tx_done_callback_test_call_cnt, s);
}

static uint32_t ext_full_packet_cb_cnt = 0;
static uint8_t *ext_full_payload_data = NULL;
size_t ext_full_payload_data_size = 0;

void ext_full_packet_cb(uint8_t *data, size_t data_size)
{
	(void) data;
	(void) data_size;

	ext_full_packet_cb_cnt += 1;
	ext_full_payload_data_size = data_size;
	ext_full_payload_data = data;
}

uint8_t *request_memory(size_t data_size)
{
	return malloc(data_size);
}


void pt_pico_packet_rx_complete(void *dlp, uint8_t *data, size_t data_size)
{
	(void) dlp;
	(void) data;
	(void) data_size;
	callback_cnt += 1;

	if (sizeof(callback_rx_data) >= data_size)
	{
		memcpy(callback_rx_data, data, data_size);
	}
	callback_rx_data_size = data_size;
}


void setUp(void)
{
	disable_output = true;
	callback_cnt = 0;
	tp_ext_tx_done_callback_test_call_cnt = 0;
	ext_full_packet_cb_cnt = 0;

	memset(callback_rx_data, 0, sizeof(callback_rx_data));
	callback_rx_data_size = 0;

	if (NULL == ftx)
	{
		struct byte_fifo_settings fsr = {
			.my_malloc = malloc,
			.fifo_buff = ftx_buff,
			.fifo_size = sizeof(ftx_buff),
		};

		ftx = byte_fifo_init(&fsr);
	}

	if (NULL == pt)
	{
		struct pt_settings s = {
			//struct dlp_micro_settings *ms;
			.malloc = malloc,

			.tx_fifo = ftx,
			.rx_fifo = ftx,

			.tx_retries = 0,
			.tx_rsp_timeout_ms = 10,
			.rx_timeout_ms = 0,

			.request_memory = request_memory,
		};

		pt = pt_init(&s);
	}
	if (pt)
	{
		byte_fifo_reset(pt->tx_fifo);
	}
}

void tearDown(void)
{
	disable_output = false;
	if (ext_full_payload_data)
	{
		free(ext_full_payload_data);
		ext_full_payload_data = NULL;
	}
}

void test_pt_init(void)
{
	struct pt_settings s = {
		.malloc = malloc,

		.tx_fifo = ftx,
		.rx_fifo = ftx,

		.tx_retries = 0,
		//.tx_rsp_timeout_ms = 0,
		.rx_timeout_ms = 0,

		.request_memory = request_memory,
	};

	struct pt *pt_p = pt_init(&s);
	TEST_ASSERT_NOT_NULL(pt_p);

}

void test_pt_pico_send(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	uint8_t data[] = {1,2,3};
	int32_t r = pt_pico_send(pt, data, sizeof(data));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_UINT16(sizeof(data) + 2, 
				 byte_fifo_get_fill_count(ftx));

	uint8_t header = byte_fifo_read(ftx);

	TEST_ASSERT_EQUAL_UINT8(
		(PT_HEADER_TYPE_PICO << PT_HEADER_TYPE_POS)
		| (sizeof(data)-1),
		header);

	TEST_ASSERT_EQUAL_UINT8(data[0],
				byte_fifo_read(ftx));

	TEST_ASSERT_EQUAL_UINT8(data[1],
				byte_fifo_read(ftx));

	TEST_ASSERT_EQUAL_UINT8(data[2],
				byte_fifo_read(ftx));


	uint8_t cs = bsd_checksum8_from(0, &header, 1);
	cs = bsd_checksum8_from(cs, data, sizeof(data));

	TEST_ASSERT_EQUAL_UINT8(cs, byte_fifo_read(ftx));

	TEST_ASSERT_TRUE(byte_fifo_is_empty(ftx));
}

void test_pt_pico_too_big_send(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	uint8_t data[PT_PICO_MAX_PAYLOAD_LENGTH + 1];

	int32_t r = pt_pico_send(pt, data, sizeof(data));
	TEST_ASSERT_EQUAL_INT32(PT_ERROR_ARGS, r);

}

void test_pt_pico_rx_one_ok_msg(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	uint8_t data[] = {4,5,6};
	int32_t r = pt_pico_send(pt, data, sizeof(data));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_pico_register_rx_callback(pt, NULL, 
				      pt_pico_packet_rx_complete);

	pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(1, callback_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), callback_rx_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, callback_rx_data, sizeof(data));
}

void test_pt_pico_rx_one_max_size_ok_msg(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	// array till 15
	uint8_t data[PT_PICO_MAX_PAYLOAD_LENGTH];

	int32_t r = pt_pico_send(pt, data, sizeof(data));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_pico_register_rx_callback(pt, NULL, 
				      pt_pico_packet_rx_complete);


	TEST_ASSERT_EQUAL_INT32(0, callback_cnt);
	pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(1, callback_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), callback_rx_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, callback_rx_data, sizeof(data));
}

void test_pt_pico_rx_multiple_ok_msg(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	uint8_t data1[] = {4,5,6};
	uint8_t data2[] = {10, 11, 12, 13, 14};

	int32_t r = pt_pico_send(pt, data1, sizeof(data1));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	r = pt_pico_send(pt, data2, sizeof(data2));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_pico_register_rx_callback(pt, NULL, 
				      pt_pico_packet_rx_complete);

	pt_receiver_run(pt, 1);


	TEST_ASSERT_EQUAL_INT32(2, callback_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data2), callback_rx_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data2, callback_rx_data, sizeof(data2));
}


void test_pt_pico_rx_junk_in_front_of_the_ok_msg(void)
{
	TEST_ASSERT_NOT_NULL(pt);
	uint8_t junk[] = {3,1,5,23};
	uint8_t data1[] = {4,5,6};
	uint8_t data2[] = {10, 11, 12, 13, 14};

	struct pt_settings s = {
		//struct dlp_micro_settings *ms;
		.malloc = malloc,

		.tx_fifo = ftx,
		.rx_fifo = ftx,

		.tx_retries = 0,
		//.tx_rsp_timeout_ms = 0,
		.rx_timeout_ms = 10,
		.request_memory = request_memory,
	};

	struct pt *ptt = pt_init(&s);

	byte_fifo_write(ftx, junk[0]);

	int32_t r = pt_pico_send(ptt, data1, sizeof(data1));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_pico_register_rx_callback(ptt, NULL, 
				      pt_pico_packet_rx_complete);

	pt_receiver_run(ptt, 1);

	// msg should be droped because of the junk in front of it
	TEST_ASSERT_EQUAL_INT32(0, callback_cnt);

	pt_receiver_run(ptt, 10);

	r = pt_pico_send(ptt, data2, sizeof(data2));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_receiver_run(ptt, 1);

	TEST_ASSERT_EQUAL_INT32(1, callback_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data2), callback_rx_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data2, callback_rx_data, sizeof(data2));
}

void test_pt_ext_move_tx_state(void)
{
	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_IDLE;
	pt->pt_ext_tx.time_passed_in_state_ms += 1;

	pt_ext_move_tx_state(pt, PT_EXT_TX_STATE_SEND_START_PACKET);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_SEND_START_PACKET, 
				pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_UINT32(
		0, pt->pt_ext_tx.time_passed_in_state_ms);
}

void test_pt_extended_tx_full_packet_done(void)
{
	uint8_t data = 5;

	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET;
	pt->pt_ext_tx.data = &data; //just get a valid ptr
	pt->pt_ext_tx.data_size = 1;
	pt->pt_ext_tx.data_already_sent += 34;

	pt->pt_ext_tx.response_packet_number += 1;
	pt->pt_ext_tx.send_response = true;
	pt->pt_ext_tx.response_flags = true;
	pt->pt_ext_tx.tx_done_callback = NULL;

	pt_extended_tx_full_packet_done_cleanup(pt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_PTR(NULL, pt->pt_ext_tx.data);

	TEST_ASSERT_EQUAL_size_t(0, pt->pt_ext_tx.data_size);
	TEST_ASSERT_EQUAL_size_t(0, pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_UINT16(0, 
				 pt->pt_ext_tx.response_packet_number);

	TEST_ASSERT_FALSE(pt->pt_ext_tx.send_response);
	TEST_ASSERT_FALSE(pt->pt_ext_tx.response_flags);
}

void test_pt_extended_send(void)
{
	enum pt_errors r;
	uint8_t data;

	r = pt_extended_send(pt,
			     NULL, 
			     0,
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_ERROR_ARGS, r);
	pt_extended_tx_full_packet_done_cleanup(pt);

	r = pt_extended_send(pt,
			     &data, 
			     1,
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	r = pt_extended_send(pt,
			     &data, 
			     1,
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_ERROR_BUSY, r);	
	pt_extended_tx_full_packet_done_cleanup(pt);

	// test if the cleanup function really unblocks
	r = pt_extended_send(pt,
			     &data, 
			     1,
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	
}


void test_pt_extended_tx_run_send_only_start_packet(void)
{
	enum pt_errors r;
	uint8_t data[] = {0,1,2,3,4,5,6,7};

	pt_extended_tx_full_packet_done_cleanup(pt);

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);


	// test the case when there is not enough space in fifo
	uint32_t fs = byte_fifo_get_free_space(pt->tx_fifo);

	for (uint32_t i = 0; (fs-1) > i; i++)
	{
		byte_fifo_write(pt->tx_fifo, i & 0xff);
	}

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_SEND_START_PACKET, 
		pt->pt_ext_tx.tx_state);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_SEND_START_PACKET, 
		pt->pt_ext_tx.tx_state);

	// test when there is enough space in fifo
	byte_fifo_reset(pt->tx_fifo);

	pt_extended_tx_run(pt, 1);

//	TEST_ASSERT_EQUAL_UINT8(
//		PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
//		pt->pt_ext_tx.tx_state);
//
//	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);


//	r = pt_extended_send(pt,
//			     &data, 
//			     1,
//			     tp_ext_tx_done_callback_test);
//
//	TEST_ASSERT_EQUAL_INT32(PT_ERROR_BUSY, r);	
//	pt_extended_tx_full_packet_done_cleanup(pt);

}

void test_pt_extended_tx_run_send_start_and_payload_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 2];

	pt_extended_tx_full_packet_done_cleanup(pt);

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);
}

void test_pt_extended_tx_run_send_start_and_multiple_payload_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 3];

	pt_extended_tx_full_packet_done_cleanup(pt);

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
		pt->pt_ext_tx.tx_state);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);
}

void test_pt_extended_tx_run_send_start_and_uneven_multiple_payload_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 3 + 1];

	pt_extended_tx_full_packet_done_cleanup(pt);

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
		pt->pt_ext_tx.tx_state);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
		pt->pt_ext_tx.tx_state);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);
}

void test_pt_extended_tx_timeout(void)
{
	pt_extended_tx_full_packet_done_cleanup(pt);

	enum pt_errors r;
	uint8_t data;

	r = pt_extended_send(pt,
			     &data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	pt_extended_tx_run(pt, 1);

	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_UINT32(
		0, tp_ext_tx_done_callback_test_call_cnt);

	pt_extended_send_response(pt, true);

	pt_extended_tx_run(pt, 1);

	// message was only sent but not received yet, so state should be the same
	TEST_ASSERT_EQUAL_UINT8(
		PT_EXT_TX_STATE_WAIT_RSP,
		pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_UINT32(
		0, tp_ext_tx_done_callback_test_call_cnt);

	// test tx timeout
	pt_extended_tx_run(pt, 100);
	TEST_ASSERT_EQUAL_UINT32(
		1, tp_ext_tx_done_callback_test_call_cnt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_TIMEOUT, last_tx_done_status);
}

void test_pt_extended_rx_header(void)
{
	pt_extended_tx_full_packet_done_cleanup(pt);

	enum pt_errors r;
	uint8_t data;
	struct pt_extended_data_rx_subpacket *subpack_rx = 
		&pt->pt_ext_rx.subpacket_rx;

	r = pt_extended_send(pt,
			     &data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	r = pt_extended_send_start_packet(pt);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	uint8_t header = byte_fifo_read(pt->tx_fifo);
	r = pt_extended_rx_header(pt, header);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	//TEST_ASSERT_EQUAL_UINT8(PT_EXT_PACKAGE_TYPE_START, 
	//			pt->pt_ext_rx.subpacket_rx.ext_subpacket_type);

	TEST_ASSERT_EQUAL_PTR(pt_extended_rx_start_packet,
			      subpack_rx->pt_extended_receive_subpacket);

	byte_fifo_reset(ftx);

	r = pt_extended_send_next_payload_packet(pt);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	header = byte_fifo_read(pt->tx_fifo);
	r = pt_extended_rx_header(pt, header);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	//TEST_ASSERT_EQUAL_UINT8(PT_EXT_PACKAGE_TYPE_PAYLOAD,
	//			subpack_rx->ext_subpacket_type);

	TEST_ASSERT_EQUAL_PTR(pt_extended_rx_payload_packet,
			      subpack_rx->pt_extended_receive_subpacket);
}


void test_pt_extended_start_packet_tx_rx(void)
{
	pt_extended_tx_full_packet_done_cleanup(pt);

	enum pt_errors r;
	uint8_t data[1024];

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	r = pt_extended_send_start_packet(pt);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	uint8_t header = byte_fifo_read(pt->tx_fifo);
	r = pt_extended_rx_header(pt, header);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	bool packet_done = false;
	while (!packet_done) {
		r = pt_extended_rx_start_packet(pt, 1, &packet_done);
		TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	}


	r = pt_extended_send_next_payload_packet(pt);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	header = byte_fifo_read(pt->tx_fifo);
	r = pt_extended_rx_header(pt, header);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	packet_done = false;
	while (!packet_done) {
		r = pt_extended_rx_payload_packet(pt, 1, &packet_done);
		TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	}
}


void test_pt_ext_send_packet_less_than_full_size(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size/2];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// send data packet
	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);
	TEST_ASSERT_EQUAL_INT32(0, ext_full_packet_cb_cnt);

	// run receive to receive above data package
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// after successfully receiving the packet, 
	// the ack should be sent back. So check if the tx statemachine
	// is set to send the response
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// after receiving the packet, the callback should be called
	TEST_ASSERT_EQUAL_INT32(1, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// run the tx statemachine to send the ack
	pt_extended_tx_run(pt, 1);

	// receive ack and check if the tx is unblocked
	uint32_t old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));
	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);


	// lets try to send another packet
	pt_debug("test: sending second packet\n");
	// change payload data
	for (uint32_t i = 0; i < sizeof(data); i++) 
	{
		data[i] = i & 0xff;
	}

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// send packet
	pt_extended_tx_run(pt, 1);

	// receive packet
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(2, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// send back ack
	pt_extended_tx_run(pt, 1);

	// receive ack
	old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));

	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);
}

void test_pt_ext_send_packet_less_than_full_size_with_header(void)
{
	disable_output = false;

	enum pt_errors r;
	uint8_t header[4] = {4,3,2,1};
	uint8_t data[pt->max_packet_payload_size/2];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// send data packet
	r = pt_extended_send_data_with_header(pt,
					 header,
					 sizeof(header),
					 data, 
					 sizeof(data),
					 tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);
	TEST_ASSERT_EQUAL_INT32(0, ext_full_packet_cb_cnt);

	// run receive to receive above data package
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// after successfully receiving the packet, 
	// the ack should be sent back. So check if the tx statemachine
	// is set to send the response
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// after receiving the packet, the callback should be called
	TEST_ASSERT_EQUAL_INT32(1, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data) + sizeof(header), 
				ext_full_payload_data_size);

	TEST_ASSERT_EQUAL_MEMORY(header, 
				 ext_full_payload_data,
				 sizeof(header));
	
	TEST_ASSERT_EQUAL_MEMORY(data, 
				 ext_full_payload_data + sizeof(header),
				 sizeof(data));

	// run the tx statemachine to send the ack
	pt_extended_tx_run(pt, 1);

	// receive ack and check if the tx is unblocked
	uint32_t old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));
	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);


	// lets try to send another packet
	pt_debug("test: sending second packet\n");
	// change payload data
	for (uint32_t i = 0; i < sizeof(data); i++) 
	{
		data[i] = i & 0xff;
	}

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// send packet
	pt_extended_tx_run(pt, 1);

	// receive packet
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(2, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// send back ack
	pt_extended_tx_run(pt, 1);

	// receive ack
	old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));

	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);
}



void test_pt_ext_send_packet_bigger_than_only_start_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 2];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// send data packet
	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);
	TEST_ASSERT_EQUAL_INT32(0, ext_full_packet_cb_cnt);

	// run receive to receive above data package
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// after successfully receiving the packet, 
	// the ack should be sent back. So check if the tx statemachine
	// is set to send the response
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// after receiving the packet, the callback should be called
	TEST_ASSERT_EQUAL_INT32(1, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// run the tx statemachine to send the ack
	pt_extended_tx_run(pt, 1);

	// receive ack and check if the tx is unblocked
	uint32_t old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));
	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);


	// lets try to send another packet
	pt_debug("test: sending second packet\n");
	// change payload data
	for (uint32_t i = 0; i < sizeof(data); i++) 
	{
		data[i] = i & 0xff;
	}

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// send packet
	pt_extended_tx_run(pt, 1);

	// receive packet
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(2, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// send back ack
	pt_extended_tx_run(pt, 1);

	// receive ack
	old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));

	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);
}

void test_pt_ext_send_packet_with_predata(void)
{
	enum pt_errors r;
	uint8_t header[3] = {1,2,3};
	uint8_t data[pt->max_packet_payload_size * 2];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// send data packet
	r = pt_extended_send_data_with_header(pt,
					      header,
					      sizeof(header),
					      data, 
					      sizeof(data),
					      tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	pt_extended_tx_run(pt, 1);
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);
	TEST_ASSERT_EQUAL_INT32(0, ext_full_packet_cb_cnt);

	// run receive to receive above data package
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// after successfully receiving the packet, 
	// the ack should be sent back. So check if the tx statemachine
	// is set to send the response
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// after receiving the packet, the callback should be called
	TEST_ASSERT_EQUAL_INT32(1, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data) + sizeof(header), 
				ext_full_payload_data_size);

	TEST_ASSERT_EQUAL_MEMORY(header, 
				 ext_full_payload_data,
				 sizeof(header));

	TEST_ASSERT_EQUAL_MEMORY(data, 
				 ext_full_payload_data + sizeof(header),
				 sizeof(data));

	// run the tx statemachine to send the ack
	pt_extended_tx_run(pt, 1);

	// receive ack and check if the tx is unblocked
	uint32_t old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));
	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);


	// lets try to send another packet
	pt_debug("test: sending second packet\n");
	// change payload data
	for (uint32_t i = 0; i < sizeof(data); i++) 
	{
		data[i] = i & 0xff;
	}

	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// send packet
	pt_extended_tx_run(pt, 1);

	// receive packet
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(2, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// send back ack
	pt_extended_tx_run(pt, 1);

	// receive ack
	old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));

	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);
}

void test_pt_ext_send_really_long_paylaod_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 64];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// send data packet
	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	while(pt->pt_ext_tx.tx_state != PT_EXT_TX_STATE_WAIT_RSP)
	{
		pt_extended_tx_run(pt, 1);
	}

	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);
	TEST_ASSERT_EQUAL_INT32(0, ext_full_packet_cb_cnt);

	// run receive to receive above data package
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// after successfully receiving the packet, 
	// the ack should be sent back. So check if the tx statemachine
	// is set to send the response
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// after receiving the packet, the callback should be called
	TEST_ASSERT_EQUAL_INT32(1, ext_full_packet_cb_cnt);
	TEST_ASSERT_EQUAL_INT32(sizeof(data), ext_full_payload_data_size);
	TEST_ASSERT_EQUAL_MEMORY(data, ext_full_payload_data, sizeof(data));

	// run the tx statemachine to send the ack
	pt_extended_tx_run(pt, 1);

	// receive ack and check if the tx is unblocked
	uint32_t old_tmp = tp_ext_tx_done_callback_test_call_cnt;
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// fifo should be empty
	TEST_ASSERT_EQUAL_INT32(0, byte_fifo_get_fill_count(pt->tx_fifo));
	// tx statemachine should be idle
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);

	// pt_extended_send done callback should be called
	TEST_ASSERT_EQUAL_UINT32(old_tmp + 1, 
				tp_ext_tx_done_callback_test_call_cnt);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_DONE, last_tx_done_status);
}

void test_pt_ext_foo_start_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	pt->pt_ext_tx.data = data;
	pt->pt_ext_tx.data_size = sizeof(data);
	//pt->pt_ext_tx.tx_done_callback = done_callback;

	struct pt_extended_start_packet_header h;

	pt_extended_fill_start_packet_header(
		pt, &h, pt->max_packet_payload_size/2);

	// test what happen if start header checksum is foo
	h.header_bsd8_cs += 1;

	pt_extended_sent_start_packet(
		pt, &h, pt->max_packet_payload_size/2);


	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_UINT8(PT_DROP_DATA_UNTIL_TIMEOUT,
				pt->pt_receive_state);


	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);
}

void test_pt_ext_start_packet_reset_previous_transfer(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 3];

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	pt->pt_ext_tx.data = data;
	pt->pt_ext_tx.data_size = sizeof(data);

	struct pt_extended_start_packet_header hs;

	pt_extended_fill_start_packet_header(
		pt, &hs, pt->max_packet_payload_size);

	// test what happen if start header checksum is foo
	pt_extended_sent_start_packet(
		pt, &hs, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);


	struct pt_extended_payload_packet_header hp;

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);

	TEST_ASSERT_EQUAL_INT32(2*pt->max_packet_payload_size, 
				pt->pt_ext_tx.data_already_sent);

	pt_extended_tx_full_packet_done_cleanup(pt);
	uint32_t tmp = ext_full_packet_cb_cnt;
	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);	

	// run send statemachine to send the packet
	while(pt->pt_ext_tx.tx_state != PT_EXT_TX_STATE_WAIT_RSP)
	{
		pt_extended_tx_run(pt, 1);
	}

	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(tmp+1,
				ext_full_packet_cb_cnt); 

}

void test_pt_ext_rx_nack_when_tx_idle(void)
{
	enum pt_errors r;

	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_send_response(pt, false); 
	pt_extended_tx_run(pt, 1); 

	r = pt_receiver_run(pt, 1); // handle nack	
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_IDLE,
				pt->pt_ext_tx.tx_state);
}

void test_pt_ext_nack_start_packet(void)
{
	//disable_output = false;
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 2];

	// reset the pt_ext 
	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);


	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);

	//pt_extended_tx_run(pt, 1); // sent start packet
	pt_extended_send_start_packet(pt);
	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET;

	byte_fifo_reset(ftx); // simulate packet lost :D
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
				pt->pt_ext_tx.tx_state);

	// request nack packet
	pt_extended_send_response(pt, false);
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);
	TEST_ASSERT_EQUAL_INT32(0, 
				pt->pt_ext_tx.response_packet_number);


	pt_extended_tx_run(pt, 1); // sent nack response packet


	// receive nack response packet
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// check if the first packet will be retransmitted
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_IDLE_TIMEOUT,
				pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_SEND_START_PACKET,
				pt->pt_ext_tx.tx_state_before_nack);

	// test if we will get the packet now
	pt_extended_tx_run(pt, pt->timeout_tx_ms);
	TEST_ASSERT_EQUAL_UINT8(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);

	TEST_ASSERT_EQUAL_INT32(0,
				ext_full_packet_cb_cnt); 

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(1,
				ext_full_packet_cb_cnt); 

	TEST_ASSERT_EQUAL_INT32(sizeof(data),
				ext_full_payload_data_size);

	TEST_ASSERT_EQUAL_MEMORY(
		data,
		ext_full_payload_data,
		ext_full_payload_data_size);
}

void test_pt_ext_start_packet_missing(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 4];

	// reset the pt_ext 
	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// make ext start packet and send it
	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	pt->pt_ext_tx.data = data;
	pt->pt_ext_tx.data_size = sizeof(data);
	pt->pt_ext_tx.data_already_sent = pt->max_packet_payload_size;
//	struct pt_extended_start_packet_header hs;
//
//	pt_extended_fill_start_packet_header(
//		pt, &hs, pt->max_packet_payload_size);
//
//	pt_extended_sent_start_packet(
//		pt, &hs, pt->max_packet_payload_size);
//
//	r = pt_receiver_run(pt, 1);
//	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
//	// all bytes should be used by tx/rx (it is same fifo)
//	TEST_ASSERT_EQUAL_INT32(0, 
//				byte_fifo_get_fill_count(pt->tx_fifo));
//
//	// receiver should be in state waiting new packet
//	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
//				pt->pt_receive_state);

	// generate payload packet with foo header crc
	struct pt_extended_payload_packet_header hp;

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	// receiver should be in drop mode due crc error
	TEST_ASSERT_EQUAL_UINT8(PT_DROP_DATA_UNTIL_TIMEOUT,
				pt->pt_receive_state);

	// and it should indicate that response (nack) packet should
	// be sent back
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// nack packet number should be 1 -> payload packet which needs
	// to be retransmitted
	TEST_ASSERT_EQUAL_INT32(0, 
				pt->pt_ext_tx.response_packet_number);

	return;



	// send the respnse packet
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_FALSE(pt->pt_ext_tx.send_response);

	TEST_ASSERT_EQUAL_INT32(4, //response packet
				byte_fifo_get_fill_count(pt->tx_fifo));


	// receive the nack response packet
	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// check that the received data is as expected
	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(
		pt->max_packet_payload_size, 
		pt->pt_ext_rx.full_payload_buffer_fill_index);

	TEST_ASSERT_EQUAL_MEMORY(
		data,
		pt->pt_ext_rx.full_payload_buffer,
		pt->max_packet_payload_size);
}

void test_pt_ext_nack_retransmit_from_last_valid_packet(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 4];

	// set test data to known values
	memset(data, 0, pt->max_packet_payload_size);

	memset(&data[pt->max_packet_payload_size], 
	       1, pt->max_packet_payload_size);

	memset(&data[pt->max_packet_payload_size*2], 
	       2, pt->max_packet_payload_size);

	memset(&data[pt->max_packet_payload_size*3], 
	       3, pt->max_packet_payload_size);

	// reset the pt_ext 
	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	// make ext start packet and send it
	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	pt->pt_ext_tx.data = data;
	pt->pt_ext_tx.data_size = sizeof(data);

	struct pt_extended_start_packet_header hs;

	pt_extended_fill_start_packet_header(
		pt, &hs, pt->max_packet_payload_size);

	pt_extended_sent_start_packet(
		pt, &hs, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// all bytes should be used by tx/rx (it is same fifo)
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	// receiver should be in state waiting new packet
	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);


	// generate payload packet with foo header crc
	struct pt_extended_payload_packet_header hp;

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	// make foo header
	hp.header_bsd8_cs += 1;

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	// receiver should be in drop mode due crc error
	TEST_ASSERT_EQUAL_UINT8(PT_DROP_DATA_UNTIL_TIMEOUT,
				pt->pt_receive_state);

	// and it should indicate that response (nack) packet should
	// be sent back
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// nack packet number should be 1 -> payload packet which needs
	// to be retransmitted
	TEST_ASSERT_EQUAL_INT32(1, 
				pt->pt_ext_tx.response_packet_number);

	// send the respnse packet
	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_FALSE(pt->pt_ext_tx.send_response);

	TEST_ASSERT_EQUAL_INT32(4, //response packet
				byte_fifo_get_fill_count(pt->tx_fifo));


	// receive the nack response packet
	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// check that the received data is as expected
	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(
		pt->max_packet_payload_size, 
		pt->pt_ext_rx.full_payload_buffer_fill_index);

	TEST_ASSERT_EQUAL_MEMORY(
		data,
		pt->pt_ext_rx.full_payload_buffer,
		pt->max_packet_payload_size);

	
	// correct header crc
	hp.header_bsd8_cs -= 1;

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);

	TEST_ASSERT_EQUAL_INT32(2*pt->max_packet_payload_size, 
				pt->pt_ext_tx.data_already_sent);


	// check that the received data is as expected
	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size*2, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(
		pt->max_packet_payload_size*2, 
		pt->pt_ext_rx.full_payload_buffer_fill_index);

	TEST_ASSERT_EQUAL_MEMORY(
		&data[pt->max_packet_payload_size],
		&pt->pt_ext_rx.full_payload_buffer[pt->max_packet_payload_size],
		pt->max_packet_payload_size);


	// send next payload packet with corrupted header

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	// make foo header
	hp.header_bsd8_cs += 1;

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	// receiver should be in drop mode due crc error
	TEST_ASSERT_EQUAL_UINT8(PT_DROP_DATA_UNTIL_TIMEOUT,
				pt->pt_receive_state);

	// and it should indicate that response (nack) packet should
	// be sent back
	TEST_ASSERT_TRUE(pt->pt_ext_tx.send_response);

	// nack packet number should be now 2 
	TEST_ASSERT_EQUAL_INT32(2, 
				pt->pt_ext_tx.response_packet_number);


	// send the respnse packet after timeout
	pt_extended_tx_run(pt, pt->timeout_tx_ms);
	TEST_ASSERT_FALSE(pt->pt_ext_tx.send_response);

	TEST_ASSERT_EQUAL_INT32(4, //response packet
				byte_fifo_get_fill_count(pt->tx_fifo));


	// receive the nack response packet
	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// check that the received data is as expected
	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size*2, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(
		pt->max_packet_payload_size*2, 
		pt->pt_ext_rx.full_payload_buffer_fill_index);

	// check if the previous packet payload isnt corrupted
	TEST_ASSERT_EQUAL_MEMORY(
		&data[pt->max_packet_payload_size],
		&pt->pt_ext_rx.full_payload_buffer[pt->max_packet_payload_size],
		pt->max_packet_payload_size);

	// correct header crc
	hp.header_bsd8_cs -= 1;

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, pt->timeout_rx_ms+1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);


	TEST_ASSERT_EQUAL_INT32(3*pt->max_packet_payload_size, 
				pt->pt_ext_tx.data_already_sent);


	// check that the received data is as expected
	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size*3, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(
		pt->max_packet_payload_size*3, 
		pt->pt_ext_rx.full_payload_buffer_fill_index);

	TEST_ASSERT_EQUAL_MEMORY(
		&data[pt->max_packet_payload_size*2],
		&pt->pt_ext_rx.full_payload_buffer[pt->max_packet_payload_size*2],
		pt->max_packet_payload_size);

	// send lasp payload packet and receive it

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_INT32(pt->max_packet_payload_size*4, 
				pt->pt_ext_tx.data_already_sent);

	TEST_ASSERT_EQUAL_INT32(1,
				ext_full_packet_cb_cnt); 

	TEST_ASSERT_EQUAL_INT32(sizeof(data),
				ext_full_payload_data_size);

	TEST_ASSERT_EQUAL_MEMORY(
		data,
		ext_full_payload_data,
		ext_full_payload_data_size);
}


void test_pt_ext_tx_wait_after_nack_received(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 4];

	// reset the pt_ext 
	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);



	r = pt_extended_send(pt,
			     data, 
			     sizeof(data),
			     tp_ext_tx_done_callback_test);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);


	pt_extended_tx_run(pt, 1); // send start packet
	r = pt_receiver_run(pt, 1); // handle nack
	pt_extended_tx_run(pt, 1); // send first payload packet
	byte_fifo_reset(ftx); // simulate packet lost :D

        // send nack
	pt_extended_send_response(pt, false); 
	pt_extended_tx_run(pt, 1); 

	// receive nack
	r = pt_receiver_run(pt, 1); // handle nack
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// now tx should be in wait for timeout state
	TEST_ASSERT_EQUAL_INT32(PT_EXT_TX_STATE_WAIT_IDLE_TIMEOUT,
				pt->pt_ext_tx.tx_state);


	// it should still be dropping packets after 2ms delay
	r = pt_receiver_run(pt, 1); // handle nack
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// now tx should be in wait for timeout state
	TEST_ASSERT_EQUAL_INT32(PT_EXT_TX_STATE_WAIT_IDLE_TIMEOUT,
				pt->pt_ext_tx.tx_state);

	// it should go back to idle after p->timeout_tx_ms delay
	pt_extended_tx_run(pt, pt->timeout_tx_ms);

	// now tx should be in wait for timeout state
	TEST_ASSERT_EQUAL_INT32(PT_EXT_TX_STATE_SEND_PAYLOAD_PACKET,
				pt->pt_ext_tx.tx_state);


	pt_extended_tx_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_EXT_TX_STATE_WAIT_RSP,
				pt->pt_ext_tx.tx_state);

	// just for fun test if we can receive the packet:)
	TEST_ASSERT_EQUAL_INT32(0,
				ext_full_packet_cb_cnt); 

	r = pt_receiver_run(pt, 1); // handle nack
	pt_extended_tx_run(pt, 1); // send first payload packet


	TEST_ASSERT_EQUAL_INT32(1,
				ext_full_packet_cb_cnt); 

	TEST_ASSERT_EQUAL_INT32(sizeof(data),
				ext_full_payload_data_size);

	TEST_ASSERT_EQUAL_MEMORY(
		data,
		ext_full_payload_data,
		ext_full_payload_data_size);

}

// TEST mixed pico and ext packets
void test_pt_pico_ext_mix(void)
{
	enum pt_errors r;
	uint8_t data[pt->max_packet_payload_size * 4];
	uint8_t pico_data[32];

	// reset the pt_ext 
	pt_extended_tx_full_packet_done_cleanup(pt);
	pt_extended_rx_full_packet_done_cleanup(pt);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_cb);

	uint32_t tmp = callback_cnt;
	pt_pico_register_rx_callback(pt, NULL, 
				      pt_pico_packet_rx_complete);

	r = pt_pico_send(pt, pico_data, sizeof(pico_data));
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	TEST_ASSERT_EQUAL_UINT32(tmp+1, callback_cnt);

	// make ext start packet and send it
	pt->pt_ext_tx.tx_state = PT_EXT_TX_STATE_SEND_START_PACKET;
	pt->pt_ext_tx.data = data;
	pt->pt_ext_tx.data_size = sizeof(data);

	struct pt_extended_start_packet_header hs;

	pt_extended_fill_start_packet_header(
		pt, &hs, pt->max_packet_payload_size);

	pt_extended_sent_start_packet(
		pt, &hs, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	// all bytes should be used by tx/rx (it is same fifo)
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

	// receiver should be in state waiting new packet
	TEST_ASSERT_EQUAL_UINT8(PT_RX_WAITING_FIRST_BYTE,
				pt->pt_receive_state);

	
	r = pt_pico_send(pt, pico_data, sizeof(pico_data));
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_UINT32(tmp+2, callback_cnt);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);

	// generate payload packet with foo header crc
	struct pt_extended_payload_packet_header hp;

	pt_extended_fill_payload_packet_header(
		pt, &hp, pt->max_packet_payload_size);

	pt_extended_sent_payload_packet(
		pt, &hp, pt->max_packet_payload_size);

	r = pt_receiver_run(pt, 1);
	TEST_ASSERT_EQUAL_INT32(PT_NO_ERROR, r);
	TEST_ASSERT_EQUAL_INT32(0, 
				byte_fifo_get_fill_count(pt->tx_fifo));

}

// TODO
// check the tx data already sent variable
// clean tx timers when sending a ext message out
// clean tx timers when new message received
// TEST !all the timers!
// TEST request_memory not enought memory
// TEST if part of payload/header is missing (timeout)
// TEST for a missing packet (seq number bigger than expected)