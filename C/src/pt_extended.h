#ifndef PT_EXTENDED_H
#define PT_EXTENDED_H

#define PT_EXT_START_PACKET_SIZE 10

enum pt_ext_tx_rsp_status {
	PT_EXT_TX_DONE,
	PT_EXT_TX_TIMEOUT,
};

void pt_extended_receiver_reset(struct pt *p);

enum pt_errors 
pt_extended_send(struct pt *p, 
		 uint8_t *data, 
		 size_t data_size,
		 void (*done_callback)(enum pt_ext_tx_rsp_status));


void pt_extended_tx_run(struct pt *p, uint32_t time_from_last_call_ms);

#endif