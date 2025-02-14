#ifndef PT_PICO_H
#define PT_PICO_H

#define PT_PICO_PACKET_HEADER_SIZE 1
#define PT_PICO_PACKET_TAIL_SIZE 1

#define PT_PICO_MAX_PAYLOAD_LENGTH 64

enum pt_pico_rx_state {
        PT_PICO_RX_STATE_WAITING_HEADER,
        PT_PICO_RX_STATE_WAITING_PAYLOAD,
};

struct pt_pico_receiver_data {
        enum pt_pico_rx_state pico_rx_state;
        
        uint8_t buff[PT_PICO_MAX_PAYLOAD_LENGTH + 2];
        uint8_t buff_data_already_received_cnt;
        uint8_t buff_expected_data_size;
        void *rx_callback_handler;
        void (*callback)(void *rx_callback_handler, uint8_t *data, size_t data_size);
        
};

void pico_rx_reset(struct pt *p);
void pt_pico_receiver_process_header(struct pt *p, uint8_t header);
int32_t pt_pico_receiver_process_payload(struct pt *p, bool *done);

void pt_pico_register_rx_callback(
	struct pt *p,
	void *high_layer_data, 
	void (*high_layer_callback)(void *, uint8_t *, size_t));

#endif