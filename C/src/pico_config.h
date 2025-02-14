#ifndef PICO_CONFIG_H
#define PICO_CONFIG_H

#include <inttypes.h>
#include <stdbool.h>

enum pico_config_errors {
        PC_NO_ERROR = 0,
        PC_ERROR_ARGS = 1,
        PC_ERROR_UNKNOWN_ID = 2,
        PC_ERROR_DATA_NOT_READY = 3,
        PC_ERROR_PAYLOAD_OUT_OF_BOUNDS = 4,
        PC_ERROR_UNKNOWN_PAYLOAD = 5,
        PC_ERROR_TIMEOUT = 6,
        PC_ERROR_NACK_RECEIVED = 7,
        PC_NO_CALLBACK = 8,
        PC_SKIP_RESPONSE = 0xff,
};

struct pico_config;

struct pico_config_settings {
        void *(*pc_malloc)(size_t);
        uint32_t max_req_rsp_time;
};

struct pico_config_request_response_handler {
        uint8_t id;
        int32_t (*request_handler)(struct pico_config *pc, 
				   uint8_t *data_in, 
				   size_t data_in_size, 
				   size_t max_out_data_size, 
				   uint8_t *data_out, 
				   size_t *data_out_size);

        void (*response_handler)(struct pico_config *pc, 
				 enum pico_config_errors status, 
				 uint8_t *data_in, 
				 size_t data_in_size);
};

struct pico_config *pico_config_init(struct pico_config_settings *pcs);

int32_t pico_config_send_request(struct pico_config *pc, int8_t id, 
                                 uint8_t *data, size_t data_size, 
				 bool wait_for_ack);

void pico_config_receive(struct pico_config *pc, 
			 uint8_t *data, size_t data_size);

//int32_t pico_config_receive(struct pico_config *pc, 
//			    uint8_t *data, size_t data_size);


void pico_config_run(struct pico_config *pc, 
		     uint32_t time_from_last_call);

void *pico_config_get_low_layer_drv_data(struct pico_config *pc);

void pico_config_register_tx(struct pico_config *pc, 
			     void *drv, 
			     int32_t (*tx)(void *low_layer_obj, 
					   uint8_t *data, size_t data_size));


void pico_config_set_handlers_map(struct pico_config *pc,
				  struct pico_config_request_response_handler *map,
				  size_t map_size);

#endif
