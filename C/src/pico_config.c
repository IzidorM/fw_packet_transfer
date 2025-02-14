#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "pico_config.h"

#define PICO_CONFIG_MAX_DATA 64

#define PICO_CONFIG_REQUEST_FLAG (1 << 7)
#define PICO_CONFIG_RESPONSE_FLAG (0 << 7)
#define PICO_CONFIG_ACK_FLAG (1 << 6)
#define PICO_CONFIG_NACK_FLAG (0 << 6)
#define PICO_CONFIG_ENABLE_RESPONSE_FLAG (1 << 6)
#define PICO_CONFIG_DISABLE_RESPONSE_FLAG (0 << 6)

#define ID_MASK 0x3f
#define FLAGS_MASK 0xc0

// packet structure [id (1byte), flags (1byte), payload (up to 8bytes)]
// where flags request/response (bit 7), ack/nack (bit 6)

struct pico_config {
        struct pico_config_request_response_handler *pc_rh_map;
        size_t rh_size;

        void *low_layer_obj;
        int32_t (*tx)(void *low_layer_obj, 
		      uint8_t *data, size_t data_size);

        uint32_t max_req_rsp_time;
        uint32_t time_passed_from_last_request_sent;
        uint8_t expected_rsp_id;
        bool wait_for_rsp;
};

int32_t pico_config_send_generic(struct pico_config *pc, 
				 uint8_t header,
                                 uint8_t *data, size_t data_size)
{
        uint8_t raw_data[data_size + 1];
        raw_data[0] = header;
        uint32_t i;
        for (i = 0; data_size > i; i++)
        {
                raw_data[i+1] = data[i];
        }

        return pc->tx(pc->low_layer_obj, raw_data, sizeof(raw_data));
}

int32_t pico_config_send_request(struct pico_config *pc, int8_t id, 
                                 uint8_t *data, size_t data_size, 
				 bool wait_for_ack_nack)
{
        if (NULL == pc || NULL == pc->tx 
	    || (NULL == data && 0 < data_size) || id > 63)
        {
                return PC_ERROR_ARGS;
        }

        if (pc->wait_for_rsp)
        {
                return PC_ERROR_DATA_NOT_READY;
        }

        uint8_t header = id | PICO_CONFIG_REQUEST_FLAG;

        if(wait_for_ack_nack)
        {
                pc->time_passed_from_last_request_sent = 0;
                pc->wait_for_rsp = true;
                pc->expected_rsp_id = id;
                header |= PICO_CONFIG_ENABLE_RESPONSE_FLAG;
        }

        int32_t r = pico_config_send_generic(pc, header, 
					     data, data_size);
        if (r)
        {
                return r;
        }


        return r;
}

int32_t pico_config_send_response(struct pico_config *pc, 
				  int8_t id, int8_t ack,
                                  uint8_t *data, size_t data_size)
{
        if (NULL == pc || (NULL == data && 0 < data_size))
        {
                return PC_ERROR_ARGS;
        }

        uint8_t header = id | PICO_CONFIG_RESPONSE_FLAG;
        if (ack)
        {
                header |= PICO_CONFIG_ACK_FLAG;
        }


        return pico_config_send_generic(pc, header, data, data_size);
}


static struct pico_config_request_response_handler *
pico_config_search_for_request_handler(struct pico_config *pc, 
				       const uint8_t id)
{
        if (NULL == pc || NULL == pc->pc_rh_map)
        {
                return NULL;
        }

        uint32_t i;
        for (i = 0; pc->rh_size > i; i++)
        {
                if (id == pc->pc_rh_map[i].id)
                {
                        return &pc->pc_rh_map[i];
                }
        }
        return NULL;
}

void pico_config_receive(struct pico_config *pc, 
			    uint8_t *data, size_t data_size)
{
// NOTE: lower layer cant do anything with error messages
// Errors need to be handled by pico_config itself or upper layers...
//        if (NULL == pc || NULL == data || 1 > data_size)
//        {
//                return PC_ERROR_ARGS;
//        }
//
//        if (PICO_CONFIG_MAX_DATA < data_size)
//        {
//                return PC_ERROR_PAYLOAD_OUT_OF_BOUNDS;
//        }

        uint8_t id = data[0] & ID_MASK;
        uint8_t flags = data[0] & FLAGS_MASK;
        uint8_t *raw_data = &data[1];

        if (PICO_CONFIG_REQUEST_FLAG & flags)
        {
                //request received

                struct pico_config_request_response_handler *rh =
                        pico_config_search_for_request_handler(pc, id);
                
                if (rh && rh->request_handler)
                {
                        bool ack = false;
                        uint8_t data_out[PICO_CONFIG_MAX_DATA];
                        size_t data_out_size = 0;

                        int32_t r = rh->request_handler(
				pc, raw_data, data_size-1, 
				PICO_CONFIG_MAX_DATA, data_out, 
				&data_out_size);

                        if (PICO_CONFIG_ENABLE_RESPONSE_FLAG & flags)
                                //if (PC_SKIP_RESPONSE != r)
                        {
                                if (PC_NO_ERROR == r)
                                {
                                        ack = true;
                                }
                                else
                                {
                                        ack = false;
                                        data_out[0] = r;
                                        data_out_size = 1;
                                }
                                pico_config_send_response(
					pc, id, ack, 
					data_out, data_out_size);
                        }
                }
                else
                {
                        uint8_t error_unknown_id = PC_ERROR_UNKNOWN_ID;
                        pico_config_send_response(
				pc, id, false, &error_unknown_id, 1);
                }
        }
        else
        {
                if (pc->expected_rsp_id == id && pc->wait_for_rsp)
                {
                        pc->wait_for_rsp = false;
                        pc->expected_rsp_id = 0;
                        enum pico_config_errors e;
                        if (flags & PICO_CONFIG_ACK_FLAG)
                        {
                                e = PC_NO_ERROR;
                        }
                        else
                        {
                                e = PC_ERROR_NACK_RECEIVED;
                        }

                        struct pico_config_request_response_handler *rh =
                                pico_config_search_for_request_handler(pc, id);
                
                        if (rh)
                        {
                                if (rh->response_handler)
                                {
                                        rh->response_handler(
						pc, e, raw_data,
						data_size - 1);
                                }
                        }
                }
        }

//        return PC_NO_ERROR;
}

void pico_config_run(struct pico_config *pc, 
		     uint32_t time_from_last_call)
{
        if (pc->wait_for_rsp)
        {
                pc->time_passed_from_last_request_sent += 
			time_from_last_call;

                if (pc->max_req_rsp_time < pc->time_passed_from_last_request_sent)
                {
                        pc->wait_for_rsp = false;
                        struct pico_config_request_response_handler *rh =
                                pico_config_search_for_request_handler(pc, 
                                                                       pc->expected_rsp_id);
                
                        if (rh)
                        {
                                if (rh->response_handler)
                                {
                                        rh->response_handler(
						pc, PC_ERROR_TIMEOUT,
						NULL, 0);
                                }
                        }
                        pc->expected_rsp_id = 0;
                }
        }
}


struct pico_config *pico_config_init(struct pico_config_settings *pcs)
{
        if (NULL == pcs || NULL == pcs->pc_malloc)
        {
                return NULL;
        }

        struct pico_config *tmp = 
		pcs->pc_malloc(sizeof(struct pico_config));

        memset(tmp, 0, sizeof(struct pico_config));

        tmp->max_req_rsp_time = pcs->max_req_rsp_time;

        return tmp;
}

void pico_config_set_handlers_map(struct pico_config *pc,
	struct pico_config_request_response_handler *map,
	size_t map_size)
{

	if (NULL == map || 0 == map_size)
	{
		return;
	}

        pc->pc_rh_map = map;
        pc->rh_size = map_size;
}


void *pico_config_get_low_layer_drv_data(struct pico_config *pc)
{
        if (NULL == pc)
        {
                return NULL;
        }
        else
        {
                return pc->low_layer_obj;
        }
}

void pico_config_register_tx(struct pico_config *pc, 
			     void *drv, 
			     int32_t (*tx)(void *low_layer_obj, 
					   uint8_t *data, size_t data_size))
{

        pc->low_layer_obj = drv;
        pc->tx = tx;
}
