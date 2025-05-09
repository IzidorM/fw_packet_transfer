#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"
#include "socket_interface.h"

#include "byte_fifo.h"
#include "pt.h"
#include "pt_extended.h"

//#define FE_TIMEOUT_DELAY 2   /* every Nth packet should be corrupted*/
//#define FE_TIMEOUT_FREQUENCY 30   /* every Nth packet should be corrupted*/
//
//#define ACK_NACK_SWITCH_FREQUENCY 3 /* every Nth packet should be corrupted*/
//
//static bool fe_enable = false; //true; //false; //true;
//static uint32_t fe_error_freq = 6;
//static uint32_t fe_packet_counter = 0;
//uint32_t force_error(uint8_t *data_buffer, uint32_t buffer_size)
//{
//        if (fe_enable == false)
//        {
//                return 0;
//        }
//        if (fe_error_freq == fe_packet_counter)
//        {
//                uint32_t corrupt_byte_index = rand() % buffer_size;
//                data_buffer[corrupt_byte_index] += 1;
//                //data_buffer[corrupt_byte_index] = 0xff;
//
//                printf("Corrupting byte %i in %i bytes\n", corrupt_byte_index, buffer_size);
//                fe_packet_counter = 0;
//        }
//        fe_packet_counter += 1;
//        return 0;
//}

/* communication handling code start */

static bool send_packet_back = false;
static uint8_t *last_rx_data = NULL;
static size_t last_rx_data_size = 0;
static struct timespec tx_time_start={0,0};

void server_packet_sent_done_cb(enum pt_ext_tx_rsp_status s)
{
	struct timespec tend={0,0};
	clock_gettime(CLOCK_MONOTONIC, &tend);
	double time_passed_s = 
		(((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
		 ((double)tx_time_start.tv_sec + 1.0e-9*tx_time_start.tv_nsec));


	if (last_rx_data)
	{
		free(last_rx_data);
	}

	if (PT_EXT_TX_DONE == s)
	{
		printf("Packet sent sucessfully, time: %f\n", 
		       time_passed_s);
	}
	else
	{
		printf("Packet sent failed\n");
	}
}

void ext_full_packet_received_cb(uint8_t *data, size_t data_size)
{
	last_rx_data = malloc(data_size);
	memcpy(last_rx_data, data, data_size);
	last_rx_data_size = data_size;

	printf("Server: Full packet received of size %zi, sending it back\n", data_size);
	send_packet_back = true;
}

int fake_dlp_server(uint8_t *data, size_t data_size, 
		    size_t default_payload_size)
{
	printf("Fifo sizes: %zi\n", 2 * data_size);

	struct connection *c = server_connectivity_init(data_size * 2);

	struct pt_settings s = {
		.malloc = malloc,

		.tx_fifo = c->txf,
		.rx_fifo = c->rxf,

		.tx_retries = 0,
		.tx_rsp_timeout_ms = 100,
		.rx_timeout_ms = 100,

		.request_memory = (uint8_t *(*)(size_t s)) malloc,
	};

	struct pt *pt = NULL;
	pt = pt_init(&s);

	pt_extended_register_packet_received_callback(
		pt, ext_full_packet_received_cb);

        for(;;)
        {
		int rv = server_wait_for_new_connection(c);
		if (0 != rv)
		{
			continue;
		}

                uint32_t time_passed = 0;
                uint32_t time_passed_from_last_rx = 0;
                int32_t r;

                struct timespec tstart={0,0}, tend={0,0};

                while (1)
                {
                        clock_gettime(CLOCK_MONOTONIC, &tstart);

			r = receive_data(c);
			if (0 > r)
			{
				printf("Connection rx closed: %i -> %i\n",
				       r, errno);

				break;
			}

			r = pt_receiver_run(pt, 1);
			if (PT_NO_ERROR != r)
			{
				printf("E: pt receiver error: %i\n", r);
				break;
			}

			pt_extended_tx_run(pt, 1);

			r = send_data(c);
			if (0 > r)
			{
				printf("Connection tx closed:%i -> %i\n",
				       r, errno);
				break;
				
			}

			if (send_packet_back)
			{
				send_packet_back= false;
				clock_gettime(CLOCK_MONOTONIC, &tx_time_start);
				int32_t r = pt_extended_send(pt,
							     last_rx_data,
							     last_rx_data_size,
							     server_packet_sent_done_cb);
				if (r)
				{
					printf("Sending back ext packet failed: %i\n", r);
				}

			}

			msleep(1);
			
                        clock_gettime(CLOCK_MONOTONIC, &tend);
                        time_passed = 
                                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
                                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1000;

                        time_passed_from_last_rx += time_passed;
                }

		//printf("Time passed: %i\n", time_passed_from_last_rx);

                //if (r)
                //{
                //        fprintf(stderr, "UPLOADING FAILED %i!\n", r);
                //}
                
                printf("Closing socket\n");
		connection_close(c);
                //break;
        }
        return 0;
}

int main(int argc, char **argv)
{
        uint32_t r = 0;

        size_t default_input_data_len = 1024*8;
        size_t default_payload_size = 128;
        int c;

        // Parse arguments
        while ((c = getopt(argc, argv, "p:s:l:f:h")) != -1)
        {
        	switch (c)
        	{
        	case 'p':
                        printf("max payload size: %i\n", atoi(optarg));
                        default_payload_size = atoi(optarg);
                        if (250 < default_payload_size)
                        {
                                printf("max payload size = 250b\n");
                                exit(1);
                        }
        		break;
        	case 's':
                        printf("Seed: %i\n", atoi(optarg));
                        srand(atoi(optarg));
        		break;
        	case 'l':
                        default_input_data_len = atoi(optarg);
                        printf("Data size: %zu\n", default_input_data_len);
        		break;
        	case 'h':
        		printf("Usage flags:\n");
        		printf("-f <filename> - file to transfer\n");
        		return 1;

        	case '?':
        		if (optopt == 'b')
        		{
        			fprintf(stderr, "Option -%c requires <filename> argument\n", optopt);
        		}
        		else if (optopt == 'f')
        		{
        			fprintf(stderr, "Option -%c requires <filename> argument\n", optopt);
        		}
        		else
        		{

        		}
    			return 1;

        	default:
        		abort();
        	}
        }

        uint8_t *rand_data = malloc(default_input_data_len);

        printf("Input rand data:\n");
        for (uint32_t i = 0; default_input_data_len > i; i++)
        {
                rand_data[i] = rand() & 0xff;
                //printf("%i\n", rand_data[i]);
        }
        
        fake_dlp_server(rand_data, default_input_data_len, default_payload_size);

        return r;
}
