#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h> 
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>

#include "utils.h"
#include "socket_interface.h"

#include "byte_fifo.h"
#include "pt.h"
#include "pt_extended.h"

#define SRV_IP "127.0.0.1" 

static size_t default_input_data_len = 64;

static uint8_t *rand_data = NULL;
//static uint8_t *rx_data_buff = NULL;

static bool send_new_packet = false;

static void ext_full_packet_received_cb(uint8_t *data, size_t data_size)
{
	(void) data;
	(void) data_size;

	printf("Client: Full packet received\n");
}

//static int tx_packet_cnt = 0;
void ext_tx_done_callback(enum pt_ext_tx_rsp_status s)
{
	if (PT_EXT_TX_DONE == s)
	{
		printf("Client: tx done!\n");

		//tx_packet_cnt += 1;
		//if (tx_packet_cnt <= 1)
		//{
		//	send_new_packet = true;
		//}
	}
	else
	{
		printf("Client: tx nack received!\n");
	}
}

struct sockaddr_in serv_addr; 
int sockfd = 0;

void usage(char *p)
{
        printf("Parsing args error");
}

bool stop = false;
bool sent_data = false;
uint8_t *rx_data = NULL;
size_t rx_data_size = 0;

int32_t rx_done(uint8_t *data, size_t data_size)
{
        printf("RX done %zu!\n", data_size);

//        rx_data = data;
//        rx_data_size = data_size;
//
//        if (rand_data)
//        {
//                if (0 == memcmp(rand_data, rx_data_buff, default_input_data_len))
//                {
//                        printf("Data ok!\n");
//                        sent_data = true;
//                }
//                else
//                {
//                        printf("Data NOT ok!\n");
//                }
//        }

        //stop = true;
        return 0;
}

int main(int argc, char **argv)
{
        int32_t r = 0;
        bool s_flag = 0;
        size_t default_payload_size = 64;
        int c;

        // Parse arguments
        while ((c = getopt(argc, argv, "p:s:l:h")) != -1)
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
        		s_flag = true;
        		int32_t seed = atoi(optarg);
                        printf("Seed: %i\n", seed);
                        srand(seed);
        		break;
        	case 'l':
                        default_input_data_len = atoi(optarg);
                        printf("Data size: %zu\n", default_input_data_len);
        		break;
        	case 'h':
        		printf("Usage:\n");
        		printf("fake_dlp_client -f <filename>");
        		return 1;

        	case '?':
        		if (optopt == 'f')
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

        if (s_flag)
        {
                rand_data = malloc(default_input_data_len);
                for (uint32_t i = 0; default_input_data_len > i; i++)
                {
                        rand_data[i] = rand() & 0xff;
                        //printf("%i\n", rand_data[i]);
                }
        }
        else
        {
                printf("Missing data to send\n");
                return 1;
        }

	printf("Fifo sizes: %zi\n", default_input_data_len);

        do {
		char *t = SRV_IP;
		struct connection *conn = client_connect_to_server(
			2*default_input_data_len,
			t);

                if (NULL == conn) {
                        printf("Can't connect to the server\n");
                        break;
                }

                printf("Connected to the server!\n");

		struct pt_settings s = {

			.malloc = malloc,

			.tx_fifo = conn->txf,
			.rx_fifo = conn->rxf,

			.tx_retries = 0,
			.tx_rsp_timeout_ms = 100,
			.rx_timeout_ms = 100,

			.request_memory = (uint8_t *(*)(size_t s)) malloc,
		};

		struct pt *pt = pt_init(&s);
		if (NULL == pt)
		{
                        printf("Can't initialize packet transfer layer\n");
                        break;
		}

		pt_extended_register_packet_received_callback(
			pt, ext_full_packet_received_cb);

		// sending ext packet
		r = pt_extended_send(pt,
				     rand_data,
				     default_input_data_len,
				     ext_tx_done_callback);

		printf("Starting while loop\n");
		send_new_packet = true;

                while (false == stop)
                {
                        //clock_gettime(CLOCK_MONOTONIC, &tstart);

			if (send_new_packet)
			{
				send_new_packet = false;
				r = pt_extended_send(pt,
						     rand_data,
						     default_input_data_len,
						     ext_tx_done_callback);

			}

			pt_extended_tx_run(pt, 1);

			r = send_data(conn);
			if (0 > r)
			{
				printf("Connection tx closed:%i -> %i\n",
				       r, errno);
				break;
				
			}

			r = receive_data(conn);
			if (0 > r)
			{

				printf("Connection rx closed:%i -> %i\n",
				       r, errno);

				break;
			}


			r = pt_receiver_run(pt, 1);
			if (PT_NO_ERROR != r)
			{
				printf("E: pt receiver error: %i\n", r);
				break;
			}
			msleep(1);

                        //struct timespec ts = {
                        //        .tv_sec = 0,
                        //        .tv_nsec = 1 * (1000 * 1000),
                        //};
                        //nanosleep(&ts, NULL);
                        //time_passed += 1;

                        //clock_gettime(CLOCK_MONOTONIC, &tend);
                        //time_passed = 
                        //        (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
                        //         ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1000;
                        //time_passed_from_last_rx += time_passed;

                }
		printf("Done\n");
		connection_close(conn);

        } while (0);

        return r;
}
