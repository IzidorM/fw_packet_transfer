#ifndef SOCKET_INTERFACE_H
#define SOCKET_INTERFACE_H

#define DEFAULT_PORT 11113

#include <arpa/inet.h> 
#include "byte_fifo.h"

struct connection {
	struct byte_fifo *txf;
	struct byte_fifo *rxf;
	struct sockaddr_in addr;
	socklen_t sock_len;
	int listenfd;
	int connfd;
};

int32_t receive_data(struct connection *c);
int32_t send_data(struct connection *c);

struct connection *server_connectivity_init(uint32_t fifo_buff_size);
int server_wait_for_new_connection(struct connection *c);

struct connection *client_connect_to_server(size_t fifo_buff_size,
					    char *ip_addr);

void connection_close(struct connection *c);

#endif