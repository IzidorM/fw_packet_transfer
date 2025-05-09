#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include "socket_interface.h"

int32_t receive_data(struct connection *c)
{
	if (NULL == c->rxf)
	{
		printf("Uninitialized fifo\n");
		return 0;
	}

	uint16_t fs = byte_fifo_get_free_space(c->rxf);

	if (0 == fs)
	{
		return 0;
	}

	uint8_t data_buff[fs];

	int n = recv(c->connfd, data_buff, fs, 0);

        //int n = recvfrom(c->connfd, data_buff, fs, 0,
	//		 //0, (struct sockaddr *) &cliaddr, &clilen);
	//		 (struct sockaddr *) & c->addr, &c->sock_len); 

	if ( n > 0)
	{
		for(uint32_t i = 0; n > i; i++)
		{
			byte_fifo_write(c->rxf, data_buff[i]);
		}
		printf("data received %i\n", n);
	}
	else if (n == 0)
	{
		// Connection closed by client
		printf("Disconnected (socket closed)\n");
		return -1;  // Return a special value indicating disconnection
	}
	else
	{
		//if (EAGAIN == errno  || EWOULDBLOCK == errno)
		//{
		//	// no data on the socket, just skip
		//	n = 0;
		//}

		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno)
		{
			// no data on the socket, just skip
			n = 0;
		}
		else
		{
			printf("Socket error: %d - %s\n", errno, strerror(errno));
			return -1;  // Signal connection issue
		}
	}


        //for (uint32_t i = 0; n > i; i++)
        //{
        //        printf(" %i\n", data_buffer[i]);
        //}

        return n;
}

int32_t send_data(struct connection *c)
{
	if (NULL == c->txf)
	{
		printf("Uninitialized fifo\n");
		return 0;
	}

        //printf("\n");
        //for (uint32_t i = 0; l > i; i++)
        //{
        //        printf(" %i\n", d[i]);
        //}

	// TODO: This can fail if sendto cant send all of the data 
	// taken out of the fifo :)
	uint16_t fs = byte_fifo_get_fill_count(c->txf);
	if (0 == fs)
	{
		return 0;
	}
	printf("Sending %i bytes\n", fs);

	uint8_t data_buff[fs];
	for(uint32_t i = 0; fs > i; i++)
	{
		data_buff[i] = byte_fifo_read(c->txf);
	}

        //uint32_t n = sendto(c->connfd, data_buff, fs, 0, 
	//		    (struct sockaddr *) &c->addr, c->sock_len); 

	uint32_t n = send(c->connfd, data_buff, fs, 0);

        //if (n != fs)
        //{
	//	printf("Exiting server tx\n");
        //        return n; 
        //}

	if (n != fs)
	{
		printf("Send incomplete or failed: %d of %d bytes sent. Error: %s\n", 
		       n, fs, strerror(errno));
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			return -1;  // Signal connection issue
		}
		return n; 
	}


        return 0;
}

void connection_close(struct connection *c)
{
	close(c->connfd);
}

int server_wait_for_new_connection(struct connection *c)
{
        struct timeval timeout;      
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;

	printf("Waitint for new connection on port %i\n", 
	       c->addr.sin_port);
	c->connfd = accept(c->listenfd, 
			(struct sockaddr *) &c->addr,
			&c->sock_len);

	if (setsockopt (c->connfd, SOL_SOCKET, 
			SO_RCVTIMEO, (char *) &timeout,
			sizeof(timeout)) < 0)
	{
		printf("setsockopt failed\n");
		return -1;
	}

	if (setsockopt (c->connfd, SOL_SOCKET, 
			SO_SNDTIMEO, (char *) &timeout,
			sizeof(timeout)) < 0)
	{
		printf("setsockopt failed\n");
		return -1;
	}

	printf("New connection\n");
	return 0;
}


struct connection *server_connectivity_init(uint32_t fifo_buff_size)
{
	struct connection *tmp = malloc(sizeof(struct connection));
	if (NULL == tmp)
	{
		return tmp;
	}

        tmp->listenfd = socket(AF_INET,SOCK_STREAM,0);

        int optval = 1;
        setsockopt(tmp->listenfd, SOL_SOCKET, 
		   SO_REUSEADDR, &optval, sizeof(int));

	tmp->sock_len = sizeof(struct sockaddr_in);

        bzero(&tmp->addr, tmp->sock_len);
        tmp->addr.sin_family = AF_INET;
        tmp->addr.sin_addr.s_addr=htonl(INADDR_ANY);
        tmp->addr.sin_port=htons(DEFAULT_PORT);

	int rv = 0;
      	rv = bind(tmp->listenfd, (struct sockaddr *) &tmp->addr,
		  tmp->sock_len);
	if (rv < 0)
	{
		printf("bind to socket port %d failed\n", DEFAULT_PORT);
		return NULL;
	}

        rv = listen(tmp->listenfd, 1024);
	if (rv < 0)
	{
		printf("listen to socket port %d failed\n", DEFAULT_PORT);
		return NULL;
	}

	struct byte_fifo_settings txfs = {
		.my_malloc = malloc,
		.fifo_buff = malloc(fifo_buff_size),
		.fifo_size = fifo_buff_size,
	};

	tmp->txf = byte_fifo_init(&txfs);

	struct byte_fifo_settings rxfs = {
		.my_malloc = malloc,
		.fifo_buff = malloc(fifo_buff_size),
		.fifo_size = fifo_buff_size,
	};

	tmp->rxf = byte_fifo_init(&rxfs);
	return tmp;
}

struct connection *client_connect_to_server(size_t fifo_buff_size,
	char *ip_addr)
{
        int err;
	struct connection *tmp = malloc(sizeof(struct connection));
	if (NULL == tmp)
	{
		return tmp;
	}

	tmp->sock_len = sizeof(struct sockaddr_in);
        bzero(&tmp->addr, tmp->sock_len);

	tmp->addr.sin_family = AF_INET;
	tmp->addr.sin_port = htons(DEFAULT_PORT);

        err = inet_pton(AF_INET, ip_addr, &tmp->addr.sin_addr);
        if (err == 1)
        {
                char tmp_ip_buff[16];
                inet_ntop(AF_INET, &tmp->addr.sin_addr, 
			  tmp_ip_buff, INET_ADDRSTRLEN);

		tmp->addr.sin_port = htons(DEFAULT_PORT); 
        }
        else
        {
                printf("Cant parse ip addr\n");
                return NULL;
        }

	printf("Connecting to ip addr %s, port %i\n", 
	       ip_addr, tmp->addr.sin_port);


        if((tmp->connfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                printf("\n Error : Could not create socket \n");
                return NULL;
        }
        
        struct timeval timeout;      
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;

        if (setsockopt (tmp->connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                        sizeof(timeout)) < 0)
        {
                printf("setsockopt failed\n");
                return NULL;
        }

        if (setsockopt (tmp->connfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                        sizeof(timeout)) < 0)
        {
                printf("setsockopt failed\n");
                return NULL;
        }

        tmp->addr.sin_family = AF_INET;

        if( connect(tmp->connfd, (struct sockaddr *) &tmp->addr, 
		    tmp->sock_len) < 0)
        {
                printf("\n Error : Connect Failed \n");
                return NULL;
        } 

	struct byte_fifo_settings txfs = {
		.my_malloc = malloc,
		.fifo_buff = malloc(fifo_buff_size),
		.fifo_size = fifo_buff_size,
	};

	tmp->txf = byte_fifo_init(&txfs);

	struct byte_fifo_settings rxfs = {
		.my_malloc = malloc,
		.fifo_buff = malloc(fifo_buff_size),
		.fifo_size = fifo_buff_size,
	};

	tmp->rxf = byte_fifo_init(&rxfs);

	if ((NULL == tmp->rxf) || (NULL == tmp->txf))
	{
		return NULL;
	}

        return tmp;
}

// This code returns Send incomplete or failed: -1 of 4 bytes sent. Error: Invalid argument when used on macos. Do you know why?
//
//The error message "Invalid argument" when using `sendto()` on macOS is likely occurring because you're using the wrong function for TCP sockets in `send_data()`.
//
//The issue is:
//
//1. You're creating a TCP socket with `SOCK_STREAM` in both the server and client code:
//   ```c
//   tmp->listenfd = socket(AF_INET, SOCK_STREAM, 0);  // Server
//   tmp->connfd = socket(AF_INET, SOCK_STREAM, 0);    // Client
//   ```
//
//2. But then you're using `sendto()` in your `send_data()` function, which is designed for connectionless sockets (like UDP/SOCK_DGRAM).
//
//3. For TCP/SOCK_STREAM sockets, you should use `send()` instead of `sendto()` since the connection is already established and the destination address is already known.
//
//To fix the issue, replace:
//
//```c
//uint32_t n = sendto(c->connfd, data_buff, fs, 0, 
//                    (struct sockaddr *) &c->addr, c->sock_len);
//```
//
//With:
//
//```c
//uint32_t n = send(c->connfd, data_buff, fs, 0);
//```
//
//The same applies to your `receive_data()` function - you should use `recv()` instead of `recvfrom()` for TCP connections:
//
//```c
//int n = recv(c->connfd, data_buff, fs, 0);
//```
//
//Using `sendto()`/`recvfrom()` with a connection-oriented socket and providing address information that doesn't match the connected peer can result in "Invalid argument" errors specifically on macOS (other systems might behave differently).