// SPDX-License-Identifier: EUPL-1.2
/* Copyright Mitran Andrei-Gabriel 2023 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <libaio.h>
#include <fcntl.h>

#include "util/aws.h"
#include "util/util.h"
#include "util/debug.h"
#include "util/lin/sock_util.h"
#include "util/lin/w_epoll.h"
#include "util/http-parser/http_parser.h"
#include "http_helper.h"

#define MAX_EVENTS 1

#define uint unsigned int
#define ulong unsigned long
#define OK_REPLY "HTTP/1.1 200 OK\r\n\r\n"
#define ERR_REPLY "HTTP/1.1 404 Not Found\r\n\r\n"
#define END "\r\n\r\n"

#define REC 0
#define PART_REC 1
#define SENT 2
#define PART_SENT 3

#define NON_VALID 0
#define STATIC 1
#define DYNAMIC 2

http_parser request_parser;
char request_path[BUFSIZ];

struct buffer {
	char buff[BUFSIZ];
	uint len;
};

struct dynamic_buffs {
	char **buffs;
	uint last_buff_len;
};

struct dynamic_cnt {
	uint nr_recv;
	uint nr_sent;
	uint nr_submit;
	uint nr_total;
};

/* Connection handler */
struct connection {
	int socket;

	/* Buffers */
	struct buffer recv_buff;
	struct buffer send_buff;

	uint fd;
	uint file_size;

	uint bytes_sent;
	off_t offset;

	struct dynamic_buffs dynamic_buffs;
	struct dynamic_cnt dynamic_cnt;

	uint type;
	uint step;

	int eventfd;

	io_context_t context;

	struct iocb *iocb;
	struct iocb **iocb_ptr;
};

/* Server socket fd */
static int listenfd;

static int epollfd;

/*
 * Initializes the connection handler
 */
static struct connection *init_conn(int socket)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(!conn, "conn malloc failed");

	memset(&conn->context, 0, sizeof(io_context_t));
	DIE(io_setup(MAX_EVENTS, &conn->context) < 0, "context io_setup failed");

	conn->socket = socket;

	conn->step = conn->type = conn->offset = conn->recv_buff.len =
		conn->send_buff.len = conn->bytes_sent = conn->dynamic_cnt.nr_recv =
			conn->dynamic_cnt.nr_submit = conn->dynamic_cnt.nr_total =
				conn->dynamic_cnt.nr_sent = conn->dynamic_buffs.last_buff_len
					= 0;

	conn->eventfd = eventfd(0, EFD_NONBLOCK);
	DIE(conn->eventfd < 0, "eventfd failed");

	memset(conn->recv_buff.buff, 0, BUFSIZ);
	memset(conn->send_buff.buff, 0, BUFSIZ);

	return conn;
}

/*
 * Frees the connection hadler, closing the socket
 */
static void conn_close(struct connection *conn, int fd)
{
	DIE(w_epoll_remove_ptr(epollfd, fd, conn) < 0,
			"w_epoll_remove_ptr failed");

	DIE(io_destroy(conn->context) < 0, "io_destroy failed");

	close(conn->socket);
	close(conn->fd);

	free(conn);
}

/*
 * Handles a new request on the socket
 */
static void handle_new_connection(void)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);

	/* Accepts a new connection */
	int socket = accept(listenfd, (SSA *)&addr, &addrlen);

	DIE(socket < 0, "accept failed");

	/* Sets the flags, making the socket non-blocking */
	fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) | O_NONBLOCK);

	struct connection *conn;

	conn = init_conn(socket);

	/* Adds the socket to epoll */
	DIE(w_epoll_add_ptr_in(epollfd, socket, conn) < 0,
		"w_epoll_add_ptr_in failed");
}

static uint send_message(struct connection *conn)
{
	int bytes_sent;

	/* Sends the data */
	bytes_sent = send(conn->socket, conn->send_buff.buff + conn->bytes_sent,
		conn->send_buff.len - conn->bytes_sent, 0);
	DIE(bytes_sent <= 0, "send failed");

	/* Not all bytes were sent */
	conn->bytes_sent += bytes_sent;
	if (conn->bytes_sent < conn->send_buff.len)
		return PART_SENT;

	return SENT;
}

/*
 * Receives the HTTP request
 */
static uint receive_request(struct connection *conn)
{
	int bytes_recv;

	/* Receives the data */
	bytes_recv = recv(conn->socket, conn->recv_buff.buff + conn->recv_buff.len,
		BUFSIZ - conn->recv_buff.len, 0);
	DIE(bytes_recv <= 0, "recv failed");

	conn->recv_buff.len += bytes_recv;

	conn->recv_buff.buff[conn->recv_buff.len] = 0;

	/* Not all bytes were received */
	if (strcmp(conn->recv_buff.buff + conn->recv_buff.len - 4, END) != 0)
		return PART_REC;

	int bytes_parsed;

	/* Initializes the parser */
	http_parser_init(&request_parser, HTTP_REQUEST);

	/* Parses the data */
	bytes_parsed = http_parser_execute(&request_parser,
		&settings_on_path, conn->recv_buff.buff, conn->recv_buff.len);
	DIE(bytes_parsed <= 0, "http_parser_execute failed");

	return REC;
}

/*
 * Puts the HTTP reply header
 */
static void put_header(struct connection *conn, uint error)
{
	char *header;
	char error_reply[BUFSIZ] = ERR_REPLY;
	char ok_reply[BUFSIZ] = OK_REPLY;

	if (error)
		header = error_reply;
	else
		header = ok_reply;

	conn->send_buff.len = strlen(header);
	memcpy(conn->send_buff.buff, header, strlen(header));
}

/*
 * Handles a client request
 */
static void handle_cl_request(struct connection *conn)
{
	if (receive_request(conn) == PART_REC)
		return;

	char static_pref[BUFSIZ] = AWS_DOCUMENT_ROOT;
	char dynamic_pref[BUFSIZ] = AWS_DOCUMENT_ROOT;

	strcat(static_pref, "static/");
	strcat(dynamic_pref, "dynamic/");

	/* Adds the socket to epoll for out events */
	DIE(w_epoll_update_ptr_out(epollfd, conn->socket, conn) < 0,
		"w_epoll_update_ptr_out failed");

	/* Opens the input file. */
	conn->fd = open(request_path, O_RDONLY);

	/* The file was not opened */
	if (conn->fd == -1) {
		conn->type = NON_VALID;
		put_header(conn, 1);
		return;
	}

	/* Gets the file's size */
	struct stat stat_buf;

	fstat(conn->fd, &stat_buf);
	conn->file_size = stat_buf.st_size;

	/* Sets the request's type */
	if (!strncmp(request_path, static_pref, strlen(static_pref))) {
		put_header(conn, 0);
		conn->type = STATIC;
		conn->step = 0;
	} else if (!strncmp(request_path, dynamic_pref, strlen(dynamic_pref))) {
		put_header(conn, 0);
		conn->type = DYNAMIC;
		conn->step = 0;
	} else {
		put_header(conn, 1);
		conn->type = NON_VALID;
		return;
	}
}

static void sendfile_async(struct connection *conn)
{
	int buff_cnt = conn->file_size / BUFSIZ;
	int bytes_cnt;
	uint is_multiple = 1;

	conn->dynamic_buffs.last_buff_len = BUFSIZ;

	/* The file_size is not a multiple of BUFSIZ */
	if (conn->file_size % BUFSIZ) {
		conn->dynamic_buffs.last_buff_len =
			conn->file_size - buff_cnt * BUFSIZ;
		++buff_cnt;
		is_multiple = 0;
	}

	conn->iocb = malloc(buff_cnt * sizeof(struct iocb));
	DIE(!conn->iocb, "iocb malloc failed");
	conn->iocb_ptr = malloc(buff_cnt * sizeof(struct iocb *));
	DIE(!conn->iocb_ptr, "iocb_ptr malloc failed");

	conn->dynamic_buffs.buffs = malloc(buff_cnt * sizeof(char *));
	DIE(!conn->dynamic_buffs.buffs, "dynamic send buffers malloc failed");

	for (int i = 0; i < buff_cnt; i++) {
		conn->dynamic_buffs.buffs[i] = malloc(BUFSIZ * sizeof(char));
		DIE(!conn->dynamic_buffs.buffs[i],
			"dynamic send buffer malloc failed");
		conn->iocb_ptr[i] = &conn->iocb[i];

		bytes_cnt = BUFSIZ;

		/* The file_size was not a multiple of BUFSIZ,
		 * so the last buffer has less bytes
		 */
		if (i == buff_cnt - 1 && !is_multiple)
			bytes_cnt = conn->file_size - conn->offset;

		io_prep_pread(&conn->iocb[i], conn->fd, conn->dynamic_buffs.buffs[i],
			bytes_cnt, conn->offset);

		conn->offset += bytes_cnt;

		io_set_eventfd(&conn->iocb[i], conn->eventfd);
	}

	DIE(w_epoll_remove_ptr(epollfd, conn->socket, conn) < 0,
		"w_epoll_remove_ptr failed");

	int nr = io_submit(conn->context, buff_cnt - conn->dynamic_cnt.nr_submit,
		conn->iocb_ptr + conn->dynamic_cnt.nr_submit);

	DIE(nr < 0, "io_submit failed");

	conn->dynamic_cnt.nr_submit += nr;

	DIE(w_epoll_add_ptr_in(epollfd, conn->eventfd, conn) < 0,
		"w_epoll_add_ptr_in failed");

	conn->dynamic_cnt.nr_total = buff_cnt;
}

/* EPOLL_IN notification was received */
void in(struct connection *conn)
{
	switch (conn->type) {
		case NON_VALID: {
			handle_cl_request(conn);

			break;
		}
		case STATIC: {
			handle_cl_request(conn);

			break;
		}
		case DYNAMIC: {
			struct io_event events[conn->dynamic_cnt.nr_submit];
			ulong eventfd;

			DIE(read(conn->eventfd, &eventfd, sizeof(eventfd)) < 0,
				"read failed");

			DIE(io_getevents(conn->context, eventfd, eventfd, events, NULL)
				!= eventfd, "io_getevents failed");
			conn->dynamic_cnt.nr_recv += eventfd;

			DIE(w_epoll_add_ptr_out(epollfd, conn->socket, conn) < 0,
				"w_epoll_add_ptr_out failed");

			break;
		}
		default: {
			exit(-1);
		}
	}
}

void dynamic_final(struct connection *conn, uint *do_return)
{
	if (conn->dynamic_cnt.nr_sent < conn->dynamic_cnt.nr_recv) {
		memcpy(conn->send_buff.buff,
			conn->dynamic_buffs.buffs[conn->dynamic_cnt.nr_sent], BUFSIZ);

		conn->send_buff.len = BUFSIZ;

		/* The last buffer was reached, it may not be BUFSIZ */
		if (conn->dynamic_cnt.nr_sent == conn->dynamic_cnt.nr_submit - 1)
			conn->send_buff.len = conn->dynamic_buffs.last_buff_len;

		if (send_message(conn) == PART_SENT) {
			*do_return = 1;
			return;
		}

		++conn->dynamic_cnt.nr_sent;
		conn->bytes_sent = 0;
	}

	if (conn->dynamic_cnt.nr_sent == conn->dynamic_cnt.nr_recv) {
		DIE(w_epoll_remove_ptr(epollfd, conn->socket, conn) < 0,
			"w_epoll_remove_ptr failed");

		if (conn->dynamic_cnt.nr_submit < conn->dynamic_cnt.nr_total) {
			int nr = io_submit(conn->context,
				conn->dynamic_cnt.nr_total - conn->dynamic_cnt.nr_submit,
					conn->iocb_ptr + conn->dynamic_cnt.nr_submit);

			DIE(nr < 0, "io_submit failed");

			conn->dynamic_cnt.nr_submit += nr;
		}
	}

	if (conn->dynamic_cnt.nr_sent == conn->dynamic_cnt.nr_total) {
		for (int i = 0; i < conn->dynamic_cnt.nr_submit; i++)
			free(conn->dynamic_buffs.buffs[i]);
		free(conn->dynamic_buffs.buffs);

		conn_close(conn, conn->eventfd);
	}
}

/* EPOLL_OUT notification was received */
void out(struct connection *conn)
{
	switch (conn->type) {
		case NON_VALID: {
			if (send_message(conn) == PART_SENT)
				return;

			conn_close(conn, conn->socket);

			break;
		}
		case STATIC: {
			switch (conn->step) {
				case 0: {
					if (send_message(conn) == PART_SENT)
						return;

					conn->step = 1;
					conn->bytes_sent = 0;

					break;
				}
				case 1: {
					int bytes_cnt = BUFSIZ;

					if (conn->file_size - conn->offset <= BUFSIZ)
						bytes_cnt = conn->file_size - conn->offset;

					int bytes_sent =
						sendfile(conn->socket, conn->fd,
							&conn->offset, bytes_cnt);

					DIE(bytes_sent < 0, "sendfile failed");

					conn->bytes_sent += bytes_sent;

					if (!bytes_sent)
						conn_close(conn, conn->socket);

					break;
				}
				default: {
					exit(-1);
				}
			}

			break;
		}
		case DYNAMIC: {
			switch (conn->step) {
				case 0: {
					if (send_message(conn) == PART_SENT)
						return;

					conn->step = 1;
					conn->bytes_sent = 0;

					break;
				}
				case 1: {
					sendfile_async(conn);

					conn->step = 2;

					break;
				}

				case 2: {
					uint do_return;

					dynamic_final(conn, &do_return);

					if (do_return)
						return;

					break;
				}
				default: {
					exit(-1);
				}
			}

			break;
		}
		default: {
			exit(-1);
		}
	}
}

int main(void)
{
	/* Initializes multiplexing */
	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create failed");

	/* Creates a server socket */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener failed");

	DIE(w_epoll_add_fd_in(epollfd, listenfd), "w_epoll_add_fd_in failed");

	/* Main loop */
	while (1) {
		struct epoll_event rev;

		/* Waiting for events */
		DIE(w_epoll_wait_infinite(epollfd, &rev) < 0,
			"w_epoll_wait_infinite failed");

		/*
		 * Considers:
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */
		struct connection *conn = rev.data.ptr;

		if (rev.data.fd == listenfd) {
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else if (rev.events & EPOLLIN) {
			in(conn);
		} else if (rev.events & EPOLLOUT) {
			out(conn);
		}
	}

	return 0;
}
