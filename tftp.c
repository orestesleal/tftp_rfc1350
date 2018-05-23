/*
 * A compliant (rfc1350) client implementation of the network
 * protocol Trivial File Tranfer Protocol, TFTP rev 2 [1]
 *
 * Copyright Orestes Leal Rodriguez 2016 <olealrd1981@gmail.com>
 *
 * The original standard document for tftp was described in rfc783
 * June, 1981, then in July, 1992, rfc1350 [1], renders obsolete the
 * first original rfc,  this tftp attempts to conforms to rfc1350
 * only.
 *
 * rfc1350 was updated by rfcs 1782, 1784, 1785, 2347, 2348 and 2349.
 * 
 * References
 *
 * [1] The TFTP Protocol (v2) rfc1350, http://tools.ietf.org/html/rfc1350
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <limits.h>
#include <libgen.h>
#include "tftp.h"

static inline size_t send_ack(int sk, struct sockaddr_in * sa,
									size_t block_num);
size_t is_data_pkt(const char * tb);
size_t is_error_pkt(const char * tb);
static inline size_t copy_tftp_data(size_t blk_size, char * data,
									const char * file, size_t mode);

struct tftp_packet * make_tftp_request_packet (const char *str_filename, const
	 char *str_mode, u16s type_opcode, size_t *stp);

struct tftp_data_packet *make_data_packet(void);

static inline void crlf2lf(char *data, size_t bs);
void * tftp_alloc(size_t size);
void usage(const char *argv);
size_t tftp_read_control(int sock, struct sockaddr_in *s_addr, size_t mode,
											const char *file, tftp_stats *st);
size_t set_skio_timeout(int sock, size_t ts, size_t tms);
size_t tftp_write_control(int sock, struct sockaddr_in * s_addr,
							size_t mode, const char * file,
							tftp_stats * st);
size_t get_file_size(const char * file);

tftp_error_packet *
create_error_packet(const char * msg, u16s error_code, u16s *bts);
size_t send_tftp_error(int sock, struct sockaddr_in *dst,
										const char *msg, u16s err_code);
ssize_t check_data_block(const void * hdr, u16s block);
static inline ssize_t check_ack(const void* hdr, size_t block);



void * get_memory(unsigned int size);
void * create_request(char *file, char *mode, char t, unsigned short opcode,
  unsigned int block_size);

/*
 *  TFTP RRQ/WRQ packet
 */
struct Request_Packet
{
    unsigned short Opcode;
    void *Filename;
    char *Mode;
};


/*
 * DATA Packet
 */
struct Data_Packet {
     unsigned short Opcode;
     unsigned short Block;
     char Data;
};

#define REQUEST_PACKET 0
#define DATA_PACKET    1
#define ACK_PACKET     2
#define ERROR_PACKET   3

#define DEFAULT_BLOCK_SIZE 512

#define LEN(s1,s2) strnlen(s1, 255) + strnlen(s2, 255)

/* 
 * Calculate the size of a Request Packet
 */
#define LEN_REQ(p) LEN(p->Filename, p->Mode) + 4

/*
   Log to FD and acknowledge error when sending data block block "blk"
	 NOTE: all "fd" parameters thrown here must be of type "FILE *"
	       and blk must be an int
*/
#define LOG_ACK_ERROR(fd, blk) \
  fprintf(fd, "error: failed to acknowledge data block #%d\n", blk);

/* compute offsets starting at address BASE, and adding offsets o1 & o2
   this is used by the packet creation facilites to resolve offsets
	 into a packet */
#define GET_OFFSET(base,o1,o2) (void *)base+o1+o2

/* set the opcode for a tftp request packet */
#define SET_OPCODE(packet,op) *(unsigned short *)packet = htons(op);

/* macro to send a datagram packet */
#define SEND_PACKET(socket, buffer, count, sock_struct) \
 sendto(socket, buffer, count, 0, (struct sockaddr *)sock_struct, \
        sizeof(struct sockaddr_in))

/* receive one ACK or ERROR packet */
#define RECV_ERR_ACK_PACKET(socket, buffer, sock_struct, addrlen) \
recvfrom(socket, buffer, sizeof(struct ack_error_packet),	0, \
        (struct sockaddr *)&sock_struct, addrlen)

int main(int argc, char * argv[])
{
	char file_name[PATH_MAX];      /* max length of filename */
	int ch, sock;
	struct sockaddr_in s_addr;	   /* sk struct with data about the tftp server */
	tftp_stats st;				         /* statistics */
	size_t op = NULL_OP; 			     /* read or write operation */
	size_t mode = NETASCII_MODE;   /* netascii mode is ON by default */

	if (argv[1] && !strcmp(argv[1], "--help")) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	bzero(&s_addr, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(TFTP_DEFAULT_PORT);

	while ((ch = getopt(argc, argv, "s:or:w:")) != -1)
	{
		switch (ch)
		{
		case 'o': /* octet mode selected */
			mode = OCTECT_MODE;
			break;

		case 's': /* check if the ipv4 address is valid */
			if (inet_pton(AF_INET, optarg, &s_addr.sin_addr) != 1) {
			  fprintf(stderr, "%s: %s, invalid ipv4 address\n", argv[0], optarg);
			  exit(EXIT_FAILURE);
			}
			break;

		case 'w':
			strncpy(file_name, optarg, PATH_MAX-1);
			op = WRITE_OP;
			break;

		case 'r':
			strncpy(file_name, optarg, PATH_MAX-1);
			op = READ_OP;
			break;

		case '?':
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!op) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

  /* create the udp socket and get a descriptor from sucessful call */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("datagram socket()");
		exit(EXIT_FAILURE);
	}

  /*
	 set timeout for the socket, TODO: adjust this when conforming with
	 the rfc dealing with configurable timeouts
	*/
	if (set_skio_timeout(sock, 60, 900000)) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	/* select between Write (send) and Read (receive) based on the
   	 operation selected on the command line parameter */
	if (op == READ_OP) {
		if (tftp_read_control(sock, &s_addr, mode, file_name, &st)) {
		  fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	else {
		if (tftp_write_control(sock, &s_addr, mode, file_name, &st) == WRITE_FAIL) {
		  fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (op == READ_OP) {
		printf("%.0f bytes recv (%.1f kbytes) (%d blocks) (%d retr)\n",
		                                                    st.bytes_rcvd,
	                                                      st.bytes_rcvd / 1024,
		                                                    st.blk_rcvd,
	                                                      st.retr_num);
	} else {
		printf("%.0f bytes sent (%.1f kbytes) (%d blocks) (%d retr)\n",
                                                        st.bytes_sent,
																												st.bytes_sent / 1024,
																												st.blk_sent,
																                        st.retr_num);
	}

	close(sock);
	return EXIT_SUCCESS;
}


/*
  Create and send an ACK packet
	=============================

	Send one ack packet to acknowledge a data block received, this one is used
	when reading a file from the server, in this situation we receive data blocks
  and send acks, the format of the ack packet is the following:

               2 bytes     2 bytes
               ---------------------
              | Opcode |   Block #  |
               ---------------------
                  ACK packet

	ack: 		    the ack packet being sent
	sa: 		    the server information (remote tid, etc.)
	block_num:	the data block to acknowledge

	NOTE: unlike a tftp request packet, the ack packets are allocated using
	      the stack since they are of fixed length and because sendto(2) is
				called inside this function.
*/
static inline size_t send_ack(int sk, struct sockaddr_in * sa, size_t block_num)
{
	struct tftp_ack_pkt ack;
	ack.opcode = htons(TFTP_ACK_PACKET);
	ack.block_n = htons(block_num);

  return SEND_PACKET(sk, &ack, sizeof(struct tftp_ack_pkt), sa);
}


/*
  Create a TFTP Request Packet.
	============================

	Normally the most used tftp packets are Read Request and Write Request
	packets, and any tftp transfer begins with such a request.
	In rfc-1350 they have the 'opcode' field set to 1 and 2 respectively.

	This function creates a Read (RRQ) or Write (WRQ) packet, the packet format
  is the following as defined by the rfc:

	            2 bytes     string    1 byte     string   1 byte
	            ------------------------------------------------
	           | Opcode |  Filename  |   0  |    Mode    |   0  |
	            ------------------------------------------------
	                              RRQ/WRQ packet

	NOTE: as soon as this packet is acknowledged correctly the calling code
	      should free the memory used by it since a request packet it's short
				lived for a tftp session.
*/
struct tftp_packet * make_tftp_request_packet (const char *str_filename,
	const char *str_mode, u16s type_opcode, size_t *stp)
{
  size_t file_len, mode_len, packet_size;
	void *packet, *pk_mode_offset, *pk_filename_offset;

  /* do some validation against the opcode selected for this packet,
	   only opcodes for read and write requests are valid */
	switch (type_opcode)
	{
		 case TFTP_RRQ_PACKET:
		 case TFTP_WRQ_PACKET:
		    break;

		 default:
		    fprintf(stderr, "Invalid type of TFTP Request packet: %d\n", type_opcode);
				exit(EXIT_FAILURE);
	}

  /*
	   compute the size (in bytes) needed to allocate the packet
	   including the NULL bytes separators
	*/
	file_len = strnlen(str_filename, PATH_MAX);
	mode_len = strnlen(str_mode, TFTP_MODE_MAXLEN);
	packet_size = file_len+mode_len+4;

	/*
	 * after knowing in advance the length of the filename, which mode was
	 * requested ("octet" or "netascii") we are ready to craft a packet.
	 *
	 * 0. Allocate memory for the packet
	 * 1. Set the opcode (type) of the packet
	 * 2. Copy the filename requested into the 'string' position in the packet
	 * 3. Write the transfer mode
	 */

  /* allocate memory for the packet */
	packet = tftp_alloc(packet_size);

  if (packet == NULL) {
	   fprintf(stderr, "Couln't allocate memory for the request packet\n");
		 exit(EXIT_FAILURE);
	}

	/* if (packet == NULL) return NULL; */

  /* resolve offsets into the new packet */
	pk_filename_offset = GET_OFFSET(packet, 2, 0);
	pk_mode_offset = GET_OFFSET(packet, file_len, 3);

  /* 1. set the opcode for read or write */
	SET_OPCODE(packet, type_opcode);

  /* 2. write the filename after the opcode field, including the NULL byte */
	memcpy(pk_filename_offset, str_filename, file_len+1);

  /* 3. insert the transfer mode using the string provided and also
	      include the zero byte */
  memcpy(pk_mode_offset, str_mode, mode_len+1);

	*stp = packet_size;
	return packet;
}


/*
 *	test for a DATA packet
 * 	@tb:	a pointer to a tftp header
 */
size_t
is_data_pkt(const char * tb)
{
	return tb[1] == TFTP_DATA_PACKET;
}

/*
 *	returns 1 if the tftp headers corresponds to a ERROR packet
 * 	@tb:	a pointer to a tftp header
 */
size_t
is_error_pkt(const char * tb)
{
	return (tb[1] == TFTP_ERROR_PACKET);
}


/*
	copy_tftp_data : store every block to disk on the requested file

	this routine is used when a Read Request is made

	this code also performs CRLF to LF conversion on the input (rrq)
	data if the mode is netascii
*/
static inline size_t
copy_tftp_data(size_t blk_size, char * data, const char * file, size_t mode)
{
	FILE *fd;

	if ( (fd = fopen(file, "a")) == NULL ) {
		return 0;
	}

	/* if netascii mode is requested (a text file) then convert CRLF to LF,
	   if not then octet mode is selected and the output data must remain
	   intact */
	if (!mode) {
		crlf2lf(data + TFTP_HDR_SIZE, blk_size - TFTP_HDR_SIZE);
	}

	if ( fwrite( data + TFTP_HDR_SIZE, blk_size - TFTP_HDR_SIZE,
														1, fd) == 0 ) {
		goto out_error;
	}

	fclose(fd);
	return 1;

out_error:
	fclose(fd);
	return 0;
}


/*
	crlr_2_lf
	convert carriage returns and line feeds into line feeds only, normally
	files with CRLF comes from microsoft windows then the conversion is
	performed in memory before the data is written to disk.

	@data: memory address of a tftp data block with user data
	@bs: block size of the data block, normally 512 (bytes) however can be
		 less when the data block is the last of the transmission.
*/
static inline void crlf2lf(char *data, size_t bs)
{
	/* replace each CR found with a space (0x20) */
	while (bs--) {
		if (*data++ == '\r') {
			*(data - 1) = ' ';
		}
	}
}

/*
	simple allocation routine for avoiding make multiple calls to malloc
	all over the program.
*/
void * tftp_alloc(size_t size)
{
   return malloc(size);
}

/* show basic program usage */
void usage(const char *argv) {
	printf("-- Help --\nThe following options are mandatory\n\n");
	printf("\t-o		octet mode\n");
	printf("\t-w		file to send to the server\n");
	printf("\t-r		file to read from the server\n");
	printf("\t-s		server address (ipv4)\n");
	printf("\t--help		this help message\n");
	puts("");
	printf("An example: ");
	printf("%s -s 200.55.129.1 -w ip.txt\n", argv);
	printf("\nwill set the tftp server to 200.55.129.1, request to write (w)\n");
	printf("the local file ip.txt in netascii mode (the default)\n");
	printf("--\n");
}

/*
	handle all details about read a tftp file, acknowledge it, check
	errors, save the user data to a file etc.

	to diagnose the errors the caller must check errno, however not
	always errno will have the error because some errors are not system
	specific errors, but protocol (tftp) specific errors.
*/
size_t tftp_read_control(int sock, struct sockaddr_in *s_addr,
						 size_t mode, const char *file, tftp_stats *st)
{
	size_t stp, rem_tid;
	ssize_t s, rf;
	socklen_t flen;
	struct sockaddr_in src_sock;
	struct tftp_packet *pk;
	char *data_ptr;

	init_stats_rd(st)			/* initialize stats counters */
	st->retr_num = 0;

  /* create a request (read) packet */
	pk = make_tftp_request_packet(file, tftp_t_modes[mode], TFTP_RRQ_PACKET, &stp);

	if ((s = sendto(sock, pk, stp, 0, (struct sockaddr *)s_addr,
									sizeof(struct sockaddr_in))) < 0) {
		return 1;
	}

	if ((data_ptr = tftp_alloc(TFTP_BLOCK_SIZE_HDR)) == NULL ) {
		return 1;
	}

	flen = sizeof(struct sockaddr_in);
	if ((rf = recvfrom(sock, data_ptr, TFTP_BLOCK_SIZE_HDR, 0,
								(struct sockaddr *)&src_sock, &flen)) < 0) {
		return 1;
	}

	rem_tid = ntohs(src_sock.sin_port); 	/* now the new tid is updated */
	s_addr->sin_port = src_sock.sin_port;
	st->blk_rcvd++;

	/*
		logics for acknowledge data packets read(2),
		receive data blocks and validate them, check
		for error packets etc.
	*/

	if (is_data_pkt(data_ptr)) {

		do {
			st->bytes_rcvd += rf - TFTP_HDR_SIZE;
			copy_tftp_data(rf, data_ptr, file, mode);
ack:
			if (send_ack(sock, &src_sock, st->blk_rcvd) < 1) {
				LOG_ACK_ERROR(stderr, st->blk_rcvd);
				return 1;
			}

			if ((rf - TFTP_HDR_SIZE) < TFTP_BLOCK_SIZE) {
				data_ptr[rf] = '\0';
				if ( st->blk_rcvd == 0) {
					++st->blk_rcvd;
				}
				break;
			}

			++st->blk_rcvd;

			if ((rf = recvfrom(sock, data_ptr, TFTP_BLOCK_SIZE_HDR, 0,
						  			(struct sockaddr *)&src_sock, &flen)) < 0) {
				return 1;
			}

			if  (rem_tid != ntohs(src_sock.sin_port)) {
				send_tftp_error(sock, &src_sock, tftp_error_codes[5], 5);
				--st->blk_rcvd;
				goto ack;
			}

			if (is_data_pkt(data_ptr)) {
				if (check_data_block(data_ptr, st->blk_rcvd) < 0) {
					(void)fprintf(stderr, "info: retransmitting ack for data block %d\n",
																	st->blk_rcvd-1);
					--st->blk_rcvd;
					++st->retr_num;

					goto ack;
				}
			}
			else if (is_error_pkt(data_ptr)) {
				goto print_reply_packet;
			}

		} while (1);
	}
	else {
		goto print_reply_packet;
	}
	free(pk);
	free(data_ptr);
	return 0;

print_reply_packet:
	printf("%s\n", data_ptr+4);
	return 0;
}

/* set I/O socket timeouts */
size_t set_skio_timeout(int sock, size_t ts, size_t tms)
{
	struct timeval tval;
	tval.tv_sec = ts;
	tval.tv_usec = tms;

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tval, sizeof(tval)) < 0) {
		return 1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tval, sizeof(tval)) < 0) {
		return 1;
	}

	return 0;
}

/*
 */
size_t tftp_write_control(int sock, struct sockaddr_in * s_addr, size_t mode,
	  const char * file, tftp_stats * st)
{
	int fd;
	ssize_t bytes_in_file, s, rf, bts, rd;
	size_t stp, bytes_to_read, rem_tid;
	socklen_t flen;
	struct sockaddr_in src_sock;
	struct ack_error_packet ack_err_buf, *ack_ebuf_packet;
	struct tftp_data_packet *data_packet;

	ack_ebuf_packet = &ack_err_buf;
	flen = sizeof(struct sockaddr_in);
	INIT_STATSW(st)			               /* initialize stats counters */
	st->retr_num = 0;

   if ((bytes_in_file = get_file_size(file)) < 0)
     return WRITE_FAIL;

   if ((fd = open(file, O_RDONLY, 0)) < 0)
     return WRITE_FAIL;

   /* turn a (possible) path into filename which is valid for requests */
   char *filename = basename((char *)file);

   /* make a tftp request packet to be used as the initial request */
   //void *pk = make_tftp_request_packet(filename, tftp_t_modes[mode], TFTP_WRQ_PACKET, &stp);

   struct Request_Packet *pk = create_request(filename, tftp_t_modes[mode], REQUEST_PACKET, 2, 0);


send_req:
  s = SEND_PACKET(sock, pk, LEN_REQ(pk), s_addr);
	if (s < 0)
	   return WRITE_FAIL;

  /*
	   receive either the ack or error packet from the server, this call also
		 fills the src_sock structure with relevant information needed for
		 communications
	*/
	if (RECV_ERR_ACK_PACKET(sock, ack_ebuf_packet, src_sock, &flen) < 0)
	  return WRITE_FAIL;

  /* handle retransmission of the first request packet if we don't see
	   an ACK from the server */
	if (check_ack(ack_ebuf_packet, st->blk_sent) < 0) {
			fprintf(stderr, "info: retransmitting block %d\n", st->blk_sent);
			++st->retr_num;
			goto send_req;
	}

	free(pk);

  /* get & set the new remote TID (remote port) for the connection, this one is
	   assigned by the ip layer on the other side of the connection and it's used
		 as the endpoint for communication, this information is filled by the first
		 call to recvfrom(2) */
	s_addr->sin_port = src_sock.sin_port;
	rem_tid = ntohs(src_sock.sin_port);

  /* create the data packet to be used as the memory area where all blocks
	   of the file will be read */
  data_packet = make_data_packet();

	/*
		if the reply to the first data packet is one ACK with Data Block
		number 0, then this is a possitive ack, continue with the transmission
	*/
	if (ack_ebuf_packet->ack_buffer[1] == TFTP_ACK_PACKET &&
		 ack_ebuf_packet->ack_buffer[3] == 0 )
	{
		do {
			++st->blk_sent;
			data_packet->block_num = htons(st->blk_sent); /* update data block number */

			size_t size = bytes_in_file > TFTP_BLOCK_SIZE ? TFTP_BLOCK_SIZE : bytes_in_file;

      /* read a block of data from the file into the packet */
			if ((rd = read(fd, (char *)data_packet+TFTP_HDR_SIZE, size)) < 0) {
			  return WRITE_FAIL;
			}

			bts = bytes_in_file > TFTP_BLOCK_SIZE ? TFTP_BLOCK_SIZE_HDR : bytes_in_file+4;
retr_xmit:

      /* send the packet */
      if (SEND_PACKET(sock, data_packet, bts, s_addr) < 0) {
				return WRITE_FAIL;
			}

			st->bytes_sent += rd;
			bytes_in_file -= rd;

			/* receive ack or error */
			if (RECV_ERR_ACK_PACKET(sock, ack_ebuf_packet, src_sock, &flen) < 0)
			  return WRITE_FAIL;

			/* handle retransmissions by checking the acks received,
			   the last data block is kept for this */
			if (check_ack(ack_ebuf_packet, st->blk_sent) < 0) {
			   fprintf(stderr, "info: retransmitting data block: %d\n", st->blk_sent);
				 st->bytes_sent -= rd;
				 bytes_in_file += rd;
				 ++st->retr_num;
				 goto retr_xmit;
			}

			/* handle an invalid tid */
			if  (rem_tid != ntohs(src_sock.sin_port)) {
				send_tftp_error(sock, &src_sock, tftp_error_codes[5], 5);
				st->bytes_sent -= rd;
				bytes_in_file += rd;
				goto retr_xmit;
			}

			/*
        if the file is 512 bytes sending one data packet causes that
		   	the server waits for the next data packet. Since there is none,
	      the server timeouts with an error, yet the file is written to
		   	disk, this is standard behavior, however this fix is to avoid
		   	the timeout in the server, to achieve this we must send one empty
				data packet with the block number that the server expect, and then
				it's over, we exit.
				NOTE: the ack reply must be checked here for consistency. Also
				the standard does not specify this situation in which a file is
				512 bytes
			 */
			if (bytes_in_file == 0 && st->bytes_sent == 512) {
				data_packet->block_num = htons(st->blk_sent + 1);
				//sendto(sock, data_packet, 4, 0, (struct sockaddr *)s_addr, sizeof(struct sockaddr_in));
				SEND_PACKET(sock, data_packet, 4, s_addr);
				break;
			}

		} while (bytes_in_file > 0);
	}

	close(fd);
	free(data_packet);
	return WRITE_SUCCESS;
}

/* get the size of "file" (in bytes) by calling stat(2) */
size_t get_file_size(const char * file)
{
	struct stat f;
	if (stat(file, &f) < 0) {
		return -1;
	}
	return f.st_size;
}


/*
  TODO: rework this code
	allocate memory for a tftp error packet.
	An error packet has always the opcode field set to 5, error
	packets are used to report invalid conditions that can occur
	in the life of a tftp transfer.
	@msg: netascii string zero terminated with the message
	@error_code: number of error code
	@bts: used here to return  to the caller the size of the error
		  packet
*/
tftp_error_packet *
create_error_packet(const char * msg, u16s error_code, u16s *bts)
{
	size_t total_alloc = strlen(msg) + 5;
	void *er_mem = (void *)tftp_alloc(total_alloc);

	if ( er_mem == NULL ) {
		return NULL;
	}

	tftp_error_packet *error_packet = er_mem;
	error_packet->opcode = htons(TFTP_ERROR_PACKET);		/* opcode field=5 for error packet */
	error_packet->code = htons(error_code);
	error_packet->mesg = (char *)error_packet + 4;
	strncpy(error_packet->mesg, msg, total_alloc - 4); /* copy the error message */
	*bts = total_alloc;

	return error_packet;  /* return the beginning of the error packet */
}

/* send an error packet in response to a specific tftp error condition */
size_t send_tftp_error(int sock, struct sockaddr_in *dst,
										const char *msg, u16s err_code) {
	u16s tbts;
	ssize_t s;

	void *epacket = create_error_packet(msg, err_code, &tbts);

	if ( epacket == NULL )
		return 1;

	if (SEND_PACKET(sock, epacket, tbts, dst) < 0)
	  return 1;

	free(epacket);
	return 0;
}

/*
	check that the received data block number match
	with the data block number that is expected.
*/

ssize_t check_data_block(const void * hdr, u16s block)
{
	u16s opcode = *(u16s *)hdr;
	u16s blockn = *((u16s *)hdr+1);

	if ( (opcode == htons(TFTP_DATA_PACKET)) && (blockn == htons(block))) {
		return 0;
	}
	return -1;
}

/*
	check that the tftp ack packets are correct and that
	the block number is the expected for a data block sent
	this small piece of code is used by tftp_write_control
	to implement the retransmission logic

	HDR is a pointer to the start of the ack packet
*/
static inline
ssize_t check_ack(const void * hdr, size_t block)
{
	unsigned short ack_opcode = *(unsigned short *)hdr;
	unsigned short blknum = *((unsigned short *)hdr+1);

	if ((ack_opcode == htons(TFTP_ACK_PACKET)) && (blknum == htons(block)))
		return 0;

	return -1;
}

/*
 * create a DATA Packet, opcode 3
 */
struct tftp_data_packet *make_data_packet()
{
	struct tftp_data_packet *packet = tftp_alloc(TFTP_BLOCK_SIZE_HDR);

	if (packet == NULL) {
	  fprintf(stderr, "tftp_alloc failed, can't allocate a data packet\n");
		exit(EXIT_FAILURE);
	}

	packet->opcode = htons(TFTP_DATA_PACKET);
	packet->user_data = (char *)packet + TFTP_HDR_SIZE;
	return packet;
}



/*
int main(void)
{
   struct Request_Packet *new_packet;
   struct Data_Packet *data;
   struct Data_Packet *error;

   new_packet = create_request("hello.c", "netascii", REQUEST_PACKET, 1, 0);

   data = create_request(NULL, NULL, DATA_PACKET, 3, DEFAULT_BLOCK_SIZE);

   error = create_request(NULL, "File not found", ERROR_PACKET, 5, 0);

   free(new_packet);
   free(data);
   free(error);
   return 0;
}
*/

/*
 * allocation wrapper
 */
void * get_memory(unsigned int size)
{
    void *new = malloc(size);

    if (new == NULL) {
      fprintf(stderr, "malloc failed to allocate memory\n");
      exit(EXIT_FAILURE);
    }
    return new;
}

/*
 *  Handling of TFTP Packets. Any part of the program who needs to send
 *  a packet must first call here to allocate and configure it first.
 *
 *  The configuration part is done setting the opcode, mode, type and
 *  filename, everything else is the task of the calling code (i.e: copy
 *  a block of data in the packet)
 *
 *  NOTE: ACK packets are no handled here since they are fixed and simple.
 *
 *  file:       filename to send in a request packet
 *  mode:       type of transfer mode for a request packet or error string
 *  t:          type of packet
 *  opcode:     opcode for the packet, all packets have an opcode field
 *  block_size: allocation size for a Data Packet, 0 otherwise
 *
 */
void * create_request(char *file, char *mode, char t, unsigned short opcode,
  unsigned int block_size)
{
    unsigned int total;

    switch (t)
    {
      case REQUEST_PACKET:

         /*
          * total size in bytes for allocate a request packet
          * 2 bytes for opcode, 2 more for NUL terminators
          * plus the length of the filename and the mode
          */
         total = 4 + LEN(file, mode);
         struct Request_Packet *packet = get_memory(total);
         memset(packet, 0, total);
         packet->Opcode = opcode;
         memcpy(&packet->Filename, file, LEN(file, "") + 1);
         memcpy(&packet->Mode, mode, LEN(mode, "") + 1);
         return packet;


      case DATA_PACKET:

         total = 4 + block_size;
         struct Data_Packet *dpacket = get_memory(total);
         dpacket->Opcode = opcode;
         return dpacket;


      /* 
       * we reuse the Data_Packet structure here since the format it's the same, 
       * we treat the 'mode' argument as the ErrMsg field to copy the error 
       * message into the packet, the ErrorCode field is not set, this is 
       * responsability to the calling code.
       */ 
      case ERROR_PACKET:
 
         total = 5 + LEN(mode, "");
         struct Data_Packet *epacket = get_memory(total);
         epacket->Opcode = opcode;
         memcpy(&epacket->Data, mode, strnlen(mode, 255) + 1);
         return epacket;
        
      default:
         fprintf(stderr, "Unknown TFTP Packet: %d\n", t);
         exit(EXIT_FAILURE);
    }
   return NULL;
}
