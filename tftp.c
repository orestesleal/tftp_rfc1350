/*  set nu autoindent sw=4 terse tabs=4
 *
 *  A compliant (rfc1350) client implementation of the network
 *	protocol Trivial File Tranfer Protocol, TFTP rev 2 [1]
 *
 * 	Copyright Orestes Leal Rodriguez 2015 <olealrd1981@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 * - rationale -
 *	The original standard document for tftp was described in rfc783 
 *	June, 1981, then in July, 1992, rfc1350 [1], renders obsolete the 
 *	first original rfc,  this tftp attempts to conforms to rfc1350
 *	only.
 *
 *	rfc1350 was updated by rfcs 1782, 1784, 1785, 2347, 2348 and 2349.
 *
 *
 *	- devlog history -
 *	28062015: 	retransmission for send/recv is implemented and 
 *				tested sucessfuly on a link with higher rates of
 *				in/out packet loss
 *	28062015:	complete compliance with rfc1350
 *
 *	-
 *	References
 *
 * [1] 	THE TFTP PROTOCOL (REVISION 2) rfc1350 
 *		http://tools.ietf.org/html/rfc1350
 *
 *	@TODO list
 *		- begin to implement rfc2347, TFTP Option Extension
 *
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
#include <libgen.h>
#include "tftp.h"

#define data_packet(b)	((b[1]) == TFTP_DATA_PACKET))

static inline size_t send_ack(int sk, struct sockaddr_in * sa, 
									size_t block_num);
static inline void ack_error(size_t blk); 
size_t is_data_pkt(const char * tb);
size_t is_error_pkt(const char * tb);
static inline size_t copy_tftp_data(size_t blk_size, char * data,
									const char * file, size_t mode);
struct tftp_rw_pkt * create_tftp_req_pkt(const char *filename, 
											const char *mode,
											u16s type, size_t *stp);
tftp_reqp * 
tftp_reqp_alloc(const char * file, const char * mode,
									u16s type_packet, size_t * rlen); 
static inline void crlf2lf(char *data, size_t bs);
char *tftp_alloc(size_t size);
void usage();
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

int main(int argc, char * argv[])
{
	extern char *optarg;
	int ch;
	int sock; 
	struct sockaddr_in s_addr;	/* tftp server */
	tftp_stats st;				/* tftp session statistics */
	size_t op = 0; 				/* 1(write), 2(read) */
	size_t mode = 0; 			/* netascii mode by default */
	size_t ip_good = 0; 
	char file[128];	

	if (argv[1] && !strcmp(argv[1], "--help")) {
		usage();
		exit(EXIT_SUCCESS);
	}

	bzero(&s_addr, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(TFTP_DEFAULT_PORT);

	while ((ch = getopt(argc, argv, "s:or:w:")) != -1) {
		switch (ch) {
		case 'o': 		/* octet transfer mode */
			mode = 1;
			break;
		case 's':
			if (inet_pton(AF_INET, optarg, &s_addr.sin_addr) < 1) {
				(void)fprintf(stderr, 
					"%s: %s, bad ipv4 internet address\n", argv[0], optarg);
				exit(EXIT_FAILURE);
			}
			ip_good = 1;
			break;	
		case 'w':
			strncpy(file, optarg, sizeof(file)-1);
			op = 1; 
			break;
		case 'r':
			strncpy(file, optarg, sizeof(file)-1);
			op = 2;
			break;
		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (!op || !ip_good) {	/* both operation and remote host are mandatory */
		usage();
		exit(EXIT_FAILURE);
	}

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("datagram socket()");	
		exit(EXIT_FAILURE);
	}

	if (set_skio_timeout(sock, 60, 900000)) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	/* select between write (send) and read (receive) based on the 
   	   operation selected on the command line parameter */
	if (op == 2) { 
		if ( tftp_read_control(sock, &s_addr, mode, file, &st)) {
			(void)fprintf(stderr, 
				"%s: %s\n", argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	else {
		if ( tftp_write_control(sock, &s_addr, mode, file, &st)) {
			(void)fprintf(stderr, 
				"%s: %s\n", argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (op > 1) {
		printf("stats: %.0f bytes recv (%.1f kbytes) (%d blocks) (%d retr)\n", 
							st.bytes_rcvd, st.bytes_rcvd / 1024, st.blk_rcvd, 
																st.retr_num);	
	} else {
		printf("stats: %.0f bytes sent (%.1f kbytes) (%d blocks) (%d retr)\n", 
							st.bytes_sent, st.bytes_sent / 1024, st.blk_sent,
																st.retr_num);
	}

	close(sock);
	return EXIT_SUCCESS;
}


/* report an error occured making the ack to 
   the data block 'blk' */ 
static inline void ack_error(size_t blk) {	
	printf("error: failed to acknowledge data block #%d\n", blk);
}

/* 
	send one ack packet to acknowledge a data block received 
	@ack: 		the ack packet being sent 
	@sa: 		the server information
	@block_num:	the data block to acknowledge
*/
static inline size_t
send_ack(int sk, struct sockaddr_in * sa, size_t block_num)
{
	ssize_t s;
	struct tftp_ack_pkt ack;
	ack.opcode = htons(TFTP_ACK_PACKET);
	ack.block_n = htons(block_num);

	return  s = sendto(sk, 
					   &ack,
					   sizeof(struct tftp_ack_pkt), 0, 
					   (struct sockaddr *)sa,
					   sizeof(struct sockaddr_in));
}

/*
	create_tftp_req_pkt: creates a tftp request packet
	(read or write) in memory, then returns the memory
	address of the packet to be used with the system call
	sendto().

	@filename: input filename to read/write
	@mode: transfer mode
	@type: type of packet to create (read or write)
	@stp: pointer where the size of the packet will
		  be returned
*/
struct tftp_rw_pkt * 
create_tftp_req_pkt(const char *filename, const char *mode,
					  				u16s type, size_t *stp)
{
	size_t f_len = strnlen(filename, 119) + 1;
	size_t m_len = strnlen(mode, 9) + 1;
	size_t res = f_len + m_len + 2;

	void *tftp_mem = (void *)tftp_alloc(res);
	char *mode_offset = (char *)tftp_mem + f_len + 2; 
	*(u16s *)tftp_mem = htons(type); 

	memcpy((char *)tftp_mem + 2, filename, f_len);
	memcpy(mode_offset, mode, m_len);

	*stp = res;
	return (struct tftp_rw_pkt *)tftp_mem;; 
}

tftp_reqp * 
tftp_reqp_alloc(const char * file, const char * mode,
									u16s type_packet, size_t * rlen) {

	tftp_reqp *req_packet;
	void *buf;

	size_t file_len = strnlen(file, 127) + 1;
	size_t mode_len = strnlen(mode, 10) + 1;
	size_t total_res = file_len + mode_len + 2; /* total bytes to allocate */

	if ( (buf = (void *)tftp_alloc(total_res)) == NULL) {
		return NULL;
	}

	req_packet = buf;
	req_packet->opcode = htons(type_packet); 	/* 1(rrq), 2(rrw) */
	req_packet->filename = (char *)req_packet + 2;
	req_packet->mode = (char *)buf + file_len + 2;

	strncpy(req_packet->filename, file, file_len);
	strncpy(req_packet->mode, mode, mode_len);

	*rlen = total_res;
	return req_packet;
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

	this code also performs CRLF to LF conversion on the input (rrq)
	data if the mode is netascii
*/
static inline size_t
copy_tftp_data(size_t blk_size, char * data, const char * file, size_t mode)
{
	FILE *fd;

	/*
	 * The path to the tftp server will most likely contain / characters on the path,
	 * remove those and get only the filename to store in the local directory
	 */
	char *local_dir_file = basename(file);

	if ( (fd = fopen(local_dir_file, "a")) == NULL ) {
	        fprintf(stderr, "fopen(3) error, NULL returned on function copy_tftp_data() when copying tftp blocks to %s\n", local_dir_file);
		return 0;
	}

	/* if netascii mode is requested (a text file) then convert CRLF to LF,
	   if not then octet mode is selected and the output data must remain
	   intact */
	if (!mode) { 
		crlf2lf(data + TFTP_HDR_SIZE, blk_size - TFTP_HDR_SIZE);
	}

	if ( fwrite( data + TFTP_HDR_SIZE, blk_size - TFTP_HDR_SIZE, 1, fd) == 0 ) 
	    goto out_error;

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
char * tftp_alloc(size_t size)
{
	return (char *)malloc(size);
}

void
usage()
{
	char *strc = "-- help --\n"
				 "\t-w file\t\tsend file to server\n"
				 "\t-r file\t\tread file from server\n"
				 "\t-s SERVER\ttftp server\n"
				 "\t-o\t\toctet mode\n"
				 "\t--help\t\tthis help message\n";
	printf("%s", strc);
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
	struct tftp_rw_pkt *pk; 
	char *data_ptr; 

	init_stats_rd(st)			/* initialize stats counters */
	st->retr_num = 0;

	pk = create_tftp_req_pkt(file, tftp_t_modes[mode], TFTP_RRQ_PACKET, &stp);

	/*
	if ((pk = tftp_reqp_alloc(file, tftp_t_modes[mode], 
									TFTP_RRQ_PACKET, &stp)) == NULL) {
		return 1; 
	}
	*/

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
	/*
	if (data_packet(data_ptr)) {
	*/

	if (is_data_pkt(data_ptr)) { 
		do {
			st->bytes_rcvd += rf - TFTP_HDR_SIZE;
			copy_tftp_data(rf, data_ptr, file, mode);
ack:
			if (send_ack(sock, &src_sock, st->blk_rcvd) < 1) {  
				ack_error(st->blk_rcvd);
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
					(void)fprintf(stderr, 
					"info: retransmitting ack for data block %d\n", st->blk_rcvd-1);

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
	handling of write operations, sending data blocks, receiving acks,
	checking for errors, etc.

	27-06-2015: retransmission implemented. Ultra reliable mechanism
				for retransmitting data blocks here (and acks on 
				tftp_read_control). Tested on a 5kbps link via software
				with 20% packet loss around a 60 bytes/sec speed (thanks 
				to vmware_ws network adapter advanced settings), however 
				retransmission does not solve all problems, timeouts are 
				beyond the control of the retransmission mechanism and 
				every tftp client and server has specific timeout values 
				and maximum number of retransmission attempts. 
*/
size_t tftp_write_control(int sock, struct sockaddr_in * s_addr, 
							size_t mode, const char * file, 
							tftp_stats * st) {
	int fd;
	ssize_t fc;
	ssize_t s, rf, bts;
	socklen_t flen;
	size_t stp;				/* size of an tftp packet created */
	struct sockaddr_in src_sock;
	size_t rem_tid;
	ssize_t rd;
	char tftp_reply[64]; 		/* replies of data blocks sent */
	size_t bytes_to_read;

	flen = sizeof(tftp_reply); 
	init_stats_wr(st)			/* initialize stats counters */
	st->retr_num = 0;

	if ((fc = get_file_size(file)) < 0) { 
		return 1;
	}

	if ( (fd = open(file, O_RDONLY, 0)) < 0) {
		return 1;
	}

	/* create a write packet */
	struct tftp_rw_pkt *pk = create_tftp_req_pkt(file, tftp_t_modes[mode], 
														TFTP_WRQ_PACKET, &stp);
send_req:
	if ((s = sendto(sock, pk, stp, 0, (struct sockaddr *)s_addr, 
										sizeof(struct sockaddr_in))) < 0) {
		return 1;	
	}

	if ((rf = recvfrom(sock, tftp_reply, sizeof(tftp_reply), 0,
									(struct sockaddr *)&src_sock, &flen)) < 0) {
		return 1;	
	}

	if ( check_ack(tftp_reply, st->blk_sent) < 0) {
			(void)fprintf(stderr, "info: retransmitting block %d\n", 
															st->blk_sent);
			++st->retr_num;
			goto send_req;
	}

	s_addr->sin_port = src_sock.sin_port;
	rem_tid = ntohs(src_sock.sin_port);

	char *tftp_data_block = tftp_alloc(TFTP_BLOCK_SIZE_HDR);
	if ( tftp_data_block == NULL) {
		return 1;
	}

	/* configure a DATA packet, opcode 3 */
	struct tftp_data_packet *dt = (void *)tftp_data_block;
	dt->opcode = htons(3);		
	dt->user_data = (char *)dt + TFTP_HDR_SIZE;

	/*
		if the reply to the first data packet is an ack with data block 
		number 0, then is a possitive ack, continue with the transmission
	*/
	if ( tftp_reply[1] == 0x4 && tftp_reply[3] == 0 ) { 

		do {
			++st->blk_sent;
			dt->block_num = htons(st->blk_sent); /* update data block number */

			bytes_to_read = fc > TFTP_BLOCK_SIZE ? TFTP_BLOCK_SIZE : fc;

			if ((rd = read(fd, &dt->user_data, bytes_to_read)) < 0) {
				return 1;
			}

			bts = fc > TFTP_BLOCK_SIZE ? TFTP_BLOCK_SIZE_HDR : fc+4;
retr_xmit:
			if ((s = sendto(sock, dt, bts, 0, (struct sockaddr *)s_addr,
										   	      sizeof(struct sockaddr_in))) < 0) {
				return 1;	
			}

			st->bytes_sent += rd;
			fc -= rd;

			/* receive ack or error */
			if ((rf = recvfrom(sock, tftp_reply, sizeof(tftp_reply), 0,
									(struct sockaddr *)&src_sock, &flen)) < 0) {
				return 1;
			}

			/* check ack and if incorrect retransmit the last data block */
			if ( check_ack(tftp_reply, st->blk_sent) < 0) {
				(void)fprintf(stderr, "info: retransmitting data block: %d\n", 
																st->blk_sent);
				st->bytes_sent -= rd;
				fc += rd;
				++st->retr_num;
				goto retr_xmit;
			}

			/* handle an invalid tid */ 
			if  (rem_tid != ntohs(src_sock.sin_port)) {
				send_tftp_error(sock, &src_sock, tftp_error_codes[5], 5);
				st->bytes_sent -= rd;
				fc += rd;
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
			if (fc == 0 && (st->bytes_sent == 512)) {
				dt->block_num = htons(st->blk_sent + 1);
				sendto(sock, dt, 4, 0, (struct sockaddr *)s_addr, sizeof(struct sockaddr_in)); 
				break;
			}

		} while (fc > 0);	
	}

	close(fd);
	free(tftp_data_block);
	return 0;
}

/*
	get the size of a file in bytes using stat(2)
*/
size_t get_file_size(const char * file)
{
	struct stat f;
	if (stat(file, &f) < 0) {
		return -1;
	}
	return f.st_size; 
}


/*
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
	size_t total_alloc = 4 + strlen(msg) + 1;
	void *er_mem = (void *)tftp_alloc(total_alloc);

	if ( er_mem == NULL ) {
		return NULL;
	}

	tftp_error_packet *error_packet = er_mem;
	error_packet->opcode = htons(5);		/* opcode field=5 for error packet */
	error_packet->code = htons(error_code);
	error_packet->mesg = (char *)error_packet + 4;
	strncpy(error_packet->mesg, msg, total_alloc - 4); /* copy the error message */ 
	*bts = total_alloc;

	return error_packet; 
}

/* 
 *	send an error packet due to a specific tftp condition
 *	@sock: udp socket
 *	@dst: remote host addr in dst->in_addr.sin_addr
 *	@msg: message to send (tftp_error_codes[] (tftp.h)
 */
size_t send_tftp_error(int sock, struct sockaddr_in *dst, 
										const char *msg, u16s err_code)
{
	u16s tbts;
	ssize_t s;

	/* allocate memory for one error packet */
	tftp_error_packet *epk = create_error_packet(msg, err_code, &tbts); 

	if ( epk == NULL ) {
		return 1;
	}
	if ((s = sendto(sock, epk, tbts, 0, (struct sockaddr *)dst, 
										sizeof(struct sockaddr_in))) < 0) {
		return 1;
	}

	free(epk);
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

	if ( (opcode == htons(3)) && (blockn == htons(block))) {
		return 0;
	}
	return -1;
}

/*	
	check that the tftp ack packets are correct and that
	the block number is the expected for a data block sent
	this small piece of code is used by tftp_write_control
	to implement the retransmission logic
*/
static inline 
ssize_t check_ack(const void * hdr, size_t block)
{
	u16s opcode = *(u16s *)hdr;
	u16s blockn = *((u16s *)hdr+1);

	if ( (opcode == htons(4)) && (blockn == htons(block))) {
		return 0;
	}
	return -1;
}
