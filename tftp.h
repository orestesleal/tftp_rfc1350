/*
	data structures and definitions for the TFTP protocol
	Copyright Orestes Leal Rodriguez 2015 <lukes357@gmail.com>

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version
	2 of the License, or (at your option) any later version.
*/

#define NULL_OP           0
#define WRITE_OP          1
#define READ_OP           2

#define WRITE_FAIL        1
#define WRITE_SUCCESS     0

#define NETASCII_MODE     0
#define OCTECT_MODE       1

/* Types of TFTP packets (rfc 1350)*/
#define TFTP_RRQ_PACKET		1
#define TFTP_WRQ_PACKET		2
#define	TFTP_DATA_PACKET	3
#define TFTP_ACK_PACKET		4
#define TFTP_ERROR_PACKET	5

#define TFTP_DEFAULT_PORT	69       /* default UDP port for TFTP servers */
#define TFTP_BLOCK_SIZE		512		   /* rfc1350 block size */
#define TFTP_HDR_SIZE		  4		     /* size of a tftp data header */
#define TFTP_BLOCK_SIZE_HDR	516		 /* default block size plus header */
#define TFTP_MODE_MAXLEN  9

typedef unsigned short u16s;

/* core tftp options */
struct tftp_core_options
{
	u16s blksize;		/* default block size o agreed (rfc2348) */
	u16s blk_size_hdr;	/* block size counting the tftp header */
	u16s timeout;		/* default timeout or agreed (rfc2349) */
};

/* macros to initialize to 0 the transfer statistics */
#define INIT_STATSW(x)    	\
		(x->blk_sent = 0);  	\
	    (x->bytes_sent = 0);	\
		(x->retr_num = 0);

#define init_stats_rd(x)   	 	\
		(x->bytes_rcvd = 0); 	\
	    (x->blk_rcvd = 0);		\
		(x->retr_num = 0);

char * tftp_t_modes[] = {			/* transfer modes */
				"netascii",
				"octet"
				};

char * tftp_error_codes[] = {		/* rfc1350 error codes */
				"Not defined",
				"File not found",
				"Access violation",
				"Disk full or allocation exceeded",
				"Ilegal TFTP operation",
				"Unknown transfer ID",
				"File already exists",
				"No such user"
				};

/* TFTP Packet */
struct tftp_packet
{
   u16s *opcode;
   char *filename;
   char *mode;
};

struct tftp_req_packet
{					/* request packet */
	u16s	opcode;
	void *	filename;
	void *	mode;
};

/* format of a TFTP DATA Packet */
struct tftp_data_packet
{
	u16s opcode;
	u16s block_num;
	char *user_data;
};

struct tftp_ack_pkt
{ 					/* 'ack' packet */
	u16s opcode;
	u16s block_n;
};

struct tftp_error_pkt
{					/* 'error' packet */
	u16s opcode;
	u16s code;
	char *mesg;
};

/* TODO: rework the statistics and create a send/recv pair or variables
         to hold the bytes sent and received, just that */
struct tftp_stats
{
	size_t blk_rcvd;
	float bytes_rcvd;
	size_t blk_sent;
	float bytes_sent;
	size_t retr_num;
};


/*
    ACK and Error Packets
		=====================
	  "ack_buffer" is the buffer used to received the acks, it's a tftp packet
		of four bytes:

           2 bytes     2 bytes
           ---------------------
          | Opcode |   Block #  |
           ---------------------
               ACK packet

   "error_buffer" is the part of the buffer that belongs to an error packet:
	  	2 bytes     2 bytes      string    1 byte
    -----------------------------------------
   | Opcode |  ErrorCode |   ErrMsg   |   0  |
    -----------------------------------------
				      ERROR packet

  NOTE: the opcode and ErrorCode part of the error packet is shared between
	      the ack packet and error packet
*/
struct ack_error_packet
{
   char ack_buffer[4];
	 char error_buffer[60];
};

typedef struct tftp_stats tftp_stats;
typedef struct tftp_req_packet tftp_reqp;
typedef struct tftp_error_pkt tftp_error_packet;
typedef struct tftp_core_options tftp_options;
