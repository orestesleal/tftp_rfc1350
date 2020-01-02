/*
	data structures and constants for the tftp client 
	Copyright Orestes Leal Rodriguez 2015 <lukes357@gmail.com>	

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version
	2 of the License, or (at your option) any later version.	
*/
enum {
	TFTP_RRQ_PACKET = 1,
	TFTP_WRQ_PACKET,
  	TFTP_DATA_PACKET,
	TFTP_ACK_PACKET,
	TFTP_ERROR_PACKET,
	TFTP_OACK_PACKET,		/* rfc2347 option ack packet */
	TFTP_NERROR_PACKET,
	TFTP_DEFAULT_PORT = 69,
	TFTP_BLOCK_SIZE = 512,
	TFTP_HDR_SIZE = 4,
	TFTP_BLOCK_SIZE_HDR = 516,
};

typedef unsigned short u16s;

/* core tftp options, when rfc2348/49 is implemented */ 
struct tftp_core_options
{
	u16s blksize;		/* default block size o agreed (rfc2348) */ 
	u16s timeout;		/* default timeout or agreed (rfc2349) */
};

/* macros to initialize to the transfer statistics */
#define init_stats_wr(x)    	\
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

struct tftp_rw_pkt 
{ 					/* rrq/wrq packet */
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

struct tftp_data_packet 
{					/* data packet */
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

struct tftp_stats 
{					/* transfer statistics */
	size_t blk_rcvd;
	float bytes_rcvd;
	size_t blk_sent;
	float bytes_sent;
	size_t retr_num;
};

typedef struct tftp_stats tftp_stats;
typedef struct tftp_req_packet tftp_reqp;
typedef struct tftp_error_pkt tftp_error_packet;
typedef struct tftp_core_options tftp_options;

