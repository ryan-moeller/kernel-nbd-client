/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NBD_PROTOCOL_H_
#define _NBD_PROTOCOL_H_

#include <sys/cdefs.h>
#include <sys/types.h>

/**
 ** Network protocol header structs and values
 **/

#define NBD_DEFAULT_PORT "10809"
#define NBD_MAX_STRING 4096

/*
 * Negotiation handshake
 *
 * Oldstyle:
 * When the client connects, the server sends a handshake packet with the
 * export size and supported flags.  There is no option negotiation, the
 * server immedately transitions to the transmission phase.  The oldstyle
 * protocol is deprecated and unsupported.
 *
 * Newstyle:
 * When the client connects, the server sends a handshake packet with the
 * handshake flags.  The client responds with its client flags, which must
 * include the FIXED_NEWSTYLE flag.
 */

#define NBD_MAGIC 0x4e42444d41474943UL
#define NBD_OLDSTYLE_MAGIC 0x00420281861253UL
#define NBD_NEWSTYLE_MAGIC 0x49484156454F5054UL

struct nbd_handshake {
	uint64_t magic;
	uint64_t style;
} __packed;


struct nbd_oldstyle_negotiation {
	uint64_t size;
	uint32_t flags;
	uint8_t reserved[124];
} __packed;


#define NBD_FLAG_FIXED_NEWSTYLE (1 << 0)
#define NBD_FLAG_NO_ZEROES      (1 << 1)

struct nbd_newstyle_negotiation {
	uint16_t handshake_flags;
} __packed;


#define NBD_CLIENT_FLAG_FIXED_NEWSTYLE NBD_FLAG_FIXED_NEWSTYLE
#define NBD_CLIENT_FLAG_NO_ZEROES      NBD_FLAG_NO_ZEROES

struct nbd_client_flags {
	uint32_t client_flags;
} __packed;


/*
 * Option haggling
 *
 * After the initial handshake, the client requests desired options and the
 * server replies to each option acknowledging if supported or with an
 * error if the option is unsupported.
 *
 * The client must only negotiate one option at a time.  Some options will
 * have multiple replies from the server.  The client must wait until the
 * final reply for an option is received before moving on.
 *
 * Option haggling is completed when the client sends either of the
 * following options:
 *  - EXPORT_NAME (transition to transmission mode)
 *  - ABORT (soft disconnect, server should acknowledge)
 * Alternatively, a hard disconnect may occur by disconnecting the TCP
 * session.
 *
 * The server's reply to the EXPORT_NAME option is unique.  EXPORT_NAME
 * signals a transition into transmission mode, and the server sends the
 * length of the export in bytes, the transmission flags, and unless the
 * NO_ZEROES flag has been negotiated during the handshake, 124 zero bytes
 * (reserved for future use).  If the server instead refuses the requested
 * export, it terminates closes the TCP session.
 *
 * Note: The transmission flags for the server's reply to EXPORT_NAME are
 * defined in the next section.
 */

#define NBD_OPTION_MAGIC NBD_NEWSTYLE_MAGIC

enum {
	NBD_OPTION_EXPORT_NAME      = 1,
	NBD_OPTION_ABORT            = 2,
	NBD_OPTION_LIST             = 3,
	NBD_OPTION_PEEK_EXPORT      = 4, // withdrawn
	NBD_OPTION_STARTTLS         = 5,
	NBD_OPTION_INFO             = 6,
	NBD_OPTION_GO               = 7,
	NBD_OPTION_STRUCTURED_REPLY = 8,
	NBD_OPTION_BLOCK_SIZE       = 9,
};

struct nbd_option {
	uint64_t magic;
	uint32_t option;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


#define NBD_OPTION_REPLY_MAGIC 0x3e889045565a9UL

enum {
	NBD_REPLY_ACK    = 1,
	NBD_REPLY_SERVER = 2,
	NBD_REPLY_INFO   = 3,

	NBD_REPLY_ERROR                 = (1 << 31),
	NBD_REPLY_ERROR_UNSUPPORTED     = (1 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_POLICY          = (2 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_INVALID         = (3 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_PLATFORM        = (4 | NBD_REPLY_ERROR), // unused
	NBD_REPLY_ERROR_TLS_REQUIRED    = (5 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_UNKNOWN         = (6 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_SHUTDOWN        = (7 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_BLOCK_SIZE_REQD = (8 | NBD_REPLY_ERROR),
};

struct nbd_option_reply {
	uint64_t magic;
	uint32_t option;
	int32_t type;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


struct nbd_option_reply_server {
	uint32_t length;
	// char export_name[]; (sent separately)
} __packed;


#define NBD_FLAG_HAS_FLAGS            (1 << 0)
#define NBD_FLAG_READ_ONLY            (1 << 1)
#define NBD_FLAG_SEND_FLUSH           (1 << 2)
#define NBD_FLAG_SEND_FUA             (1 << 3) /* FUA = force unit access */
#define NBD_FLAG_ROTATIONAL           (1 << 4) /* use elevator algorithm */
#define NBD_FLAG_SEND_TRIM            (1 << 5)
#define NBD_FLAG_SEND_WRITE_ZEROES    (1 << 6)
#define NBD_FLAG_SEND_DF              (1 << 7)
#define NBD_FLAG_CAN_MULTI_CONN       (1 << 8)
#define NBD_FLAG_SEND_RESIZE          (1 << 9)
#define NBD_FLAG_SEND_CACHE           (1 << 10)
#define NBD_FLAG_SEND_FAST_ZERO       (1 << 11)
#define NBD_FLAG_BLOCK_STATUS_PAYLOAD (1 << 12)

struct nbd_export_info {
	uint64_t size;
	uint16_t transmission_flags;
	uint8_t reserved[124];
} __packed;


enum {
	NBD_INFO_EXPORT	     = 0,
	NBD_INFO_NAME        = 1,
	NBD_INFO_DESCRIPTION = 2,
	NBD_INFO_BLOCK_SIZE  = 3,
};

struct nbd_info_export {
	uint16_t type;
	uint64_t size;
	uint16_t transmission_flags;
} __packed;

struct nbd_info_name {
	uint16_t type;
	// char export_name[]; (sent separately)
} __packed;

struct nbd_info_description {
	uint16_t type;
	// char export_description[]; (sent separately)
} __packed;

struct nbd_info_block_size {
	uint16_t type;
	uint32_t minimum_blocksize;
	uint32_t preferred_blocksize;
	uint32_t maximum_payload;
} __packed;


/*
 * Transmission
 *
 * The client sends a request, and the server replies.  Replies may not
 * necessarily be in the same order as the requests, so the client assigns
 * a cookie to each request.  The cookie must be unique among all active
 * requests.  The server replies using the same cookie to associate the
 * reply with the correct transaction.
 *
 * The client must not send a FLUSH request until replies for all write
 * commands to be flushed have been received when parallelized across
 * multiple connections to the server.
 *
 * Only the client may cleanly disconnect during transmission, by sending
 * the DISCONNECT command.  Either the client or server may perform a hard
 * disconnect by dropping the TCP session.  If a client receives ESHUTDOWN
 * errors it must attempt a clean disconnect.
 *
 * Note on errors: The server should map EDQUOT and EFBIG to ENOSPC.
 */

#define NBD_REQUEST_MAGIC 0x25609513

#define NBD_CMD_FLAG_FUA         (1 << 0)
#define NBD_CMD_FLAG_NO_HOLE     (1 << 1)
#define NBD_CMD_FLAG_DF          (1 << 2)
#define NBD_CMD_FLAG_REQ_ONE     (1 << 3)
#define NBD_CMD_FLAG_FAST_ZERO   (1 << 4)
#define NBD_CMD_FLAG_PAYLOAD_LEN (1 << 5) // experimental EXTENDED_HEADERS

enum {
	NBD_CMD_READ       = 0,
	NBD_CMD_WRITE      = 1,
	NBD_CMD_DISCONNECT = 2,
	NBD_CMD_FLUSH      = 3,
	NBD_CMD_TRIM       = 4,
};

struct nbd_request {
	uint32_t magic;
	uint16_t flags;
	uint16_t command;
	uint64_t cookie;
	uint64_t offset;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


#define NBD_SIMPLE_REPLY_MAGIC 0x67446698

enum {
	NBD_EPERM     = 1,
	NBD_EIO       = 5,
	NBD_ENOMEM    = 12,
	NBD_EINVAL    = 22,
	NBD_ENOSPC    = 28,
	NBD_EOVERFLOW = 75,
	NBD_ESHUTDOWN = 108,
};

struct nbd_simple_reply {
	uint32_t magic;
	uint32_t error;
	uint64_t cookie;
	// uint8_t data[]; (sent separately)
} __packed;


#define NBD_STRUCTURED_REPLY_MAGIC 0x668e33ef

#define NBD_REPLY_FLAG_DONE (1 << 0)

enum {
	NBD_REPLY_TYPE_NONE             = 0,
	NBD_REPLY_TYPE_OFFSET_DATA      = 1,
	NBD_REPLY_TYPE_OFFSET_HOLE      = 2,
	// 3 unused
	// 4 unused
	NBD_REPLY_TYPE_BLOCK_STATUS     = 5,
	NBD_REPLY_TYPE_BLOCK_STATUS_EXT = 6, // experimental EXTENDED_HEADERS

	NBD_REPLY_TYPE_ERROR_BIT    = (1 << 15),
	NBD_REPLY_TYPE_ERROR        = (1 | NBD_REPLY_TYPE_ERROR_BIT),
	NBD_REPLY_TYPE_ERROR_OFFSET = (2 | NBD_REPLY_TYPE_ERROR_BIT),
};

struct nbd_structured_reply {
	uint32_t magic;
	uint16_t flags;
	uint16_t type;
	uint64_t cookie;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;

struct nbd_reply_offset_data {
	uint64_t offset;
	// uint8_t data[]; (sent separately)
} __packed;

struct nbd_reply_offset_hole {
	uint64_t offset;
	uint32_t size;
} __packed;

struct nbd_reply_block_status {
	uint32_t context;
	// struct nbd_reply_block_status_descriptor descs[]; (sent separately)
} __packed;

struct nbd_reply_block_status_descriptor {
	uint32_t size;
	uint32_t status;
} __packed;

struct nbd_reply_error {
	uint32_t error;
	uint16_t length;
	// char message[]; (sent separately)
} __packed;

struct nbd_reply_error_offset {
	uint64_t offset;
} __packed;

#endif /* #ifndef _NBD_PROTOCOL_H_ */
