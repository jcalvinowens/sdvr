/*
 * proto.h: SDVR wire protocol structures
 *
 * Copyright (C) 2023 Calvin Owens <jcalvinowens@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#pragma once

#include <stdint.h>

/*
 * These constants are arbitrary, but changing them may break compability with
 * existing clients/servers.
 */

#define SDVR_HELLOPAD	(64)
#define SDVR_HELLOLEN	(SDVR_HELLOPAD + sizeof(uint32_t))
#define SDVR_NAMELEN	(128)

/*
 * These constants depend on NaCl.
 *
 * This is to avoid the need to include the NaCl header here. The constants are
 * verified against the constants in NaCl with static_assert in crypto.c.
 */

#define SDVR_PLEN	(32)
#define SDVR_PKLEN	(32)
#define SDVR_NONCELEN	(24)
#define SDVR_MACLEN	(16)

/**
 * Key Exchange Procotol
 * ---------------------
 *
 * The protocol is structured so that the daemon can maintain zero state for
 * DGRAM clients until the client can be authenticated.
 *
 * The padding in msg_0 exists to make the daemon an uneconomical reflector:
 * since the source address could be spoofed, we force the client to send more
 * data than we reply with.
 *
 * The implementation provides perfect forward security: a third party who is
 * able to record all network traffic from a client, and later compromise that
 * client and obtain its secret keys, will not be able to decrypt any of the
 * recorded data.
 *
 * The key exchange consists of four messages. Eventually, the first one or two
 * will be able to be omitted if the client/server already know each other's
 * public keys, but that isn't implemented yet.
 *
 *	SERVER  <--- kx_msg_0 ---    CLIENT (DGRAM only)
 *	SERVER   --- kx_msg_1 --->   CLIENT
 *	SERVER  <--- kx_msg_2 ---    CLIENT
 *	SERVER   --- kx_msg_3 --->   CLIENT
 *
 * After that, everything is encrypted with the ECDH derived keys.
 *
 *	SERVER  <--- c_setup ---     CLIENT
 *	SERVER   --- s_setup --->    CLIENT
 *	SERVER  <<<<< VIDEO <<<<     CLIENT
 *	SERVER  <<<<< VIDEO <<<<     CLIENT
 **/

/*
 * CLIENT -> SERVER (DGRAM sockets only)
 *
 * The daemon will accept any dgram >= HELLOLEN in length.
 */

struct kx_msg_0 {
	uint8_t zeros[SDVR_HELLOPAD];

} __attribute__((packed));

/*
 * SERVER -> CLIENT
 *
 * For STREAM sockets, this is the initial message.
 */

struct kx_msg_1 {
	uint8_t pk[SDVR_PKLEN];

} __attribute__((packed));

/*
 * BOTH DIRECTIONS
 *
 * ECDH key exchange material, shared between msg_2 and msg_3.
 */

struct kx_material {
	uint8_t kx_p[SDVR_PLEN];
	uint8_t s_nonce[SDVR_NONCELEN];

} __attribute__((packed));

/*
 * CLIENT -> SERVER
 *
 * If the client already knows the server PK, this may be the initial message
 * sent in DGRAM mode. In STREAM mode the server PK is always sent, but the
 * client does not need to wait for it.
 */

struct kx_msg_2_text {
	struct kx_material kxm;

} __attribute__((packed));

struct kx_msg_2 {
	uint8_t pk[SDVR_PKLEN];
	uint8_t kx_nonce[SDVR_NONCELEN];
	uint8_t text_mac[SDVR_MACLEN];
	struct kx_msg_2_text text;

} __attribute__((packed));

/*
 * SERVER -> CLIENT
 *
 * To encrypt msg_2, the client must have already known the server PK, so it is
 * not included in msg_3. The cookie is ignored for STREAM sockets.
 */

struct kx_msg_3_text {
	struct kx_material kxm;
	uint32_t cookie;

} __attribute__((packed));

struct kx_msg_3 {
	uint8_t kx_nonce[SDVR_NONCELEN];
	uint8_t text_mac[SDVR_MACLEN];
	struct kx_msg_3_text text;

} __attribute__((packed));

/*
 * Setup data for both server and client.
 */

struct client_setup_desc {
	char name[SDVR_NAMELEN];
	uint32_t pixelformat;
	uint32_t fps_numerator;
	uint32_t fps_denominator;
	uint32_t width;
	uint32_t height;

} __attribute__((packed));

struct server_setup_desc {
	char name[SDVR_NAMELEN];
	uint16_t max_payload;

} __attribute__((packed));

/*
 * The "header" record that precedes frame data for STREAM sockets.
 */

struct frame_desc {
	int64_t pts_mono_us;
	int64_t tx_mono_us;
	uint32_t sequence;
	uint32_t length;
	uint32_t chunk_size;

} __attribute__((packed));

/*
 * DGRAM cookies 0x00000000 and 0xffffffff are reserved for the key exchange.
 */

#define SDVR_COOKIE_ZEROS	((uint32_t)0)
#define SDVR_COOKIE_ONES	((uint32_t)0-1)

struct kx_dgram {
	uint32_t zeros_or_ones;

	union {
		struct kx_msg_0 m0;	// zeros: client -> server
		struct kx_msg_1 m1;	// zeros: server -> client
		struct kx_msg_2 m2;	// ones:  client -> server
		struct kx_msg_3 m3;	// ones:  server -> client
	};

} __attribute__((packed));

/*
 * DGRAM structures for exchanging setup data.
 */

struct client_setup_dgram_text {
	struct client_setup_desc desc;

} __attribute__((packed));

struct client_setup_dgram {
	uint32_t cookie;

	uint64_t nonce;
	uint8_t text_mac[SDVR_MACLEN];
	struct client_setup_dgram_text text;

} __attribute__((packed));

struct server_setup_dgram_text {
	struct server_setup_desc desc;

} __attribute__((packed));

struct server_setup_dgram {
	uint64_t nonce;
	uint8_t text_mac[SDVR_MACLEN];
	struct server_setup_dgram_text text;

} __attribute__((packed));

/*
 * The header for each record in DGRAM sockets.
 *
 * Sending PTS/SEQ/LEN with every record is unnecessary, but costs very little
 * and makes life a lot simpler for the daemon.
 */

struct dgram_frame {
	uint32_t frame_pts_mono_us;
	uint32_t frame_sequence;
	uint32_t frame_length;
	uint32_t offset;

	uint8_t data[];

} __attribute__((packed));

/*
 * DGRAM video packet structure.
 *
 * Clients are multiplexed using a 32-bit "cookie" value, allowing a single UDP
 * port to serve 2^32 clients. The same scheme is used for raw ethernet frames.
 *
 * The daemon does not care what the source address is: the only requirement is
 * that during the key exchange, a reply to the source address be routed back to
 * the client.
 */

struct dgram {
	uint32_t cookie;
	uint64_t nonce;

	uint8_t text_mac[SDVR_MACLEN];
	struct dgram_frame text;

} __attribute__((packed));
