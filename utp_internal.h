/*
 * Copyright (c) 2010-2013 BitTorrent, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __UTP_INTERNAL_H__
#define __UTP_INTERNAL_H__

#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "utp.h"
#include "utp_callbacks.h"
#include "utp_templates.h"
#include "utp_hash.h"
#include "utp_packedsockaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These originally lived in utp_config.h */
#define CCONTROL_TARGET (100 * 1000) // us

typedef enum {
	payload_bandwidth, connect_overhead,
	close_overhead, ack_overhead,
	header_overhead, retransmit_overhead
} bandwidth_type_t;

#ifdef WIN32
	#ifdef _MSC_VER
		#include "libutp_inet_ntop.h"
	#endif

	// newer versions of MSVC define these in errno.h
	#ifndef ECONNRESET
		#define ECONNRESET WSAECONNRESET
		#define EMSGSIZE WSAEMSGSIZE
		#define ECONNREFUSED WSAECONNREFUSED
		#define ETIMEDOUT WSAETIMEDOUT
	#endif
#endif

typedef struct RST_Info RST_Info;
struct PACKED_ATTRIBUTE RST_Info {
	PackedSockAddr addr;
	uint32 connid;
	uint16 ack_nr;
	uint64 timestamp;
};

typedef struct UTPSocket UTPSocket;

typedef struct UTPSocketKey UTPSocketKey;
struct UTPSocketKey {
	PackedSockAddr addr;
	uint32 recv_id;		 // "conn_seed", "conn_id"
};

uint utp_socket_comp(const void *key_a, const void *key_b, size_t keysize);
uint32 utp_socket_hash(const void *keyp, size_t keysize);

typedef struct UTPSocketKeyData UTPSocketKeyData;
struct UTPSocketKeyData {
	UTPSocketKey key;
	UTPSocket *socket;
	utp_link_t link;
};

#define UTP_SOCKET_BUCKETS 79
#define UTP_SOCKET_INIT    15

// It's really important that we don't have duplicate keys in the hash table.
// If we do, we'll eventually crash. if we try to remove the second instance
// of the key, we'll accidentally remove the first instead. then later,
// checkTimeouts will try to access the second one's already freed memory.
void UTP_FreeAll(utp_hash_t *utp_sockets);

struct struct_utp_context {
	void *userdata;
	utp_callback_t* callbacks[UTP_ARRAY_SIZE];

	uint64 current_ms;
	utp_context_stats context_stats;
	UTPSocket *last_utp_socket;
	UTPSocket **ack_sockets;
	size_t ack_sockets_count;
	size_t ack_sockets_alloc;
	RST_Info *rst_info;
	size_t rst_info_count;
	size_t rst_info_alloc;
	utp_hash_t *utp_sockets;
	size_t target_delay;
	size_t opt_sndbuf;
	size_t opt_rcvbuf;
	uint64 last_check;

	bool log_normal:1;	// log normal events?
	bool log_mtu:1;		// log MTU related events?
	bool log_debug:1;	// log debugging events? (Must also compile with UTP_DEBUG_LOGGING defined)
};

void utp_context_log(utp_context *ctx, int level, utp_socket *socket, char const *fmt, ...);
void utp_context_log_unchecked(utp_context *ctx, utp_socket *socket, char const *fmt, ...);
bool utp_context_would_log(utp_context *ctx, int level);

#ifdef __cplusplus
}
#endif

#endif //__UTP_INTERNAL_H__
