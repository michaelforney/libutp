// vim:set ts=4 sw=4 ai:

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

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "utp_types.h"
#include "utp_hash.h"
#include "utp_packedsockaddr.h"

#include "libutp_inet_ntop.h"

byte PackedSockAddr_get_family(const PackedSockAddr *addr)
{
	#if defined(__sh__)
		return ((addr->_sin6d[0] == 0) && (addr->_sin6d[1] == 0) && (addr->_sin6d[2] == htonl(0xffff)) != 0) ?
			AF_INET : AF_INET6;
	#else
		return (IN6_IS_ADDR_V4MAPPED(&addr->_in._in6addr) != 0) ? AF_INET : AF_INET6;
	#endif // defined(__sh__)
}

bool PackedSockAddr_equal(const PackedSockAddr *lhs, const PackedSockAddr *rhs)
{
	if (lhs == rhs)
		return true;
	if (lhs->_port != rhs->_port)
		return false;
	return memcmp(lhs->_sin6, rhs->_sin6, sizeof(lhs->_sin6)) == 0;
}

void PackedSockAddr_set(PackedSockAddr *addr, const SOCKADDR_STORAGE* sa, socklen_t len)
{
	if (sa->ss_family == AF_INET) {
		assert(len >= sizeof(struct sockaddr_in));
		const struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		addr->_sin6w[0] = 0;
		addr->_sin6w[1] = 0;
		addr->_sin6w[2] = 0;
		addr->_sin6w[3] = 0;
		addr->_sin6w[4] = 0;
		addr->_sin6w[5] = 0xffff;
		addr->_sin4 = sin->sin_addr.s_addr;
		addr->_port = ntohs(sin->sin_port);
	} else {
		assert(len >= sizeof(struct sockaddr_in6));
		const struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		addr->_in._in6addr = sin6->sin6_addr;
		addr->_port = ntohs(sin6->sin6_port);
	}
}

SOCKADDR_STORAGE PackedSockAddr_get_sockaddr_storage(const PackedSockAddr *addr, socklen_t *len)
{
	SOCKADDR_STORAGE sa;
	const byte family = PackedSockAddr_get_family(addr);
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)&sa;
		if (len) *len = sizeof(struct sockaddr_in);
		memset(sin, 0, sizeof(struct sockaddr_in));
		sin->sin_family = family;
		sin->sin_port = htons(addr->_port);
		sin->sin_addr.s_addr = addr->_sin4;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&sa;
		memset(sin6, 0, sizeof(struct sockaddr_in6));
		if (len) *len = sizeof(struct sockaddr_in6);
		sin6->sin6_family = family;
		sin6->sin6_addr = addr->_in._in6addr;
		sin6->sin6_port = htons(addr->_port);
	}
	return sa;
}

// #define addrfmt(x, s) x.fmt(s, sizeof(s))
cstr PackedSockAddr_fmt(const PackedSockAddr *addr, str s, size_t len)
{
	memset(s, 0, len);
	const byte family = PackedSockAddr_get_family(addr);
	str i;
	if (family == AF_INET) {
		INET_NTOP(family, (uint32*)&addr->_sin4, s, len);
		i = s;
		while (*++i) {}
	} else {
		i = s;
		*i++ = '[';
		INET_NTOP(family, (struct in6_addr*)&addr->_in._in6addr, i, len-1);
		while (*++i) {}
		*i++ = ']';
	}
	snprintf(i, len - (i-s), ":%u", addr->_port);
	return s;
}
