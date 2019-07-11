#ifndef __TEMPLATES_H__
#define __TEMPLATES_H__

#include <assert.h>

#if defined(POSIX)
/* Allow over-writing FORCEINLINE from makefile because gcc 3.4.4 for buffalo
   doesn't seem to support __attribute__((always_inline)) in -O0 build
   (strangely, it works in -Os build) */
#ifndef FORCEINLINE
// The always_inline attribute asks gcc to inline the function even if no optimization is being requested.
// This macro should be used exclusive-or with the inline directive (use one or the other but not both)
// since Microsoft uses __forceinline to also mean inline,
// and this code is following a Microsoft compatibility model.
// Just setting the attribute without also specifying the inline directive apparently won't inline the function,
// as evidenced by multiply-defined symbols found at link time.
#define FORCEINLINE inline __attribute__((always_inline))
#endif
#endif

#ifdef __GNUC__
// Used for gcc tool chains accepting but not supporting pragma pack
// See http://gcc.gnu.org/onlinedocs/gcc/Type-Attributes.html
#define PACKED_ATTRIBUTE __attribute__((__packed__))
#else
#define PACKED_ATTRIBUTE
#endif

#ifdef __GNUC__
#define ALIGNED_ATTRIBUTE(x)  __attribute__((aligned (x)))
#else
#define ALIGNED_ATTRIBUTE(x)
#endif

// Utility templates
#undef min
#undef max

static inline uintmax_t min(uintmax_t a, uintmax_t b)
{
	return a < b ? a : b;
}

static inline uintmax_t max(uintmax_t a, uintmax_t b)
{
	return a > b ? a : b;
}

/* XXX: Is this really needed? Can conn->send_quota ever be negative? */
static inline intmax_t smin(intmax_t a, intmax_t b)
{
	return a < b ? a : b;
}

/* XXX: Is this really needed? Can rtt ever be negative? */
static inline intmax_t smax(intmax_t a, intmax_t b)
{
	return a > b ? a : b;
}

#if (defined(__SVR4) && defined(__sun))
#pragma pack(1)
#else
#pragma pack(push,1)
#endif

typedef uint32_t uint32_big;
typedef uint16_t uint16_big;

#if (defined(__SVR4) && defined(__sun))
#pragma pack(0)
#else
#pragma pack(pop)
#endif

#endif //__TEMPLATES_H__
