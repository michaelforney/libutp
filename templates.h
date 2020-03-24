#ifndef __TEMPLATES_H__
#define __TEMPLATES_H__

#include <assert.h>

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

#endif //__TEMPLATES_H__
