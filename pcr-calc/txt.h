#ifndef _TXT_H_
# define _TXT_H_

# include <inttypes.h>
# include <unistd.h>

# define TXT_INFO_SYSFS "/sys/devices/platform/txt/"

typedef union {
	uint64_t raw;
	struct {
		uint16_t vid    : 16;
		uint16_t did    : 16;
		uint16_t rid    : 16;
		uint16_t ext    : 16;
	};
} txt_cr_didvid_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t _res   : 31;
		uint8_t debug   : 1;
	};
} txt_cr_ver_fsbif_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t _res   : 31;
		uint8_t debug   : 1;
	};
} txt_cr_ver_qpiif_t;

# define DECLARE_READ_TXT(entry, size)                          \
	static inline int read_txt_cr_##entry(txt_cr_##entry##_t *e)    \
{                                                               \
	return read_##size(TXT_INFO_SYSFS #entry, &e->raw);         \
}
DECLARE_READ_TXT(didvid, u64);
DECLARE_READ_TXT(ver_fsbif, u32);
DECLARE_READ_TXT(ver_qpiif, u32);

static inline int access_txt_crs(void)
{
	return !access(TXT_INFO_SYSFS "didvid", R_OK) &&
		!access(TXT_INFO_SYSFS "ver_fsbif", R_OK) &&
		!access(TXT_INFO_SYSFS "ver_qpiif", R_OK);
}

#endif /* _TXT_H_ */
