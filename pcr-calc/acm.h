#ifndef _ACM_H_
# define _ACM_H_

# include <stddef.h>
# include <inttypes.h>

# include "../include/mle.h"

/*
 * ACM flags; tboot:acmod.h
 */
typedef union {
	uint16_t raw;
	struct {
		uint16_t  reserved       : 14;
		uint16_t  pre_production : 1;
		uint16_t  debug_signed   : 1;
	};
} acm_flags_t;

/*
 * ACM header; tboot:acmod.h
 */
typedef struct {
#define MODULE_TYPE_CHIPSET 0x02
	uint16_t     module_type;

#define ACM_SUBTYPE_RESET   0x01
	uint16_t     module_subtype;

	uint32_t     header_len;
	uint32_t     header_ver;    /* currently 0.0 */
	uint16_t     chipset_id;
	acm_flags_t  flags;

#define ACM_VENDOR_INTEL    0x8086
	uint32_t     module_vendor;

	uint32_t     date;
	uint32_t     size;
	uint16_t     txt_svn;
	uint16_t     se_svn;
	uint32_t     code_control;
	uint32_t     error_entry_point;
	uint32_t     gdt_limit;
	uint32_t     gdt_base;
	uint32_t     seg_sel;
	uint32_t     entry_point;
	uint8_t      reserved2[64];
	uint32_t     key_size;
	uint32_t     scratch_size;
	uint8_t      rsa2048_pubkey[256];
	uint32_t     pub_exp;
	uint8_t      rsa2048_sig[256];
	uint32_t     scratch[143];
	uint8_t      user_area[];
}__attribute__((packed)) acm_hdr_t;

/*
 * ACM Info table; tboot:acmod.h
 */
typedef struct {
#define ACM_UUID_V3	((uuid_t){0x7fc03aaa, 0x46a7, 0x18db, 0xac2e, \
		{0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a}})
	uuid_t     uuid;

#define ACM_TYPE_BIOS               0x0
#define ACM_TYPE_SINIT              0x1
#define ACM_TYPE_MASK               0x7
#define ACM_TYPE_REVOCATION_MASK    0x8
	uint8_t    chipset_acm_type;
	uint8_t    version;             /* currently 4 */
	uint16_t   length;
	uint32_t   chipset_id_list;
	uint32_t   os_sinit_data_ver;
	uint32_t   min_mle_hdr_ver;
	txt_caps_t capabilities;
	uint8_t    acm_ver;
	uint8_t    reserved[3];
	/* versions>= 4 */
	uint32_t   processor_id_list;
	/* versions>= 5 */
	uint32_t   tpm_info_list_off;
}__attribute__((packed)) acm_info_table_t;

/*
 * ACM Processor IDs; tboot:acmod.h
 */
typedef struct {
	uint32_t fms;
	uint32_t fms_mask;
	uint64_t platform_id;
	uint64_t platform_mask;
}__attribute__((packed)) acm_processor_id_t;

/*
 * ACM Processor ID list; tboot:acmod.h
 */
typedef struct {
	uint32_t             count;
	acm_processor_id_t   processor_ids[];
}__attribute__((packed)) acm_processor_id_list_t;

/*
 * ACM Chipset IDs; tboot:acmod.h
 */
typedef struct {
#define CHIPSET_FLAGS_REVISION_MASK 0x1
	uint32_t flags;
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t revision_id;
	uint16_t reserved;
	uint32_t extended_id;
}__attribute__((packed)) acm_chipset_id_t;

/*
 * ACM Chipset IDs list; tboot:acmod.h
 */
typedef struct {
	uint32_t            count;
	acm_chipset_id_t    chipset_ids[];
}__attribute__((packed)) acm_chipset_id_list_t;

/*
 * ACM main abstraction struct.
 */
struct acm {
	acm_hdr_t *header;
	acm_info_table_t *infotable;
	acm_processor_id_list_t *cpulist;
	acm_chipset_id_list_t *chiplist;
	size_t size;
};

struct acm *acm_load(const char *path);
void acm_unload(struct acm *acm);

#endif /* _ACM_H_ */
