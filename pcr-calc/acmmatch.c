#include <errno.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "platform.h"
#include "uuid.h"
#include "acm.h"
#include "txt.h"

#define printe(fmt, ...)         fprintf(stderr, fmt "\n", ##__VA_ARGS__)

int parse_u32(const char *s, uint32_t *v)
{
	size_t len;
	char *end;
	unsigned long a;

	len = strnlen(s, 11);   /* 0xVVVVVVVV\0 */
	if (len >= 11)
		return -EINVAL;

	a = strtoul(s, &end, 0);
	if (end != (s + len)) {
		*v = 0;
		return -EINVAL;
	}

	*v = a;
	return 0;
}

int parse_u64(const char *s, uint64_t *v)
{
	size_t len;
	char *end;
	unsigned long long a;

	len = strnlen(s, 19);   /* 0xVVVVVVVVVVVVVVVV\0 */
	if (len >= 19)
		return -EINVAL;

	a = strtoull(s, &end, 0);
	if (end != (s + len)) {
		*v = 0;
		return -EINVAL;
	}

	*v = a;
	return 0;
}

static int acm_is_debug(const struct acm *acm,
		const txt_cr_ver_fsbif_t *fsbif,
		const txt_cr_ver_qpiif_t *qpiif)
{
	acm_hdr_t *header = acm->header;

	switch (fsbif->raw) {
		case 0xffffffff:
		case 0x00000000:
			return header->flags.debug_signed == qpiif->debug;
		default:
			return header->flags.debug_signed == fsbif->debug;
	}
}

static int acm_is_sinit(const struct acm *acm)
{
	acm_hdr_t *header = acm->header;
	acm_info_table_t *infotable = acm->infotable;

	return header->module_type == MODULE_TYPE_CHIPSET &&
		!(infotable->chipset_acm_type & ACM_TYPE_REVOCATION_MASK) &&
		infotable->chipset_acm_type == ACM_TYPE_SINIT;
}

static int acm_match_chipset(const struct acm *acm,
		const txt_cr_didvid_t *didvid)
{
	acm_chipset_id_list_t *chiplist = acm->chiplist;
	unsigned int i;
	int match = 0;

	for (i = 0; !match && i < chiplist->count; ++i) {
		acm_chipset_id_t *chipset = &chiplist->chipset_ids[i];

		if (chipset->vendor_id == didvid->vid &&
		    chipset->device_id == didvid->did) {
			if (chipset->flags & CHIPSET_FLAGS_REVISION_MASK)
				match = !!(chipset->revision_id & didvid->rid);
			else
				match = chipset->revision_id == didvid->rid;
		}
	}

	return match;
}

static int acm_match_cpu(struct acm *acm,
		const cpuid_proc_sig_eax_t *sig,
		const msr_ia32_platform_id_t *msr)
{
	acm_processor_id_list_t *cpulist = acm->cpulist;
	unsigned int i;
	int match = 0;

	for (i = 0; !match && i < cpulist->count; ++i) {
		acm_processor_id_t *cpu = &cpulist->processor_ids[i];

		if (cpu->fms == (sig->raw & cpu->fms_mask) &&
		    cpu->platform_id == (msr->raw & cpu->platform_mask))
			match = 1;
	}

	return match;
}

/*
 * Attempts to load the file at path as an ACM.
 * Return -EINVAL, if the ACM is invalid
 *        -ENOSYS, if the platform does not provide the necessary information,
 * 0 if the ACM matches the current platform,
 * 1 if the ACM _does not_ match the current platform.
 */
int platform_match_acm(const char *path,
	const txt_cr_didvid_t *didvid,
	const txt_cr_ver_fsbif_t *fsbif,
	const txt_cr_ver_qpiif_t *qpiif,
	const cpuid_proc_sig_eax_t *sig,
	const msr_ia32_platform_id_t *msr)
{
	struct acm *acm;
	int rc;

	assert(path != NULL);

	acm = acm_load(path);
	if (acm == NULL)
		return -EINVAL;

	if (acm_is_debug(acm, fsbif, qpiif)) {
		rc = 1;
		goto out;
	}

	if (!acm_is_sinit(acm)) {
		rc = 1;
		goto out;
	}

	if (!acm_match_chipset(acm, didvid)) {
		rc = 1;
		goto out;
	}

	if (acm->cpulist != NULL)
		/* Only infotables version 4 and above include a cpulist. */
		if (!acm_match_cpu(acm, sig, msr)) {
			rc = 1;
			goto out;
		}

	rc = 0;

out:
	acm_unload(acm);
	return rc;
}

static void usage(const char *name)
{
	assert(name != NULL);
	printf("Usage: %s [-h] ACM [ACMs]\n", name);
	printf("Parse the given ACMs and display which match the current"
		" platform on stdout.\n");
	printf("    -h  Display this help.\n");
	printf("    -d didvid   Provide the didvid value to be used (instead of reading TXT public configuration registers).\n");
	printf("    -f fsbif    Provide the fsbif value to be used (instead of reading TXT public configuration registers).\n");
	printf("    -q qpiif    Provide the qpiif value to be used (instead of reading TXT public configuration registers).\n");
	printf("    -p msr-pid  Provide the MSR platform ID value to be used (instead of reading MSR devnodes).\n");
	printf("    -s cpuid    Provide the cpuid signature value to be used (instead of running CPUID).\n");
}

enum {
	FLAG_DIDVID	= 1 << 0,
	FLAG_FSBIF	= 1 << 1,
	FLAG_QPIIF	= 1 << 2,
	FLAG_CPUID_SIG	= 1 << 3,
	FLAG_MSR_PID	= 1 << 4,
};

int main(int argc, char *argv[])
{
	int rc, opt, i, match = 0;
	uint32_t flags = 0;
	const uint32_t fmask = FLAG_DIDVID | FLAG_FSBIF | FLAG_QPIIF;
	txt_cr_didvid_t didvid = { 0 };
	txt_cr_ver_fsbif_t fsbif = { 0 };
	txt_cr_ver_qpiif_t qpiif = { 0 };
	cpuid_proc_sig_eax_t sig;
	msr_ia32_platform_id_t msr;

	do {
		opt = getopt(argc, argv, "hd:q:f:p:s:");
		switch (opt) {
			case 'h':
				usage(argv[0]);
				return 0;
			case -1:
				continue;
			case 'd':
				rc = parse_u64(optarg, &didvid.raw);
				if (rc < 0) {
					printe("Invalid DIDVID value provided to -d.");
					return rc;
				}
				flags |= FLAG_DIDVID;
			break;
			case 'q':
				rc = parse_u32(optarg, &qpiif.raw);
				if (rc < 0) {
					printe("Invalid QPIIF value provided to -q.");
					return rc;
				}
				flags |= FLAG_QPIIF;
				break;
			case 'f':
				rc = parse_u32(optarg, &fsbif.raw);
				if (rc < 0) {
					printe("Invalid FSBIF value provided to -f.");
					return rc;
				}
				flags |= FLAG_FSBIF;
				break;
			case 'p':
				rc = parse_u64(optarg, &msr.raw);
				if (rc < 0) {
					printe("Invalid MSR platform ID value provided to -p.");
					return rc;
				}
				flags |= FLAG_MSR_PID;
				break;
			case 's':
				rc = parse_u32(optarg, &sig.raw);
				if (rc < 0) {
					printe("Invalid CPUID signature value provided to -s.");
					return rc;
				}
				flags |= FLAG_CPUID_SIG;
			break;

			default:
				usage(argv[0]);
				return EINVAL;
		}
	} while (opt != -1);

	if (optind >= argc) {
		printe("Missing path(s) to ACM file(s).");
		usage(argv[0]);
		return EINVAL;
	}

	if (!flags || ((flags & fmask) != fmask)) {
		if (!access_txt_crs()) {
			printe("Cannot access TXT control registers."
				" Is module txt loaded?");
			return ENOENT;
		}

		if (!(flags & FLAG_DIDVID)) {
			if (read_txt_cr_didvid(&didvid) < 0)
				return ENOSYS;
		}
		if (!(flags & FLAG_FSBIF)) {
			if (read_txt_cr_ver_fsbif(&fsbif) < 0)
				return ENOSYS;
		}
		if (!(flags & FLAG_QPIIF)) {
			if (read_txt_cr_ver_qpiif(&qpiif) < 0)
				return ENOSYS;
		}
	}

	if (!(flags & FLAG_CPUID_SIG))
		sig.raw = cpuid_eax(0x1);

	if (!(flags & FLAG_MSR_PID)) {
		if (!access_msr_devnode()) {
			printe("Cannot access MSRs. Is module msr loaded?");
			return ENOENT;
		}
		msr.raw = rdmsr(MSR_IA32_PLATFORM_ID);
	}

	for (i = optind; i < argc; ++i) {
		rc = platform_match_acm(argv[i],
					&didvid, &fsbif, &qpiif, &sig, &msr);
		if (rc < 0) {
			switch (rc) {
				case -EINVAL:
					printe("Invalid ACM: %s.", argv[i]);
					break;
				case -ENOSYS:
					printe("Could not read platform data."
						"You may need to load modules:"
						" msr, txt_info.");
					return rc;
				default:
					printe("Error while loading ACM: %s.", strerror(-rc));
					return rc;
			}
		} else if (!rc) {
			match = 1;
			printf("Platform matches ACM %s.\n", argv[i]);
		}
	}

	return match ? 0 : 1;
}
