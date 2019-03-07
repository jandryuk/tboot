#include <errno.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include "platform.h"
#include "uuid.h"
#include "acm.h"
#include "txt.h"

#define printe(fmt, ...)         fprintf(stderr, fmt "\n", ##__VA_ARGS__)

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
}

int main(int argc, char *argv[])
{
	int rc, opt, i, match = 0;
	txt_cr_didvid_t didvid = { 0 };
	txt_cr_ver_fsbif_t fsbif = { 0 };
	txt_cr_ver_qpiif_t qpiif = { 0 };
	cpuid_proc_sig_eax_t sig;
	msr_ia32_platform_id_t msr;

	do {
		opt = getopt(argc, argv, "Dh");
		switch (opt) {
			case 'h':
				usage(argv[0]);
				return 0;
			case -1:
				continue;
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

	if (!access_txt_crs()) {
		printe("Cannot access TXT control registers."
			" Is module txt loaded?");
		return ENOENT;
	}

	if (!access_msr_devnode()) {
		printe("Cannot access MSRs. Is module msr loaded?");
		return ENOENT;
	}

	if (read_txt_cr_didvid(&didvid) < 0)
		return ENOSYS;
	if (read_txt_cr_ver_fsbif(&fsbif) < 0)
		return ENOSYS;
	if (read_txt_cr_ver_qpiif(&qpiif) < 0)
		return ENOSYS;

	sig.raw = cpuid_eax(0x1);
	msr.raw = rdmsr(MSR_IA32_PLATFORM_ID);

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
					printe("Error while loading ACM: %s.",
						strerror(-rc));
					return rc;
			}
		} else if (!rc) {
			match = 1;
			printf("Platform matches ACM %s.\n", argv[i]);
		}
	}

	return match ? 0 : 1;
}
