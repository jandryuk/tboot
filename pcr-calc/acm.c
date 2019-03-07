#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "uuid.h"
#include "acm.h"

#define DEBUG 0
#define printd(fmt, ...)					\
	if (DEBUG) {						\
		fprintf(stdout, fmt "\n", ##__VA_ARGS__);	\
	}

static acm_hdr_t *get_acm_header(void *p)
{
	uint32_t res;
	acm_hdr_t *hdr = p;

	if (__builtin_umul_overflow(hdr->size, 4, &res))
		return NULL;
	if (hdr->module_type != MODULE_TYPE_CHIPSET)
		return NULL;
	if (hdr->module_vendor != ACM_VENDOR_INTEL)
		return NULL;

	return hdr;
}

static acm_info_table_t *get_acm_info_table(const acm_hdr_t *hdr)
{
	uint32_t res;
	uint32_t offset;
	acm_info_table_t *infotable;

	/* Check infotable is in ACM. */
	if (__builtin_uadd_overflow(hdr->header_len, hdr->scratch_size, &res))
		return NULL;
	if (__builtin_umul_overflow(res, 4, &res))
		return NULL;
	if (res > hdr->size * 4)
		return NULL;

	offset = (hdr->header_len + hdr->scratch_size) * 4;

	/* Check infotable does not outbound ACM. */
	if (__builtin_uadd_overflow(res, sizeof (*infotable), &res))
		return NULL;
	if (res > hdr->size * 4)
		return NULL;

	return (acm_info_table_t *)((void *)hdr + offset);
}

static acm_processor_id_list_t *get_acm_processor_list(const acm_hdr_t *hdr,
		const acm_info_table_t *infotable)
{
	uint32_t res1, res2;
	uint32_t offset;
	acm_processor_id_list_t *proclist;

	offset = infotable->processor_id_list;
	proclist = (acm_processor_id_list_t *)((void *)hdr + offset);

	/* Check proclist is contained in ACM size. */
	if (__builtin_umul_overflow(
		proclist->count, sizeof (acm_processor_id_t), &res1))
		return NULL;
	if (__builtin_uadd_overflow(offset, sizeof (proclist->count), &res2))
		return NULL;
	if (__builtin_uadd_overflow(res1, res2, &res1))
		return NULL;
	if (res1 > hdr->size * 4)
		return NULL;

	return proclist;
}

static acm_chipset_id_list_t *get_acm_chipset_list(const acm_hdr_t *hdr,
		const acm_info_table_t *infotable)
{
	uint32_t res1, res2;
	uint32_t offset;
	acm_chipset_id_list_t *chiplist;

	offset = infotable->chipset_id_list;
	chiplist = (acm_chipset_id_list_t *)((void *)hdr + offset);

	/* Check chiplist is contained in ACM size. */
	if (__builtin_umul_overflow(
		chiplist->count, sizeof (acm_chipset_id_t), &res1))
		return NULL;
	if (__builtin_uadd_overflow(offset, sizeof (chiplist->count), &res2))
		return NULL;
	if (__builtin_uadd_overflow(res1, res2, &res1))
		return NULL;
	if (res1 > hdr->size * 4)
		return NULL;

	return chiplist;
}

static int uuids_equal(const uuid_t *u1, const uuid_t *u2)
{
	return (u1->data1 == u2->data1 &&
		u1->data2 == u2->data2 &&
		u1->data3 == u2->data3 &&
		u1->data4 == u2->data4 &&
		u1->data5[0] == u2->data5[0] &&
		u1->data5[1] == u2->data5[1] &&
		u1->data5[2] == u2->data5[2] &&
		u1->data5[3] == u2->data5[3] &&
		u1->data5[4] == u2->data5[4] &&
		u1->data5[5] == u2->data5[5]);
}

struct acm *acm_load(const char *path)
{
	int fd;
	void *p;
	struct stat sb;
	struct acm *acm;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printd("Failed to open file `%s': %s", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &sb)) {
		printd("Failed to get file `%s' status: %s", path, strerror(errno));
		goto fail_stat;
	}

	acm = malloc(sizeof (*acm));
	if (!acm) {
		printd("malloc failed: %s", strerror(errno));
		goto fail_alloc;
	}

	acm->size = sb.st_size;
	if (acm->size < sizeof (acm_hdr_t)) {
		printd("Invalid ACM %s: Too small.", path);
		goto fail_sanity;
	}

	p = mmap(NULL, acm->size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == NULL) {
		printd("mmap failed: %s", strerror(errno));
		goto fail_map;
	}
	close(fd);

	acm->header = get_acm_header(p);
	if (acm->header == NULL) {
		printd("Invalid ACM %s: Header cannot be found.", path);
		goto fail_map;
	}

	acm->infotable = get_acm_info_table(acm->header);
	if (acm->infotable == NULL) {
		printd("Invalid ACM %s: Info table cannot be found.", path);
		goto fail_map;
	}

	if (!uuids_equal(&acm->infotable->uuid, &ACM_UUID_V3)) {
		printd("Invalid ACM %s: UUID mismatch.", path);
		goto fail_map;
	}

	acm->chiplist = get_acm_chipset_list(acm->header, acm->infotable);
	if (acm->chiplist == NULL) {
		printd("Invalid ACM %s: Chipset list cannot be found.", path);
		goto fail_map;
	}

	if (acm->infotable->version < 4)
		acm->cpulist = NULL;
	else {
		acm->cpulist = get_acm_processor_list(acm->header, acm->infotable);
		if (acm->cpulist == NULL) {
			printd("Invalid ACM %s: Processor list cannot be found.", path);
			goto fail_map;
		}
	}

	return acm;

fail_map:
	munmap(acm->header, acm->size);
fail_sanity:
	free(acm);
fail_alloc:
fail_stat:
	close(fd);

	return NULL;
}

void acm_unload(struct acm *acm)
{
	munmap(acm->header, acm->size);
	free(acm);
}
