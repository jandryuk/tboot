#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "platform.h"

#define printe(fmt, ...)         fprintf(stderr, fmt "\n", ##__VA_ARGS__)

int read_u32(const char *path, uint32_t *v)
{
	int fd;
	ssize_t rc = 0;
	char buf[12] = { 0 };   /* "0xVVVVVVVV\n\0" */
	char *end;
	unsigned long a;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = read(fd, buf, sizeof (buf));
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	a = strtoul(buf, &end, 0);
	if (end != (buf + rc - 1)) {
		rc = -EINVAL;
		goto out;
	}

	*v = a;

out:
	close(fd);
	return rc;
}

int read_u64(const char *path, uint64_t *v)
{
	int fd;
	ssize_t rc = 0;
	char buf[19] = { 0 };   /* "0xVVVVVVVVVVVVVVVV\n\0" */
	char *end;
	unsigned long long a;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = read(fd, buf, sizeof (buf));
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	a = strtoull(buf, &end, 0);
	if (end != (buf + rc - 1)) {
		rc = -EINVAL;
		goto out;
	}

	*v = a;

out:
	close(fd);
	return rc;
}

uint64_t rdmsr(int msr)
{
	int fd, rc;
	uint64_t val;

	fd = open(MSR_DEVNODE, O_RDONLY);
	if (fd < 0) {
		printe("open failed: %s. Is module `msr' loaded?",
			strerror(errno));
		return -1ULL;
	}

	rc = lseek(fd, msr, SEEK_SET);
	if (rc < 0) {
		printe("lseek failed: %s.", strerror(errno));
		return -1ULL;
	} else if (rc != msr) {
		printe("failed to seek msr value in " MSR_DEVNODE ".");
		return -1ULL;
	}

	rc = read(fd, &val, sizeof (val));
	if (rc < 0) {
		printe("read failed: %s.", strerror(errno));
		return -1ULL;
	} else if (rc != sizeof (val)) {
		printe("failed to read msr value in " MSR_DEVNODE ".");
		return -1ULL;
	}

	return val;
}
