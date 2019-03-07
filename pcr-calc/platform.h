#ifndef _PLATFORM_H_
# define _PLATFORM_H_

# include <inttypes.h>
# include <unistd.h>

/*
 * Low-level helpers.
 */
/* MSR devnode exposed by the Linux msr module. */
# define MSR_DEVNODE "/dev/cpu/0/msr"
/* See Intel SDM Vol3A 9.11.4. */
# define MSR_IA32_PLATFORM_ID    0x17U

static inline void __cpuid(unsigned int ax, uint32_t *p)
{
	asm volatile (
		"cpuid"
		: "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3]) /* outputs */
		: "0" (ax)                                           /* inputs */
	);
}

/* Output in EAX of CPUID EAX=1. */
typedef union {
	uint32_t raw;
	struct {
		uint32_t step:4;
		uint32_t model:4;
		uint32_t family:4;
		uint32_t type:2;
		uint32_t _res0:2;
		uint32_t model_ext:4;
		uint32_t family_ext:8;
		uint32_t _res1:4;
	};
} cpuid_proc_sig_eax_t;

/* RDMDR 0x17: IA32_PLATFORM_ID. */
typedef union {
	uint64_t raw;
	struct {
		uint64_t _res0:50;
		uint32_t id:3;
		uint32_t _res1:11;
	};
} msr_ia32_platform_id_t;

static inline uint32_t cpuid_eax(unsigned int op)
{
	uint32_t regs[4] = { 0 };

	__cpuid(op, regs);

	return regs[0];
}

static inline int access_msr_devnode(void)
{
	return !access(MSR_DEVNODE, R_OK);
}

int read_u32(const char *path, uint32_t *v);
int read_u64(const char *path, uint64_t *v);
uint64_t rdmsr(int msr);

#endif /* !_PLATFORM_H_ */

