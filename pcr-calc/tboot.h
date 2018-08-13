#ifndef _TBOOT_H_
# define _TBOOT_H_

typedef struct {
    unsigned int major, minor, micro;
} tb_version_t;

#define TB_VERSION_DEFAULT { .major = 1, .minor = 9, .micro = 12 }

#endif /* !_TBOOT_H_ */

