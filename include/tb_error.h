/*
 * tb_error.h: error code definitions
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __TB_ERROR_H__
#define __TB_ERROR_H__

/* see errorcode.h for format */
#define MAKE_TBOOT_ERRORCODE(err)     (0xc0000000 | 0x8000 | (err))

#ifdef __ASSEMBLY__

/* special errorcode used for layout error (in boot.S) */
#define TB_ERR_LAYOUT 1

#else

typedef enum {
    TB_ERR_NONE                       = 0,  /* succeed */
    TB_ERR_LAYOUT                     = 1,  /* layout in boot.S (not matches) */

    TB_ERR_GENERIC                    = 2,  /* non-fatal generic error */

    TB_ERR_TPM_NOT_READY              = 3,  /* tpm not ready */
    TB_ERR_SMX_NOT_SUPPORTED          = 4,  /* smx not supported */
    TB_ERR_VMX_NOT_SUPPORTED          = 5,  /* vmx not supported */
    TB_ERR_TXT_NOT_SUPPORTED          = 6,  /* txt not supported */
    TB_ERR_CPU_NOT_READY              = 7,  /* CPU not able to launch */

    TB_ERR_MODULE_VERIFICATION_FAILED = 8,  /* module failed to verify against
                                               policy */
    TB_ERR_MODULES_NOT_IN_POLICY      = 9,  /* modules in mbi but not in
                                               policy */
    TB_ERR_POLICY_INVALID             = 10, /* policy is invalid */
    TB_ERR_POLICY_NOT_PRESENT         = 11, /* no policy in TPM NV */

    TB_ERR_SINIT_NOT_PRESENT          = 12, /* SINIT ACM not provided */
    TB_ERR_ACMOD_VERIFY_FAILED        = 13, /* verifying AC module failed */

    TB_ERR_POST_LAUNCH_VERIFICATION   = 14, /* verification of post-launch
                                               failed */
    TB_ERR_S3_INTEGRITY               = 15, /* creation or verification of
                                               S3 integrity measurements
                                               failed */

    TB_ERR_FATAL                      = 16, /* generic fatal error */
    TB_ERR_NV_VERIFICATION_FAILED     = 17, /* NV failed to verify against
                                               policy */
    TB_ERR_PREV_LAUNCH_FAILURE        = 18, /* failure on previous launch */

    TB_ERR_MAX                              /* must be <= 2^12 */
} tb_error_t;


extern void print_tb_error_msg(tb_error_t error);
extern bool read_error_index(tb_error_t *error);
extern void write_tb_error(tb_error_t error);
extern bool was_last_boot_error(void);

#endif /* __ASSEMBLY__ */

#endif /* __TB_ERROR_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
