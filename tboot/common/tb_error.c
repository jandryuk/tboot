/*
 * tb_error.c: support functions for tb_error_t type
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <uuid.h>
#include <loader.h>
#include <uuid.h>
#include <hash.h>
#include <tb_error.h>
#include <tb_policy.h>
#include <tpm.h>
#include <tboot.h>
#include <txt/config_regs.h>
#include <txt/txt.h>
#include <txt/errorcode.h>

#define TB_LAUNCH_ERR_IDX     0x20000002      /* launch error index */

static bool no_err_idx;

/*
 * print_tb_error_msg
 *
 * print tb policy error message
 *
 */
void print_tb_error_msg(tb_error_t error)
{
    switch( error ) {
        case TB_ERR_NONE:
            printk(TBOOT_INFO"succeeded.\n");
            break;
        case TB_ERR_GENERIC:
            printk(TBOOT_WARN"non-fatal generic error.\n");
            break;
        case TB_ERR_TPM_NOT_READY:
            printk(TBOOT_WARN"TPM not ready.\n");
            break;
        case TB_ERR_SMX_NOT_SUPPORTED:
            printk(TBOOT_WARN"SMX not supported.\n");
            break;
        case TB_ERR_VMX_NOT_SUPPORTED:
            printk(TBOOT_ERR"VMX not supported.\n");
            break;
        case TB_ERR_TXT_NOT_SUPPORTED:
            printk(TBOOT_ERR"TXT not supported.\n");
            break;
        case TB_ERR_CPU_NOT_READY:
            printk(TBOOT_ERR"CPU not ready for launch.\n");
            break;
        case TB_ERR_MODULES_NOT_IN_POLICY:
            printk(TBOOT_ERR"modules in mbi but not in policy.\n");
            break;
        case TB_ERR_MODULE_VERIFICATION_FAILED:
            printk(TBOOT_ERR"verifying module against policy failed.\n");
            break;
        case TB_ERR_POLICY_INVALID:
            printk(TBOOT_ERR"policy invalid.\n");
            break;
        case TB_ERR_POLICY_NOT_PRESENT:
            printk(TBOOT_WARN"no policy in TPM NV.\n");
            break;
        case TB_ERR_SINIT_NOT_PRESENT:
            printk(TBOOT_WARN"SINIT ACM not provided.\n");
            break;
        case TB_ERR_ACMOD_VERIFY_FAILED:
            printk(TBOOT_WARN"verifying AC module failed.\n");
            break;
        case TB_ERR_POST_LAUNCH_VERIFICATION:
            printk(TBOOT_ERR"verification of post-launch failed.\n");
            break;
        case TB_ERR_S3_INTEGRITY:
            printk(TBOOT_ERR"creation or verification of S3 measurements failed.\n");
            break;
        case TB_ERR_FATAL:
            printk(TBOOT_ERR"generic fatal error.\n");
            break;
        case TB_ERR_NV_VERIFICATION_FAILED:
            printk(TBOOT_ERR"verifying nv against policy failed.\n");
            break;
        case TB_ERR_PREV_LAUNCH_FAILURE:
            printk(TBOOT_ERR"error on previous launch.\n");
            break;
        default:
            printk(TBOOT_ERR"unknown error (%d).\n", error);
            break;
    }
}

/*
 * write_error_index
 *
 * write error code to TPM NV
 *
 */
static void write_error_index(tb_error_t error)
{
    if ( !g_tpm || no_err_idx )
         return;

    /* to prevent wearout, only write if data has changed */
    tb_error_t prev_error = TB_ERR_NONE;
    if ( read_error_index(&prev_error) ) {
        if ( prev_error != error ) {
            if ( !g_tpm->nv_write(g_tpm, 0, g_tpm->tb_err_index, 0,
                                  (uint8_t *)&error, sizeof(tb_error_t)) ) {
                no_err_idx = true;
            }
        }
    }
}

/*
 * read_error_index
 *
 * read error code from TPM NV (TB_LAUNCH_ERR_IDX)
 *
 */
bool read_error_index(tb_error_t *error)
{
    uint32_t size = sizeof(tb_error_t);

    if ( error == NULL ) {
        printk(TBOOT_ERR"Error: error pointer is zero.\n");
        return false;
    }

    memset(error, 0, size);

    /* read! */
    if ( !g_tpm->nv_read(g_tpm, 0, g_tpm->tb_err_index, 0,
                (uint8_t *)error, &size) ) {
        printk(TBOOT_WARN"Error: read TPM error: 0x%x.\n", g_tpm->error);
        no_err_idx = true;
        return false;
    }

    no_err_idx = false;
    return true;
}

/*
 * write_tb_error_code
 *
 * write error code to TXT.ERRORCODE (if post-launch) and into
 * TPM NV (TB_LAUNCH_ERR_IDX) (if defined).
 *
 */
void write_tb_error(tb_error_t error)
{
    /* don't write (new) error if there is an existing error */
    if ( was_last_boot_error() ) {
        printk("previous error exists, not overwriting\n");
        return;
    }

    /* write to TXT.ERRORCODE only if we're post-launch */
    if ( txt_is_launched() ) {
        /* must do this in fn, so do here */
        COMPILE_TIME_ASSERT( TB_ERR_MAX <= (1<<12) );

        tboot_errorcode_t tboot_err;

        /* TB_ERR_NONE is not really an error, so just write 0s */
        if ( error == TB_ERR_NONE )
            tboot_err._raw = 0;
        else
            tboot_err._raw = MAKE_TBOOT_ERRORCODE(error);
        write_priv_config_reg(TXTCR_ERRORCODE, tboot_err._raw);
        printk("writing error (0x%Lx) to TXT.ERRORCODE\n", tboot_err._raw);
    }

    /* write to TB_LAUNCH_ERR_IDX, if it exists */
    write_error_index(error);
}

/*
 * was_last_boot_error
 * false: no error; true: error
 */
bool was_last_boot_error(void)
{
    /*
     * if it's TB_ERR_NONE, still need to check TXT.ERRORCODE because might
     * have cleared it but fix didn't work and so will error out again in
     * SINIT, setting TXT.ERRORCODE but leaving TB_LAUNCH_ERR_IDX clear, and
     * otherwise would have reset loop
     */

    /* check TXT.ERRORCODE */
    if ( is_txt_errorcode_error() ) {
        /* put TB_ERR_PREV_LAUNCH_FAILURE into TB_LAUNCH_ERR_IDX. */
        write_error_index(TB_ERR_PREV_LAUNCH_FAILURE);
        return true;
    }
    return false;
}

