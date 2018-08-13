/*
 * eventlog.h: TXT TPM event log definitions
 *
 * Copyright (c) 2017 Daniel P. Smith
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

#ifndef __EVENTLOG_H__
#define __EVENTLOG_H__

#include "tboot.h"

typedef enum {
	EVTYPE_BASE                 = 0x400,
	EVTYPE_PCRMAPPING           = EVTYPE_BASE + 1,
	EVTYPE_HASH_START           = EVTYPE_BASE + 2,
	EVTYPE_MLE_HASH             = EVTYPE_BASE + 4,
	EVTYPE_BIOSAC_REG_DATA      = EVTYPE_BASE + 10,
	EVTYPE_CPU_SCRTM_STAT       = EVTYPE_BASE + 11,
	EVTYPE_LCP_CONTROL_HASH     = EVTYPE_BASE + 12,
	EVTYPE_ELEMENTS_HASH        = EVTYPE_BASE + 13,
	EVTYPE_STM_HASH             = EVTYPE_BASE + 14,
	EVTYPE_OSSINITDATA_CAP_HASH = EVTYPE_BASE + 15,
	EVTYPE_SINIT_PUBKEY_HASH    = EVTYPE_BASE + 16,
	EVTYPE_LCP_HASH             = EVTYPE_BASE + 17,
} txt_event_type_t;

int emulate_event(const struct acm *acm, uint16_t alg, uint8_t tpmver,
	const tb_version_t *tbver, struct pcr_event *evt);

struct tpm *parse_tpm12_log(char *buffer, size_t size);
struct tpm *parse_tpm20_log_legacy(char *buffer, size_t size);
struct tpm *parse_tpm20_log_tcg(void *buffer, size_t size);

#endif
