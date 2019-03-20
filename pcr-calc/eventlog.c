/*
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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "uuid.h"
#include "heap.h"
#include "acm.h"
#include "tpm.h"
#include "eventlog.h"

#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

static int get_ossinit_caps_tboot_common(const txt_caps_t *acm_caps,
		const txt_caps_t *mle_hdr, const txt_caps_t *mask,
		uint8_t tpmver, txt_caps_t *caps)
{
	txt_caps_t ossinit_data_caps;

	ossinit_data_caps._raw = mle_hdr->_raw & ~mask->_raw;

	if (acm_caps->rlp_wake_monitor)
		ossinit_data_caps.rlp_wake_monitor = 1;
	else if (acm_caps->rlp_wake_getsec)
		ossinit_data_caps.rlp_wake_getsec = 1;
	else
		return -1;

	/* TODO: Can be forced on cmdline too. */
	switch (tpmver) {
		case TPM12:
			ossinit_data_caps.tcg_event_log_format = 0;
			break;
		case TPM20:
			/* TODO: Can be forced to legacy on cmdline. */
			if (acm_caps->tcg_event_log_format)
				ossinit_data_caps.tcg_event_log_format = 1;
			break;
		default:
			return -1;
	}

	/* XXX: Forced to 0 for now (and masked anyway). May change? */
	ossinit_data_caps.ecx_pgtbl = 0;

	switch (tpmver) {
		case TPM12:
			ossinit_data_caps.pcr_map_no_legacy = 1;
			ossinit_data_caps.pcr_map_da = 0;
			/* TODO: Has to be enabled on cmdline (pcr_map). */
			if (acm_caps->pcr_map_da && 0)
				ossinit_data_caps.pcr_map_da = 1;
			else if (!acm_caps->pcr_map_no_legacy)
				ossinit_data_caps.pcr_map_no_legacy = 0;
			else if (acm_caps->pcr_map_da)
				ossinit_data_caps.pcr_map_da = 1;
			else
				return -1;
			break;
		case TPM20:
			/* PCR mapping selection MUST be zero in TPM2.0 mode
			 * since D/A mapping is the only supported by TPM2.0 */
			ossinit_data_caps.pcr_map_no_legacy = 0;
			ossinit_data_caps.pcr_map_da = 0;
			break;
		default:
			return -1;
	}

	caps->_raw = ossinit_data_caps._raw;

	return 0;
}

/* See tboot/txt/txt.c, include/mle.h */
static int get_ossinit_caps_tboot196(const struct acm *acm, uint8_t tpmver,
		txt_caps_t *caps)
{
	const txt_caps_t mle_hdr = {
		.rlp_wake_getsec = 1,
		.rlp_wake_monitor = 1,
		.ecx_pgtbl = 1,
		.stm = 0,
		.pcr_map_no_legacy = 0,
		.pcr_map_da = 1,
		.platform_type = 0,
		.max_phy_addr = 0,
		.tcg_event_log_format = 1,
		.reserved1 = 0,
	};  /* MLE_HDR_CAPS: 0x227 */
	const txt_caps_t mask = {
		.rlp_wake_getsec = 1,
		.rlp_wake_monitor = 1,
		.ecx_pgtbl = 0,
		.stm = 0,
		.pcr_map_no_legacy = 0,
		.pcr_map_da = 1,
		.platform_type = 0,
		.max_phy_addr = 0,
		.tcg_event_log_format = 0,
		.reserved1 = 0,
	};

	return get_ossinit_caps_tboot_common(&acm->infotable->capabilities,
			&mle_hdr, &mask, tpmver, caps);
}

/* See tboot/txt/txt.c, include/mle.h */
/* Since 1.9.6: tcg_event_log_format is now masked before processing, so the
 * value from the MLE header defined in TBoot is ignored. */
static int get_ossinit_caps_tboot199(const struct acm *acm, uint8_t tpmver,
		txt_caps_t *caps)
{
	const txt_caps_t mle_hdr = {
		.rlp_wake_getsec = 1,
		.rlp_wake_monitor = 1,
		.ecx_pgtbl = 1,
		.stm = 0,
		.pcr_map_no_legacy = 0,
		.pcr_map_da = 1,
		.platform_type = 0,
		.max_phy_addr = 0,
		.tcg_event_log_format = 1,
		.reserved1 = 0,
	};  /* MLE_HDR_CAPS: 0x227 */
	const txt_caps_t mask = {
		.rlp_wake_getsec = 1,
		.rlp_wake_monitor = 1,
		.ecx_pgtbl = 0,
		.stm = 0,
		.pcr_map_no_legacy = 0,
		.pcr_map_da = 1,
		.platform_type = 0,
		.max_phy_addr = 0,
		.tcg_event_log_format = 1,
		.reserved1 = 0,
	};

	return get_ossinit_caps_tboot_common(&acm->infotable->capabilities,
			&mle_hdr, &mask, tpmver, caps);
}

static int event_ossinit_data_cap_hash(const struct acm *acm, uint16_t alg,
		uint8_t tpmver, tb_version_t tbver, tb_hash_t *hash)
{
	txt_caps_t caps;
	int rc;

	switch (tbver) {
		case TB_196:
			rc = get_ossinit_caps_tboot196(acm, tpmver, &caps);
			break;
		case TB_199:
			rc = get_ossinit_caps_tboot199(acm, tpmver, &caps);
			break;
		default:
			rc = -1;
			break;
	}

	if (!hash_buffer((unsigned char *)&caps, sizeof (caps), hash, alg))
		return -1;

	return rc;
}

int emulate_event(const struct acm *acm, uint16_t alg,
		uint8_t tpmver, tb_version_t tbver, struct pcr_event *evt)
{
	int rc;

	switch (evt->type) {
		case EVTYPE_OSSINITDATA_CAP_HASH:
			rc = event_ossinit_data_cap_hash(acm, alg, tpmver, tbver,
					&evt->digest);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

struct tpm *parse_tpm12_log(char *buffer, size_t size)
{
	struct tpm *t;
	tpm12_pcr_event_t *c, *n;
	event_log_container_t *log = (event_log_container_t *) buffer;

	t = new_tpm(TPM12);
	if (!t){
		goto out;
	}
	/* TODO: check for signature */

	c = (tpm12_pcr_event_t *)((void*)log + log->pcr_events_offset);
	n = (tpm12_pcr_event_t *)((void*)log + log->next_event_offset);

	if ((char *) n > (buffer + size)){
		goto out_free;
	}

	while (c < n) {
		if (!tpm_record_event(t, TB_HALG_SHA1, (void *) c)) {
			goto out_free;
		}
		c = (void *)c + sizeof(*c) + c->data_size;
	}

	return t;
out_free:
	destroy_tpm(t);
out:
	return NULL;
}

struct tpm *parse_tpm20_log_legacy(char *buffer, size_t size)
{
	struct tpm *t;
	void *c, *n;
	uint32_t hash_size, data_size;
	heap_event_log_descr_t *log = (heap_event_log_descr_t *) buffer;

	t = new_tpm(TPM20);
	if (!t)
		goto out;

	hash_size = get_hash_size(log->alg);

	/* point at start of log */
	buffer += sizeof(heap_event_log_descr_t);
	c = buffer + log->pcr_events_offset;
	n = buffer + log->next_event_offset;

	if ((char *) n > (buffer + size))
		goto out_free;

	/* non-sha1 logs first entry is a no-op sha1 entry,
	 * so skip the first event
	 */
	if (log->alg != TB_HALG_SHA1){
		c += sizeof(tpm12_pcr_event_t) + sizeof(tpm20_log_descr_t);
	}

	while (c < n) {
		if (!tpm_record_event(t, log->alg, c))
			goto out_free;
		data_size = *(uint32_t *)(c + 2*sizeof(uint32_t) + hash_size);
		c += 3*sizeof(uint32_t) + hash_size + data_size;
	}

	return t;
out_free:
	destroy_tpm(t);
out:
	return NULL;
}

/*
 * Agile log structure helpers.
 */
static inline const TCG_EfiSpecIdEventAlgorithmSizes *
	tcg_header_algorithms(const TCG_EfiSpecIdEventStructHeader *hdr)
{
	/* TCG_EfiSpecIdEventAlgorithmSizes follows the static header
	 * immediately. */
	return ((void*)hdr) + sizeof (*hdr);
}

static inline size_t tcg_pcr_event_size(const TCG_PCR_EVENT *h)
{
	return sizeof (*h) + h->EventSize;
}

static size_t parse_tcg_pcr_event2(struct tpm *t, const TCG_PCR_EVENT2_HDR *h,
	const TCG_EfiSpecIdEventAlgorithmSizes *algs)
{
	const TPML_DIGEST_VALUES *digests;
	const TCG_PCR_EVENT2_EVT *event;
	unsigned int n, c = sizeof (*h);

	digests = ((void*)h) + c;
	n = tpm_record_event_tcg(t, h->PCRIndex, h->EventType, digests, algs);
	if (!n)
		return 0;

	c += n;
	event = ((void*)h) + c;
	/* Skip the Event content for now. */
        n = sizeof (event->EventSize) +
		sizeof (event->Event[0]) * event->EventSize;
	c += n;

	return c;
}

struct tpm *parse_tpm20_log_tcg(void *buffer, size_t size)
{
	struct tpm *t;
	const TCG_PCR_EVENT *hdr = buffer;
	const TCG_EfiSpecIdEventAlgorithmSizes *algs;
	unsigned int n, c;

	t = new_tpm(TPM20);
	if (!t)
		return NULL;

	if (hdr->PCRIndex != PCR_INDEX_HEADER ||
	    hdr->EventType != EV_NO_ACTION)
		goto out;

	algs = tcg_header_algorithms((void*)hdr->Event);
	c = tcg_pcr_event_size(hdr);

	for (; c < size; c += n) {
		n = parse_tcg_pcr_event2(t, buffer + c, algs);
		if (!n)
			goto out;
	}

	return t;
out:
	destroy_tpm(t);

	return NULL;
}
