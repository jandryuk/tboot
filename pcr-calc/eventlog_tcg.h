#ifndef _EVENTLOG_TCG_H_
# define _EVENTLOG_TCG_H_

# include <stdint.h>

/*
 * To match with specification definition:
 *
 * struct tdTCG_EfiSpecIDEventStruct {
 *     TCG_EfiSpecIdEventStructHeader hdr;
 *     TCG_EfiSpecIdEventAlgorithmSizes algs;
 *     TCG_EfiSpecIdEventVendorInfo vinfo
 * } TCG_EfiSpecIDEventStruct;
 *
 * This makes it easier to parse/print the different components with dynamic
 * sizes.
 */

typedef struct tdTCG_EfiSpecIdEventStructHeader {
	uint8_t signature[16];
	uint32_t platformClass;
	uint8_t specVersionMinor;
	uint8_t specVersionMajor;
	uint8_t specErrata;
	uint8_t uintnSize;
}__attribute__((packed)) TCG_EfiSpecIdEventStructHeader;

typedef struct tdTCG_EfiSpecIdEventAlgorithmSize {
	uint16_t algorithmId;
	uint16_t digestSize;
}__attribute__((packed)) TCG_EfiSpecIdEventAlgorithmSize;

typedef struct tdTCG_EfiSpecIdEventAlgorithmSizes {
	uint32_t numberOfAlgorithms;
	TCG_EfiSpecIdEventAlgorithmSize digestSizes[];
}__attribute__((packed)) TCG_EfiSpecIdEventAlgorithmSizes;

typedef struct tdTCG_EfiSpecIdEventVendorInfo {
	uint8_t vendorInfoSize;
	uint8_t vendorInfo[];
}__attribute__((packed)) TCG_EfiSpecIdEventVendorInfo;

/*
 * SHA1 Event Log Entry Format.
 */
typedef struct tdTCG_PCR_EVENT {
#define PCR_INDEX_HEADER    0x0
	uint32_t PCRIndex;
#define EV_NO_ACTION    0x3
	uint32_t EventType;
	uint8_t Digest[20];
	uint32_t EventSize;
	uint8_t Event[];
}__attribute__((packed)) TCG_PCR_EVENT;

/*
 * Crypto Agile Log Entry Format.
 *
 * typedef struct tdTCG_PCR_EVENT2 {
 *     TCG_PCR_EVENT2_HDR hdr;
 *     TPML_DIGEST_VALUES digests;
 *     TCG_PCR_EVENT2_EVT event;
 * } TCG_PCR_EVENT2;
 */
typedef struct tdTCG_PCR_EVENT2_HDR {
	uint32_t PCRIndex;
	uint32_t EventType;
}__attribute__((packed)) TCG_PCR_EVENT2_HDR;

typedef struct tdTPMT_HA {
	uint16_t AlgorithmId;
	uint8_t Digest[];
}__attribute__((packed)) TPMT_HA;

typedef struct tdTPML_DIGEST_VALUES {
	uint32_t Count;
	TPMT_HA Digests[];
}__attribute__((packed)) TPML_DIGEST_VALUES;

typedef struct tdTCG_PCR_EVENT2_EVT {
	uint32_t EventSize;
	uint8_t Event[];
}__attribute__((packed)) TCG_PCR_EVENT2_EVT;

#endif /* !_EVENTLOG_TCG_H_ */

