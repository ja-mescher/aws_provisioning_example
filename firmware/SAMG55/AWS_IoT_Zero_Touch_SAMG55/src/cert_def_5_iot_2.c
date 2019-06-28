
#include "atcacert/atcacert_def.h"

const atcacert_cert_element_t g_cert_elements_5_iot_2[] = {
	{
		.id         = "IssueDate",
		.device_loc = {
			.zone      = DEVZONE_DATA,
			.slot      = 8,
			.is_genkey = 0,
			.offset    = 208+93,
			.count     = 13
		},
		.cert_loc   = {
			.offset = 130,
			.count  = 13
		}
	},
	{
		.id         = "ExpireDate",
		.device_loc = {
			.zone      = DEVZONE_DATA,
			.slot      = 8,
			.is_genkey = 0,
			.offset    = 208+108,
			.count     = 13
		},
		.cert_loc   = {
			.offset = 145,
			.count  = 13
		}
	}
};

const uint8_t g_cert_template_5_iot_2[] = {
    0x30, 0x82, 0x01, 0xe1, 0x30, 0x82, 0x01, 0x87,  0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x2a,
    0x38, 0xa4, 0x1c, 0x96, 0x0a, 0x04, 0xde, 0x42,  0xb2, 0x28, 0xa5, 0x0b, 0xe8, 0x34, 0x98, 0x02,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,  0x3d, 0x04, 0x03, 0x02, 0x30, 0x50, 0x31, 0x24,
    0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,  0x1b, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53,
    0x69, 0x67, 0x6e, 0x20, 0x45, 0x43, 0x43, 0x20,  0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20,
    0x2d, 0x20, 0x52, 0x34, 0x31, 0x13, 0x30, 0x11,  0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
    0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67,  0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x13, 0x0a, 0x47, 0x6c, 0x6f, 0x62,  0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x32, 0x31, 0x31, 0x31, 0x33,  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17,
    0x0d, 0x33, 0x38, 0x30, 0x31, 0x31, 0x39, 0x30,  0x33, 0x31, 0x34, 0x30, 0x37, 0x5a, 0x30, 0x50,
    0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04,  0x0b, 0x13, 0x1b, 0x47, 0x6c, 0x6f, 0x62, 0x61,
    0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x45, 0x43,  0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43,
    0x41, 0x20, 0x2d, 0x20, 0x52, 0x34, 0x31, 0x13,  0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
    0x0a, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53,  0x69, 0x67, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x47, 0x6c,  0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,  0x42, 0x00, 0x04, 0xb8, 0xc6, 0x79, 0xd3, 0x8f,
    0x6c, 0x25, 0x0e, 0x9f, 0x2e, 0x39, 0x19, 0x1c,  0x03, 0xa4, 0xae, 0x9a, 0xe5, 0x39, 0x07, 0x09,
    0x16, 0xca, 0x63, 0xb1, 0xb9, 0x86, 0xf8, 0x8a,  0x57, 0xc1, 0x57, 0xce, 0x42, 0xfa, 0x73, 0xa1,
    0xf7, 0x65, 0x42, 0xff, 0x1e, 0xc1, 0x00, 0xb2,  0x6e, 0x73, 0x0e, 0xff, 0xc7, 0x21, 0xe5, 0x18,
    0xa4, 0xaa, 0xd9, 0x71, 0x3f, 0xa8, 0xd4, 0xb9,  0xce, 0x8c, 0x1d, 0xa3, 0x42, 0x30, 0x40, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,  0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,  0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,  0x16, 0x04, 0x14, 0x54, 0xb0, 0x7b, 0xad, 0x45,
    0xb8, 0xe2, 0x40, 0x7f, 0xfb, 0x0a, 0x6e, 0xfb,  0xbe, 0x33, 0xc9, 0x3c, 0xa3, 0x84, 0xd5, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
    0x02, 0x21, 0x00, 0xdc, 0x92, 0xa1, 0xa0, 0x13,  0xa6, 0xcf, 0x03, 0xb0, 0xe6, 0xc4, 0x21, 0x97,
    0x90, 0xfa, 0x14, 0x57, 0x2d, 0x03, 0xec, 0xee,  0x3c, 0xd3, 0x6e, 0xca, 0xa8, 0x6c, 0x76, 0xbc,
    0xa2, 0xde, 0xbb, 0x02, 0x20, 0x27, 0xa8, 0x85,  0x27, 0x35, 0x9b, 0x56, 0xc6, 0xa3, 0xf2, 0x47,
    0xd2, 0xb7, 0x6e, 0x1b, 0x02, 0x00, 0x17, 0xaa,  0x67, 0xa6, 0x15, 0x91, 0xde, 0xfa, 0x94, 0xec,
    0x7b, 0x0b, 0xf8, 0x9f, 0x84
};

const atcacert_def_t g_cert_def_5_iot_2 = {
	.type                   = CERTTYPE_X509,
	.template_id            = 5,
	.chain_id               = 0,
	.private_key_slot       = 0,
	.sn_source              = SNSRC_STORED,
	.cert_sn_dev_loc        = {
		.zone      = DEVZONE_DATA,
		.slot      = 8,
		.is_genkey = 0,
		.offset    = 208+74,
		.count     = 17
	},
	.issue_date_format      = DATEFMT_RFC5280_UTC,
	.expire_date_format     = DATEFMT_RFC5280_UTC,
	.tbs_cert_loc           = {
		.offset = 4,
		.count  = 395
	},
	.expire_years           = 26,
	.public_key_dev_loc     = {
		.zone      = DEVZONE_DATA,
		.slot      = 10,
		.is_genkey = 0,
		.offset    = 0,
		.count     = 72
	},
	.comp_cert_dev_loc      = {
		.zone      = DEVZONE_DATA,
		.slot      = 8,
		.is_genkey = 0,
		.offset    = 208,
		.count     = 72
	},
	.std_cert_elements      = {
		{ // STDCERT_PUBLIC_KEY
			.offset = 267,
			.count  = 64
		},
		{ // STDCERT_SIGNATURE
			.offset = 411,
			.count  = 74
		},
		{ // STDCERT_ISSUE_DATE
			.offset = 130,
			.count  = 13
		},
		{ // STDCERT_EXPIRE_DATE
			.offset = 145,
			.count  = 13
		},
		{ // STDCERT_SIGNER_ID
			.offset = 0,
			.count  = 0
		},
		{ // STDCERT_CERT_SN
			.offset = 15,
			.count  = 17
		},
		{ // STDCERT_AUTH_KEY_ID
			.offset = 0,
			.count  = 0
		},
		{ // STDCERT_SUBJ_KEY_ID
			.offset = 379,
			.count  = 20
		}
	},
	.cert_elements          = g_cert_elements_5_iot_2,
	.cert_elements_count    = sizeof(g_cert_elements_5_iot_2) / sizeof(g_cert_elements_5_iot_2[0]),
	.cert_template          = g_cert_template_5_iot_2,
	.cert_template_size     = sizeof(g_cert_template_5_iot_2),
};

