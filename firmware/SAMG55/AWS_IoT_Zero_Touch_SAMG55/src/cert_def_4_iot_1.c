
#include "atcacert/atcacert_def.h"

const atcacert_cert_element_t g_cert_elements_4_iot_1[] = {
    {
        .id         = "IssueDate",
        .device_loc = {
            .zone      = DEVZONE_DATA,
            .slot      = 8,
            .is_genkey = 0,
            .offset    = 89,
            .count     = 13
        },
        .cert_loc   = {
            .offset = 114,
            .count  = 13
        }
    },
    {
        .id         = "ExpireDate",
        .device_loc = {
            .zone      = DEVZONE_DATA,
            .slot      = 8,
            .is_genkey = 0,
            .offset    = 104,
            .count     = 13
        },
        .cert_loc   = {
            .offset = 129,
            .count  = 13
        }
    }
};

const uint8_t g_cert_template_4_iot_1[] = {
	0x30, 0x82, 0x01, 0xc5, 0x30, 0x82, 0x01, 0x6b,  0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0d, 0x01,
	0xf0, 0xf7, 0x9d, 0x59, 0xdd, 0x6e, 0x50, 0xf7,  0x42, 0x73, 0x71, 0x50, 0x30, 0x0a, 0x06, 0x08,
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,  0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,  0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a,
	0x13, 0x19, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20,  0x4c, 0x4c, 0x43, 0x31, 0x11, 0x30, 0x0f, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x47, 0x54,  0x53, 0x20, 0x4c, 0x54, 0x53, 0x52, 0x30, 0x1e,
	0x17, 0x0d, 0x31, 0x38, 0x31, 0x31, 0x30, 0x31,  0x30, 0x30, 0x30, 0x30, 0x34, 0x32, 0x5a, 0x17,
	0x0d, 0x34, 0x32, 0x31, 0x31, 0x30, 0x31, 0x30,  0x30, 0x30, 0x30, 0x34, 0x32, 0x5a, 0x30, 0x44,
	0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,  0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22, 0x30,
	0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19,  0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x54,
	0x72, 0x75, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72,  0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4c, 0x4c,
	0x43, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,  0x04, 0x03, 0x13, 0x08, 0x47, 0x54, 0x53, 0x20,
	0x4c, 0x54, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13,  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xcd,
	0xf1, 0x8c, 0x8e, 0xda, 0xef, 0xb2, 0x09, 0x0a,  0x19, 0x77, 0x00, 0x24, 0x50, 0xdb, 0xf9, 0x73,
	0x77, 0x68, 0x91, 0xf5, 0x0b, 0x7e, 0xb0, 0x3a,  0x40, 0x98, 0x05, 0x57, 0x65, 0xcc, 0xb8, 0x43,
	0x6d, 0x41, 0x92, 0x06, 0xe4, 0x75, 0x0e, 0x4b,  0xa8, 0xc5, 0x9f, 0xc7, 0xf4, 0xc9, 0x29, 0x55,
	0x78, 0xe4, 0x42, 0xc6, 0xa1, 0x72, 0x8c, 0x32,  0x72, 0x46, 0x7f, 0x3a, 0x77, 0xe2, 0x24, 0xa3,
	0x42, 0x30, 0x40, 0x30, 0x0e, 0x06, 0x03, 0x55,  0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
	0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55,  0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
	0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03,  0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x3e,
	0xfe, 0xff, 0xcc, 0x52, 0xeb, 0xbf, 0x34, 0x3e,  0x3d, 0xf3, 0x40, 0xd0, 0xe4, 0x25, 0xb1, 0x5f,
	0xb8, 0xbb, 0x52, 0x30, 0x0a, 0x06, 0x08, 0x2a,  0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
	0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xf2,  0xae, 0x7f, 0xf5, 0x6d, 0x04, 0x7a, 0x86, 0xc3,
	0x74, 0xd4, 0xc1, 0x42, 0x2a, 0xed, 0x37, 0xda,  0x13, 0x1a, 0x77, 0x6c, 0x7e, 0xdb, 0x8c, 0x20,
	0x66, 0x55, 0x72, 0x6e, 0xa5, 0x3f, 0x45, 0x02,  0x20, 0x6b, 0xd1, 0x29, 0x82, 0xb6, 0xcb, 0xa4,
	0x9a, 0x21, 0xa0, 0xa5, 0xa8, 0xe3, 0x7f, 0xf8,  0x05, 0x8a, 0x01, 0x8c, 0xdf, 0x81, 0x7d, 0xd3,
	0x6d, 0x5b, 0x09, 0x6b, 0x35, 0x31, 0xb2, 0xf4,  0x48
};

const atcacert_def_t g_cert_def_4_iot_1 = {
    .type                   = CERTTYPE_X509,
    .template_id            = 4,
    .chain_id               = 0,
    .private_key_slot       = 0,
    .sn_source              = SNSRC_STORED,
    .cert_sn_dev_loc        = { 
        .zone      = DEVZONE_DATA,
        .slot      = 8,
        .is_genkey = 0,
        .offset    = 74,
        .count     = 13
    },
    .issue_date_format      = DATEFMT_RFC5280_UTC,
    .expire_date_format     = DATEFMT_RFC5280_UTC,
    .tbs_cert_loc           = {
        .offset = 4,
        .count  = 367
    },
    .expire_years           = 24,
    .public_key_dev_loc     = {
        .zone      = DEVZONE_DATA,
        .slot      = 9,
        .is_genkey = 0,
        .offset    = 0,
        .count     = 72
    },
    .comp_cert_dev_loc      = {
        .zone      = DEVZONE_DATA,
        .slot      = 8,
        .is_genkey = 0,
        .offset    = 0,
        .count     = 72
    },
    .std_cert_elements      = {
	    { // STDCERT_PUBLIC_KEY
		    .offset = 239,
		    .count  = 64
	    },
	    { // STDCERT_SIGNATURE
		    .offset = 383,
		    .count  = 74
	    },
	    { // STDCERT_ISSUE_DATE
		    .offset = 114,
		    .count  = 13
	    },
	    { // STDCERT_EXPIRE_DATE
		    .offset = 129,
		    .count  = 13
	    },
	    { // STDCERT_SIGNER_ID
		    .offset = 0,
		    .count  = 0
	    },
	    { // STDCERT_CERT_SN
		    .offset = 15,
		    .count  = 13
	    },
	    { // STDCERT_AUTH_KEY_ID
		    .offset = 0,
		    .count  = 0
	    },
	    { // STDCERT_SUBJ_KEY_ID
		    .offset = 351,
		    .count  = 20
	    }
    },
    .cert_elements          = g_cert_elements_4_iot_1,
    .cert_elements_count    = sizeof(g_cert_elements_4_iot_1) / sizeof(g_cert_elements_4_iot_1[0]),
    .cert_template          = g_cert_template_4_iot_1,
    .cert_template_size     = sizeof(g_cert_template_4_iot_1),
};

