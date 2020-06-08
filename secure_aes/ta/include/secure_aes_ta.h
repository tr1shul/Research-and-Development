#ifndef __SECURE_AES_TA_H__
#define __SECURE_AES_TA_H__

#define TA_SECURE_AES_UUID \
	{ 0x1316b0f7, 0x80ea, 0x4097, \
		{ 0x94, 0xa9, 0xbf, 0x2b, 0x63, 0x55, 0x1d, 0x72 } }

#define TA_AES_ALGO_ECB			0
#define TA_AES_ALGO_CBC			1
#define TA_AES_ALGO_CTR			2

#define TA_AES_SIZE_128BIT		(128 / 8)
#define TA_AES_SIZE_256BIT		(256 / 8)

#define TA_AES_MODE_ENCODE		1
#define TA_AES_MODE_DECODE		0


#define TA_AES_CMD_PREPARE		0
#define TA_AES_CMD_SET_KEY		1
#define TA_AES_CMD_SET_IV		2
#define TA_AES_CMD_CIPHER		3

#endif
