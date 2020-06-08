#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <secure_aes_ta.h>

#define AES_TEST_BUFFER_SIZE    4096
#define AES_TEST_KEY_SIZE       16
#define AES_BLOCK_SIZE          16

#define DECODE                  0
#define ENCODE                  1

struct test_ctx {
        TEEC_Context ctx;
        TEEC_Session sess;
};

int main(void)
{
        struct test_ctx ctx;
        char key[AES_TEST_KEY_SIZE];
        char iv[AES_BLOCK_SIZE];
        char clear[AES_TEST_BUFFER_SIZE];
        char ciph[AES_TEST_BUFFER_SIZE];
        char temp[AES_TEST_BUFFER_SIZE];

        printf("Preparing session");

        TEEC_UUID uuid = TA_SECURE_AES_UUID;
        uint32_t origin;
        TEEC_Result res;

        /* Initialize a context connecting us to the TEE */
        res = TEEC_InitializeContext(NULL, &(ctx.ctx));

        /* Open a session with the TA */
        res = TEEC_OpenSession(&(ctx.ctx), &(ctx.sess), &uuid,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);

        printf("Preparing encoding");
        
        TEEC_Operation op;
	uint32_t err;

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE);
        op.params[0].value.a = TA_AES_ALGO_CTR;
        op.params[1].value.a = TA_AES_SIZE_128BIT;
        op.params[2].value.a = TA_AES_MODE_ENCODE;
	res = TEEC_InvokeCommand(&(ctx.sess), TA_AES_CMD_PREPARE, &op, &err);

	printf("Load key");
	memset(key, 0x11, sizeof(key));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = AES_TEST_KEY_SIZE;
	res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_SET_KEY, &op, &err);

	memset(iv, 0, sizeof(iv));
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = AES_BLOCK_SIZE;
	res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_SET_IV, &op, &err);

	printf("Encoding buffer");
	memset(clear, 0x22, sizeof(clear));
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = clear;
	op.params[0].tmpref.size = AES_TEST_BUFFER_SIZE;
	op.params[1].tmpref.buffer = ciph;
	op.params[1].tmpref.size = AES_TEST_BUFFER_SIZE;
	res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_CIPHER, &op, &err);

	printf("Preparing decoding");

	memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE);
        op.params[0].value.a = TA_AES_ALGO_CTR;
        op.params[1].value.a = TA_AES_SIZE_128BIT;
        op.params[2].value.a = TA_AES_MODE_DECODE;
        res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_PREPARE, &op, &err);

	printf("Load key");
        memset(key, 0x11, sizeof(key));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

        op.params[0].tmpref.buffer = key;
        op.params[0].tmpref.size = AES_TEST_KEY_SIZE;
        res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_SET_KEY, &op, &err);

        memset(iv, 0, sizeof(iv));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = iv;
        op.params[0].tmpref.size = AES_BLOCK_SIZE;
        res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_SET_IV, &op, &err);

        printf("Encoding buffer");
        memset(clear, 0x22, sizeof(clear));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = ciph;
        op.params[0].tmpref.size = AES_TEST_BUFFER_SIZE;
	op.params[1].tmpref.buffer = temp;
        op.params[1].tmpref.size = AES_TEST_BUFFER_SIZE;
        res = TEEC_InvokeCommand(&ctx.sess, TA_AES_CMD_CIPHER, &op, &err);

	if (memcmp(clear, temp, AES_TEST_BUFFER_SIZE))
		printf("Clear text and decoded text differ => ERROR\n");
	else
		printf("Clear text and decoded text match\n");

	TEEC_CloseSession(&ctx.sess);
	TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}
