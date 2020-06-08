#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <secure_aes_ta.h>

#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)

struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_AES_ALGO_ECB:
		*algo = TEE_ALG_AES_ECB_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CBC:
		*algo = TEE_ALG_AES_CBC_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CTR:
		*algo = TEE_ALG_AES_CTR;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param) {
	case AES128_KEY_BYTE_SIZE:
	case AES256_KEY_BYTE_SIZE:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param) {
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result alloc_resources(void *session, uint32_t param_types,
				  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher * sess;
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	sess = (struct aes_cipher *) session;

	res = ta2tee_algo_id(params[0].value.a, &sess->algo);
	res = ta2tee_key_size(params[1].value.a, &sess->key_size);
	res = ta2tee_mode_id(params[2].value.a, &sess->mode);

	res = TEE_AllocateOperation(&sess->op_handle, sess->algo, sess->mode, sess->key_size * 8);
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, sess->key_size * 8, &sess->key_handle);

	key = TEE_Malloc(sess->key_size, 0);
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);

	return res;
}

static TEE_Result set_aes_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher * sess;
	TEE_Attribute attr;
	TEE_Result res;
	uint32_t key_sz;
	char *key;

	sess = (struct aes_cipher *) session;
	
	key = params[0].memref.buffer;
	key_sz = params[0].memref.size;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);
	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);

	return res;
}

static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher * sess;
	size_t iv_sz;
	char *iv;

        sess = (struct aes_cipher *) session;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	TEE_CipherInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

static TEE_Result cipher_buffer(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	
	struct aes_cipher * sess;
	
	sess = (struct aes_cipher *) session;

	return TEE_CipherUpdate(sess->op_handle,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{

}
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{
	struct aes_cipher *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct aes_cipher *sess;
	DMSG("Session %p: release session", session);
	sess = (struct aes_cipher *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4])
{
	switch(cmd)
	{
		case TA_AES_CMD_PREPARE:
			return alloc_resources(session, param_types, params);
		case TA_AES_CMD_SET_KEY:
			return set_aes_key(session, param_types, params);
		case TA_AES_CMD_SET_IV:
			return reset_aes_iv(session, param_types, params);
		case TA_AES_CMD_CIPHER:
			return cipher_buffer(session, param_types, params);
	}
}
