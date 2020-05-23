#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <secure_math_ta.h>

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}

	(void)&params;
	(void)&sess_ctx;

	IMSG("Secure Math\n");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx;
	IMSG("Goodbye\n");
}

static TEE_Result add_values(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}	

	params[1].value.a = params[0].value.a + params[0].value.b;
	
	IMSG("Added...");
	return TEE_SUCCESS;	
}

static TEE_Result sub_values(uint32_t param_types, TEE_Param params[4])
{
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
        DMSG("has been called");

        if (param_types != exp_param_types)
        {
                return TEE_ERROR_BAD_PARAMETERS;
        }

        params[1].value.a = params[0].value.a - params[0].value.b;
        
        IMSG("Subtracted...");
        return TEE_SUCCESS;
}

static TEE_Result mul_values(uint32_t param_types, TEE_Param params[4])
{
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
        DMSG("has been called");

        if (param_types != exp_param_types)
        {
                return TEE_ERROR_BAD_PARAMETERS;
        }

        params[1].value.a = params[0].value.a * params[0].value.b;
        
        IMSG("Multiplied...");
        return TEE_SUCCESS;
}

static TEE_Result div_values(uint32_t param_types, TEE_Param params[4])
{
        uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
        DMSG("has been called");

        if (param_types != exp_param_types)
        {
                return TEE_ERROR_BAD_PARAMETERS;
        }

        params[1].value.a = params[0].value.a / params[0].value.b;
        
        IMSG("Divided...");
        return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_SECURE_MATH_CMD_ADD:
		return add_values(param_types, params);
	case TA_SECURE_MATH_CMD_SUB:
		return sub_values(param_types, params);
	case TA_SECURE_MATH_CMD_MUL:
		return mul_values(param_types, params);
	case TA_SECURE_MATH_CMD_DIV:
		return div_values(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
