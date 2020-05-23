#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <secure_math_ta.h>

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_MATH_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 35;
	op.params[0].value.b = 7;

	printf("Invoking TA to Add: %d and %d\n", op.params[0].value.a, op.params[0].value.b);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MATH_CMD_ADD, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("%d + %d = %d\n", op.params[0].value.a, op.params[0].value.b, op.params[1].value.a);

	printf("Invoking TA to Subtract: %d and %d\n", op.params[0].value.a, op.params[0].value.b);
        res = TEEC_InvokeCommand(&sess, TA_SECURE_MATH_CMD_SUB, &op,
                                 &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                        res, err_origin);
        printf("%d - %d = %d\n", op.params[0].value.a, op.params[0].value.b, op.params[1].value.a);

	printf("Invoking TA to Multiply: %d and %d\n", op.params[0].value.a, op.params[0].value.b);
        res = TEEC_InvokeCommand(&sess, TA_SECURE_MATH_CMD_MUL, &op,
                                 &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                        res, err_origin);
        printf("%d * %d = %d\n", op.params[0].value.a, op.params[0].value.b, op.params[1].value.a);

	printf("Invoking TA to Divide: %d and %d\n", op.params[0].value.a, op.params[0].value.b);
        res = TEEC_InvokeCommand(&sess, TA_SECURE_MATH_CMD_DIV, &op,
                                 &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                        res, err_origin);
        printf("%d / %d = %d\n", op.params[0].value.a, op.params[0].value.b, op.params[1].value.a);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
