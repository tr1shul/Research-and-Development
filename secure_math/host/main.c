#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <tee_client_api.h>
#include <secure_math_ta.h>

int main(void)
{
	int network_socket;
	struct sockaddr_in server_address;
	
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_MATH_UUID;
	uint32_t err_origin;

	network_socket = socket(AF_INET, SOCK_STREAM, 0);
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_address.sin_port = htons(8001);
	int status = connect(network_socket, (struct sockaddr *) &server_address, sizeof(server_adddress));
	if (status == -1)
	{
		printf("An error occured while creating a connection\n");
	}

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
