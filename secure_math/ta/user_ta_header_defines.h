#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <secure_math_ta.h>

#define TA_UUID				TA_SECURE_MATH_UUID

#define TA_FLAGS			TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE			(2 * 1024)

#define TA_DATA_SIZE			(32 * 1024)

#define TA_VERSION	"1.0"

#define TA_DESCRIPTION	"Example of OP-TEE Trusted Application"

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "edu.asu.optee.examples.secure_math.property1", \
	USER_TA_PROP_TYPE_STRING, \
        "Some string" }, \
    { "edu.asu.optee.examples.secure_math.property2", \
	USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /* USER_TA_HEADER_DEFINES_H */
