#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void *  check_memory_internal(const char * function, int lino, void * pointer, unsigned int size, const char * description)
{
	if(!pointer)
	{
		fprintf(stderr, "%s:%d: could not allocate %d bytes for %s\n",function, lino, size, description);
		exit(1);
	}
	return pointer;
}

#define check_memory(pointer, size, description) check_memory_internal(__FUNCTION__, __LINE__, pointer, size, description)

static void * checked_malloc_internal(const char * function, int lino, unsigned int size, const char * description)
{
	return check_memory_internal(function,lino,malloc(size),size,description);
}

#define checked_malloc(size, description) checked_malloc_internal(__FUNCTION__, __LINE__, size, description)

static char* strings_join(const char* const* strings, const char* separator)
{
	char* result;
	char* current;
	size_t maximum_size;
	size_t i;
	size_t count = string_list_length(strings);
	size_t separator_length = strlen(separator);
	size_t * string_lengths = checked_malloc(sizeof (*string_lengths) * count, "string_lengths");
	size_t total_length = 0;
	for (i = 0; i < count; i ++)
	{
		string_lengths[i] = strlen(strings[i]);
		total_length += string_lengths[i];
	}
	maximum_size = (((count == 0)?0: (count - 1) * separator_length)
					+ total_length
					+ 1);
	result = checked_malloc(maximum_size, __FUNCTION__);
	strcpy(result, "");
	current = result;
	for (i = 0; i < count; i ++)
	{
		strcpy(current, strings[i]);
		current += string_lengths[i];
		if(i < count - 1)
		{
			strcpy(current, separator);
			current += separator_length;
		}
	}
	free(string_lengths);
	return result;
}

static char * ck_token_flags_label(ck_flags_t flags)
{
	static struct
	{
		const ck_flags_t flag,
		const char *  label;
	} table[] = {{CKF_RNG,                           "CKF_RNG"},
		     {CKF_WRITE_PROTECTED,               "CKF_WRITE_PROTECTED"},
		     {CKF_LOGIN_REQUIRED,                "CKF_LOGIN_REQUIRED"},
		     {CKF_USER_PIN_INITIALIZED,          "CKF_USER_PIN_INITIALIZED"},
		     {CKF_RESTORE_KEY_NOT_NEEDED,        "CKF_RESTORE_KEY_NOT_NEEDED"},
		     {CKF_CLOCK_ON_TOKEN,                "CKF_CLOCK_ON_TOKEN"},
		     {CKF_PROTECTED_AUTHENTICATION_PATH, "CKF_PROTECTED_AUTHENTICATION_PATH"},
		     {CKF_DUAL_CRYPTO_OPERATIONS,        "CKF_DUAL_CRYPTO_OPERATIONS"},
		     {CKF_TOKEN_INITIALIZED,             "CKF_TOKEN_INITIALIZED"},
		     {CKF_SECONDARY_AUTHENTICATION,      "CKF_SECONDARY_AUTHENTICATION"},
		     {CKF_USER_PIN_COUNT_LOW,            "CKF_USER_PIN_COUNT_LOW"},
		     {CKF_USER_PIN_FINAL_TRY,            "CKF_USER_PIN_FINAL_TRY"},
		     {CKF_USER_PIN_LOCKED,               "CKF_USER_PIN_LOCKED"},
		     {CKF_USER_PIN_TO_BE_CHANGED,        "CKF_USER_PIN_TO_BE_CHANGED"},
		     {CKF_SO_PIN_COUNT_LOW,              "CKF_SO_PIN_COUNT_LOW"},
		     {CKF_SO_PIN_FINAL_TRY,              "CKF_SO_PIN_FINAL_TRY"},
		     {CKF_SO_PIN_LOCKED,                 "CKF_SO_PIN_LOCKED"},
		     {CKF_SO_PIN_TO_BE_CHANGED,          "CKF_SO_PIN_TO_BE_CHANGED"}};
	const char *  labels[ARRAY_SIZE(table) + 1];
	int i;
	int j = 0;
	for (i = 0;i < ARRAY_SIZE(table);i ++ )
	{
		if (table[i].flag & flags != 0)
		{
			labels[j ++ ] = table[i].label;
		}
	}
	labels[j] = 0;
	return strings_join(labels, " | ");
}

