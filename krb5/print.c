#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#ifndef krb5_print_h
#include "print.h"
#endif

#define countof(a) (sizeof(a)/sizeof((a)[0]))

void *  check_memory_internal(const char * function, int lino, void * pointer, unsigned int size, const char * description)
{
	if(!pointer){
		fprintf(stderr, "%s:%d: could not allocate %d bytes for %s\n",function, lino, size, description);
		exit(1);}
	return pointer;
}

#define check_memory(pointer, size, description) check_memory_internal(__FUNCTION__, __LINE__, pointer, size, description)

void * checked_malloc_internal(const char * function, int lino, unsigned int size, const char * description)
{
	return check_memory_internal(function,lino,malloc(size),size,description);
}

#define checked_malloc(size, description) checked_malloc_internal(__FUNCTION__, __LINE__, size, description)


static size_t strings_count(const char* const* strings){
	int i;
	size_t count = 0;
	for(i = 0;strings[i];i ++ ){
		count ++;}
	return count;}

/* static size_t strings_total_length(const char** strings){ */
/* 	int i; */
/* 	size_t length = 0; */
/* 	for(i = 0;strings[i];i ++ ){ */
/* 		length += strlen(strings[i]);} */
/* 	return length;} */

static char* strings_join(const char* const* strings, const char* separator)
{
	char* result;
	char* current;
	size_t maximum_size;
	size_t i;
	size_t count = strings_count(strings);
	size_t separator_length = strlen(separator);
	size_t * string_lengths = checked_malloc(sizeof (*string_lengths) * count, "string_lengths");
	size_t total_length = 0;
	for (i = 0; i < count; i ++){
		string_lengths[i] = strlen(strings[i]);
		total_length += string_lengths[i];}
	maximum_size = (((count == 0)?0: (count - 1) * separator_length)
					+ total_length
					+ 1);
	result = checked_malloc(maximum_size, __FUNCTION__);
	strcpy(result, "");
	current = result;
	for (i = 0; i < count; i ++){
		strcpy(current, strings[i]);
		current += string_lengths[i];
		if(i < count - 1){
			strcpy(current, separator);
			current += separator_length;}}
	free(string_lengths);
	return result;
}

static char* string_concatenate(const char* string, ...)
{
	char *  result;
	char *  current;
	/* sum the lengths of the strings */
	const char * arg;
	volatile int i = 0; /* for debugging purposes, we maintain an index of the arguments */ 
	va_list strings;
	int total_length = 0;
	arg=string;
	va_start(strings,string);
	while(arg){
		total_length+=strlen(arg);
		arg=va_arg(strings,const char*);
		i++;}
	va_end(strings);
	total_length += 1; /*  null byte */
	result = checked_malloc(total_length, "concatenation");
	/* start copying */
	strcpy(result, "");
	current = result;
	arg = string;
	i = 0;
	va_start(strings, string);
	while (arg){
		strcpy(current, arg);
		current += strlen(arg);
		arg = va_arg(strings, const char*);
		i ++;}
	va_end(strings);
	/* strcpy copied the terminating null byte */
	return result;
}



char* sprint_krb5_magic(const krb5_magic magic)
{
	char * buffer = checked_malloc(11, "krb5_magic");
	snprintf(buffer, 11, "[%08X]", magic);
	return buffer;
}

char* sprint_krb5_data(const krb5_data* data)
{
	char* smagic = sprint_krb5_magic(data->magic);
	char* result = string_concatenate(smagic, " ", data->data, 0);
	free(smagic);
	return result;
}

char * sprint_krb5_principal_type(const krb5_int32 type)
{
	static const char * types0[] = {
		"KRB5_NT_UNKNOWN",
		"KRB5_NT_PRINCIPAL", 
		"KRB5_NT_SRV_INST", 
		"KRB5_NT_SRV_HST", 
		"KRB5_NT_SRV_XHST", 
		"KRB5_NT_UID", 
		"KRB5_NT_X500_PRINCIPAL", 
		"KRB5_NT_SMTP_NAME",
		"Unknown principal type 8", 
		"Unknown principal type 9", 
		"KRB5_NT_ENTERPRISE_PRINCIPAL", 
		"KRB5_NT_WELLKNOWN"
	};

	static const char * types_130[] = {
		"KRB5_NT_ENT_PRINCIPAL_AND_ID", 
		"KRB5_NT_MS_PRINCIPAL_AND_ID", 
		"KRB5_NT_MS_PRINCIPAL"
	};

	if ((0 <= type) && (type < countof(types0)))
 	{
		return strdup(types0[type]);
	}
	else if ((-130 <= type) && (type < -130 + countof(types_130)))
	{
		return strdup(types_130[type]);
	}
	else
	{
		char * buffer = checked_malloc(48, "unknown principal type");
		sprintf(buffer, "Unknown principal type %d", type);
		return buffer;
	}
}

char* sprint_krb5_principal(const krb5_principal principal)
{
	char* smagic = sprint_krb5_magic(principal->magic);
	char* srealm = sprint_krb5_data(&(principal->realm));
	char* stype = sprint_krb5_principal_type(principal->type);
	char** scomponent_list = checked_malloc(sizeof(char*) * principal->length, "krb5 principal component array");
	char*  scomponents;
	char*  next;
	const char*  sep = "";
	char* result;
	int complength = 0;
	int i;
	for (i = 0;i < principal->length;i ++ )
	{
		scomponent_list[i] = sprint_krb5_data(&(principal->data[i]));
		complength += 1 + strlen(scomponent_list[i]);
	}
	scomponents = checked_malloc(1 + complength, "krb5 principal components string");
	next = scomponents;
	for (i = 0;i < principal->length;i ++ )
	{
		strcpy(next, sep);
		next += strlen(sep);
		strcpy(next, scomponent_list[i]);
		next += strlen(scomponent_list[i]);
		sep = "/";
	}
	result = string_concatenate(smagic, " ", stype, ": ", scomponents, " @ ", srealm, 0);
	free(smagic);
	free(srealm);
	free(stype);
	for (i = 0;i < principal->length;i ++ )
	{
		free(scomponent_list[i]);
	}
	free(scomponent_list);
	free(scomponents);
	return result;
}

char * sprint_krb5_address_type(const krb5_addrtype type)
{
	static struct
	{
		int type;
		const char * label;
	} map[] = {
		{ADDRTYPE_INET,     "ADDRTYPE_INET"}, 
		{ADDRTYPE_CHAOS,    "ADDRTYPE_CHAOS"}, 
		{ADDRTYPE_XNS,      "ADDRTYPE_XNS"}, 
		{ADDRTYPE_ISO,      "ADDRTYPE_ISO"}, 
		{ADDRTYPE_DDP,      "ADDRTYPE_DDP"}, 
		{ADDRTYPE_NETBIOS,  "ADDRTYPE_NETBIOS"}, 
		{ADDRTYPE_INET6,    "ADDRTYPE_INET6"}, 
		{ADDRTYPE_ADDRPORT, "ADDRTYPE_ADDRPORT"}, 
		{ADDRTYPE_IPPORT,   "ADDRTYPE_IPPORT"}
	};

	int i;
	for (i = 0;i < ARRAYSIZE(map);i ++ )
	{
		if (type == map[i].type)
		{
			return strdup(map[i].label);
		}
	}

	{
		char * buffer = checked_malloc(64, "unknown address type");
		sprintf(buffer, "Unknown %saddress type %d",
				ADDRTYPE_IS_LOCAL(type)?"local ":"", type);
		return buffer;
	}		
}

char *  sprint_krb5_octet(unsigned int length, krb5_octet * octets)
{
	char * result = checked_malloc(3*length + 1, "krb5 octets");
	char * next;
	int i;
	for (i = 0, next = result;i < length;i ++, next += 3)
	{
		sprintf(next, "%02x ", octets[i]);
	}
	* next = 0;
	return result;
}

char* sprint_krb5_address(const krb5_address* address){
	char* smagic = sprint_krb5_magic(address->magic);
	char* stype = sprint_krb5_address_type(address->addrtype);
	char* scontents = sprint_krb5_octet(address->length, address->contents);
	char * result = string_concatenate(smagic, " ", stype, ": ", scontents, 0);
	free(smagic);
	free(stype);
	free(scontents);
	return result;}

static bool end_of_label_table(const krb5_flag_label *flags, int i){
	return flags[i].flag == 0;}

char* sprint_krb5_flags(const krb5_flags flags, const krb5_flag_label * label_table){
	char*  result;
	const char** labels;
	size_t j = 0;
	size_t i;
	size_t count = 0;
	for (i = 0; !end_of_label_table(label_table, i); i ++){
		if(label_table[i].flag & flags){
			count++;}}
	labels = checked_malloc(sizeof(*labels) * (1 + count), "flags description");
	for (i = 0; !end_of_label_table(label_table, i); i ++){
		if (label_table[i].flag & flags){
			labels[j] = label_table[i].label;
			j ++ ;}}
	labels[j] = 0;
	result = strings_join(labels, "|");
	free(labels);
	return result;}

char* sprint_krb5_enctype(const krb5_enctype enctype)
{
	static const struct
	{
		const krb5_enctype enctype;
		const char *  label;
	} enctypes[] = {
		{ENCTYPE_NULL, "ENCTYPE_NULL"},
		{ENCTYPE_DES_CBC_CRC, "ENCTYPE_DES_CBC_CRC"},
		{ENCTYPE_DES_CBC_MD4, "ENCTYPE_DES_CBC_MD4"},
		{ENCTYPE_DES_CBC_MD5, "ENCTYPE_DES_CBC_MD5"},
		{ENCTYPE_DES_CBC_RAW, "ENCTYPE_DES_CBC_RAW"},
		{ENCTYPE_DES3_CBC_SHA, "ENCTYPE_DES3_CBC_SHA"},
		{ENCTYPE_DES3_CBC_RAW, "ENCTYPE_DES3_CBC_RAW"},
		{ENCTYPE_DES_HMAC_SHA1, "ENCTYPE_DES_HMAC_SHA1"},
		{ENCTYPE_DSA_SHA1_CMS, "ENCTYPE_DSA_SHA1_CMS"},
		{ENCTYPE_MD5_RSA_CMS, "ENCTYPE_MD5_RSA_CMS"},
		{ENCTYPE_SHA1_RSA_CMS, "ENCTYPE_SHA1_RSA_CMS"},
		{ENCTYPE_RC2_CBC_ENV, "ENCTYPE_RC2_CBC_ENV"},
		{ENCTYPE_RSA_ENV, "ENCTYPE_RSA_ENV"},
		{ENCTYPE_RSA_ES_OAEP_ENV, "ENCTYPE_RSA_ES_OAEP_ENV"},
		{ENCTYPE_DES3_CBC_ENV, "ENCTYPE_DES3_CBC_ENV"},
		{ENCTYPE_DES3_CBC_SHA1, "ENCTYPE_DES3_CBC_SHA1"},
		{ENCTYPE_AES128_CTS_HMAC_SHA1_96, "ENCTYPE_AES128_CTS_HMAC_SHA1_96"},
		{ENCTYPE_AES256_CTS_HMAC_SHA1_96, "ENCTYPE_AES256_CTS_HMAC_SHA1_96"},
		{ENCTYPE_ARCFOUR_HMAC, "ENCTYPE_ARCFOUR_HMAC"},
		{ENCTYPE_ARCFOUR_HMAC_EXP, "ENCTYPE_ARCFOUR_HMAC_EXP"},
		{ENCTYPE_CAMELLIA128_CTS_CMAC, "ENCTYPE_CAMELLIA128_CTS_CMAC"},
		{ENCTYPE_CAMELLIA256_CTS_CMAC, "ENCTYPE_CAMELLIA256_CTS_CMAC"},
		{ENCTYPE_UNKNOWN, "ENCTYPE_UNKNOWN"},
		{0, 0}
	};
	int i;
	for (i = 0;enctypes[i].label;i ++ )
	{
		if (enctypes[i].enctype == enctype)
		{
			return check_memory(strdup(enctypes[i].label), 1 + strlen(enctypes[i].label), "enctype label");
		}
	}

	{
		char * buffer = checked_malloc(48, "unknown enctype label");
		sprintf(buffer, "Unknown enctype %d", enctype);
		return buffer;
	}
}

char* sprint_krb5_preauthtype(const krb5_preauthtype preauthtype){
	char * buffer = checked_malloc(48, "preauthtype");
	sprintf(buffer, "preauthtype %d", preauthtype);
	return buffer;}

char* sprint_krb5_boolean(const int value){
	return check_memory(strdup(value?"true":"false"), 6, "boolean");}

char* sprint_krb5_int32(const krb5_int32 value){
	char * buffer = checked_malloc(24, "int32");
	sprintf(buffer, "%d", value);
	return buffer;}

static const krb5_flag_label get_init_creds_opt_flag_labels[]={
	{KRB5_GET_INIT_CREDS_OPT_TKT_LIFE,      "KRB5_GET_INIT_CREDS_OPT_TKT_LIFE"},
	{KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE,    "KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE"},
	{KRB5_GET_INIT_CREDS_OPT_FORWARDABLE,   "KRB5_GET_INIT_CREDS_OPT_FORWARDABLE"},
	{KRB5_GET_INIT_CREDS_OPT_PROXIABLE,     "KRB5_GET_INIT_CREDS_OPT_PROXIABLE"},
	{KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST,    "KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST"},
	{KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST,  "KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST"},
	{KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST,  "KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST"},
	{KRB5_GET_INIT_CREDS_OPT_SALT,          "KRB5_GET_INIT_CREDS_OPT_SALT"},
	{KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT, "KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT"},
	{KRB5_GET_INIT_CREDS_OPT_CANONICALIZE,  "KRB5_GET_INIT_CREDS_OPT_CANONICALIZE"},
	{KRB5_GET_INIT_CREDS_OPT_ANONYMOUS,     "KRB5_GET_INIT_CREDS_OPT_ANONYMOUS"}, 
	{0,0}
};

static size_t addresses_count(krb5_address** const address_list){
	size_t count = 0;
	size_t i;
	if(address_list){
		for(i=0;address_list[i];i++){
			count++;}}
	return count;}

char* sprint_krb5_get_init_creds_opt(const krb5_get_init_creds_opt* opt){
	char* flags       	 = sprint_krb5_flags(opt->flags, get_init_creds_opt_flag_labels);
	char* tkt_life    	 = sprint_krb5_int32(opt->tkt_life);
	char* renew_life  	 = sprint_krb5_int32(opt->renew_life);
	char* forwardable 	 = sprint_krb5_boolean(opt->forwardable);
	char* proxiable   	 = sprint_krb5_boolean(opt->proxiable);
	char** etype_list  = checked_malloc(sizeof (*etype_list) * (1 + opt->etype_list_length), "etype_list");
	size_t address_count = addresses_count(opt->address_list);
	char** address_list  = checked_malloc(sizeof (*address_list) * (1 + address_count), "address_list");
	char** preauth_list  = checked_malloc(sizeof (*preauth_list) * (1 + opt->preauth_list_length), "preauth_list");
	char * etypes;
	char * addresses;
	char * preauthtypes;
	int i;
	for (i = 0;i < opt->etype_list_length;i ++ ){
		etype_list[i] = sprint_krb5_enctype(opt->etype_list[i]);}
	etype_list[opt->etype_list_length] = 0;
	etypes = strings_join((const char *const *)etype_list, ", ");
	for (i = 0;i < address_count;i ++ ){
		address_list[i] = sprint_krb5_address(opt->address_list[i]);}
	address_list[address_count] = 0;
	addresses = strings_join((const char *const *)address_list, ", ");
	for (i = 0;i < opt->preauth_list_length;i ++ ){
		preauth_list[i] = sprint_krb5_preauthtype(opt->preauth_list[i]);}
	preauth_list[opt->preauth_list_length] = 0;
	preauthtypes = strings_join((const char *const *)preauth_list, ", ");
	char * salt = opt->salt?sprint_krb5_data(opt->salt):check_memory(strdup("NIL"), 4, "salt");
	char * result = string_concatenate("(krb5_get_init_creds_opt",
									   " :flags ", flags,
									   " :tkt_life ", tkt_life,
									   " :renew_life ", renew_life,
									   " :forwardable ", forwardable,
									   " :proxiable ", proxiable,
									   " :etype_list (", etypes, ")", 
									   " :addresses (", addresses, ")", 
									   " :preauth_list (", preauthtypes, ")", 
									   " :salt ", salt, ")",
									   NULL);
	for (i = 0;i < opt->etype_list_length;i ++ ){
		free(etype_list[i]);}
	for (i = 0;i < address_count;i ++ ){
		free(address_list[i]);}
	for (i = 0;i < opt->preauth_list_length;i ++ ){
		free(preauth_list[i]);}
	free(salt);
	free(preauthtypes);
	free(addresses);
	free(etypes);
	free(preauth_list);
	free(address_list);
	free(etype_list);
	free(proxiable);
	free(forwardable);
	free(renew_life);
	free(tkt_life);
	free(flags);
	return result;}	

