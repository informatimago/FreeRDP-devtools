#ifndef krb5_print_h
#define krb5_print_h
#include <krb5/krb5.h>

char* sprint_krb5_int32(const krb5_int32 value);

char* sprint_krb5_magic(const krb5_magic magic);
char* sprint_krb5_data(const krb5_data* data);
char* sprint_krb5_principal(const krb5_principal principal);
char* sprint_krb5_address(const krb5_address* address);



typedef struct
{
	const krb5_int32 flag;
	const char* label; /*  null for last entry */ 
} krb5_flag_label;

char* sprint_krb5_flags(const krb5_flags flags, const krb5_flag_label * label_table);
char* sprint_krb5_enctype(const krb5_enctype enctype);
char* sprint_krb5_preauthtype(const krb5_preauthtype preauthtype);
char* sprint_krb5_get_init_creds_opt(const krb5_get_init_creds_opt* opt);


#endif // krb5_print_h
