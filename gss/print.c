#include <winpr/strlst.h>
#include <winpr/sspi_gss.h>


/*
calling error uses 8 bits, so there could be 256 different calling error codes.
routine error uses 8 bits, so there could be 256 different routine error codes.
supplementary flags uses 16 bits, so there could be 16 different flag names.
*/

static struct code_label_map
{
	int code;
	const char*  label;
}
map_calling[] =
{
	{SSPI_GSS_S_CALL_INACCESSIBLE_READ,  "INACCESSIBLE_READ"},
	{SSPI_GSS_S_CALL_INACCESSIBLE_WRITE, "INACCESSIBLE_WRITE"},
	{SSPI_GSS_S_CALL_BAD_STRUCTURE,	     "BAD_STRUCTURE"},
	{0,                                  NULL}
},
map_routing[] =
{
	{SSPI_GSS_S_BAD_MECH,             "BAD_MECH"},
	{SSPI_GSS_S_BAD_NAME,             "BAD_NAME"},
	{SSPI_GSS_S_BAD_NAMETYPE,         "BAD_NAMETYPE"},
	{SSPI_GSS_S_BAD_BINDINGS,         "BAD_BINDINGS"},
	{SSPI_GSS_S_BAD_STATUS,           "BAD_STATUS"},
	{SSPI_GSS_S_BAD_SIG,              "BAD_SIG"},
	{SSPI_GSS_S_NO_CRED,              "NO_CRED"},
	{SSPI_GSS_S_NO_CONTEXT,           "NO_CONTEXT"},
	{SSPI_GSS_S_DEFECTIVE_TOKEN,      "DEFECTIVE_TOKEN"},
	{SSPI_GSS_S_DEFECTIVE_CREDENTIAL, "DEFECTIVE_CREDENTIAL"},
	{SSPI_GSS_S_CREDENTIALS_EXPIRED,  "CREDENTIALS_EXPIRED"},
	{SSPI_GSS_S_CONTEXT_EXPIRED,      "CONTEXT_EXPIRED"},
	{SSPI_GSS_S_FAILURE,              "FAILURE"},
	{SSPI_GSS_S_BAD_QOP,              "BAD_QOP"},
	{SSPI_GSS_S_UNAUTHORIZED,         "UNAUTHORIZED"},
	{SSPI_GSS_S_UNAVAILABLE,          "UNAVAILABLE"},
	{SSPI_GSS_S_DUPLICATE_ELEMENT,    "DUPLICATE_ELEMENT"},
	{SSPI_GSS_S_NAME_NOT_MN,          "NAME_NOT_MN"},
	{SSPI_GSS_S_BAD_MECH_ATTR,        "BAD_MECH_ATTR"},
	{0,                               NULL}
},
map_supplementary[] =
{
	{SSPI_GSS_S_CONTINUE_NEEDED,      "CONTINUE_NEEDED"},
	{SSPI_GSS_S_DUPLICATE_TOKEN,      "DUPLICATE_TOKEN"},
	{SSPI_GSS_S_OLD_TOKEN,            "OLD_TOKEN"},
	{SSPI_GSS_S_UNSEQ_TOKEN,          "UNSEQ_TOKEN"},
	{SSPI_GSS_S_GAP_TOKEN,            "GAP_TOKEN"},
	{0,                               NULL}
};

static struct
{
	enum { type_value, type_flag } type;
	int size;
	int offset;
	int mask;
	struct code_label_map * map
} sspi_gss_status_label_maps[] = {
	{type_value, 8,  SSPI_GSS_C_CALLING_ERROR_OFFSET, SSPI_GSS_C_CALLING_ERROR_MASK, map_calling},
	{type_value, 8,  SSPI_GSS_C_ROUTINE_ERROR_OFFSET, SSPI_GSS_C_ROUTINE_ERROR_MASK, map_routing},
	{type_flag,  16, SSPI_GSS_C_SUPPLEMENTARY_OFFSET, SSPI_GSS_C_SUPPLEMENTARY_MASK, map_supplementary}
        };

char* sspi_gss_status_label(UINT32 status)
{
	static const char * sep = ", ";
	int i;
	char ** items = malloc((1 + ARRAY_SIZE(sspi_gss_status_label_maps)) * sizeof(char*));

	if (items == NULL)
	{
		goto out_of_memory;
	}

	for (i = 0; i < ARRAY_SIZE(sspi_gss_status_label_maps); i++)
	{
		int code = status & (sspi_gss_status_label_maps[i].mask << sspi_gss_status_label_maps[i].offset);
		int j = 0;
		int k;
		char** flags;
		switch (sspi_gss_status_label_maps[i].type)
		{
			case type_value:
				while((sspi_gss_status_label_maps[i].map[j].label != NULL)
					&& (sspi_gss_status_label_maps[i].map[j].code != code))
				{
					j++;
				}
				items[i] = strdup(sspi_gss_status_label_maps[i].map[j].label
					?sspi_gss_status_label_maps[i].map[j].label
					:"Unknown status code.");
				break;
			case type_flag:
				flags = malloc((1 + sspi_gss_status_label_maps[i].size) * sizeof(char*));

				if (flags == NULL)
				{
					goto out_of_memory;
				}

				k = 0;
				for (j = 0;sspi_gss_status_label_maps[i].map[j].label != NULL; j++)
				{
					if(code & sspi_gss_status_label_maps[i].map[j].code != 0)
					{
						flags[k] = strdup(sspi_gss_status_label_maps[i].map[j].label);
						if (flags[k] == NULL)
						{
							string_list_free(flags);
							goto out_of_memory;
						}
						k ++ ;
					}
				}
				flags[k] = NULL;
				items[i] = string_join(flags,"|");
				string_list_free(flags);
				break;
		}

		if (items[i] == NULL)
		{
			goto out_of_memory;
		}

		if (table[i].flag & flags != 0)
		{
			labels[j ++ ] = table[i].label;
		}
	}
	items[i] = NULL;
	return strings_join(labels, " | ");

out_of_memory:
	string_list_free(items);
	return strdup("ERROR: Cannot allocate the label.");
}


