#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>

#include <freerdp/settings.h>
#include <freerdp/freerdp.h>
#include <freerdp/log.h>


static const char* device_type_label(UINT32 type)
{
	switch (type)
	{
		case RDPDR_DTYP_SERIAL:
			return "serial";

		case RDPDR_DTYP_PARALLEL:
			return "parallel";

		case RDPDR_DTYP_PRINT:
			return "printer";

		case RDPDR_DTYP_FILESYSTEM:
			return "filesystem";

		case RDPDR_DTYP_SMARTCARD:
			return "smartcard";

		default:
			{
				static char buffer[80];
				sprintf(buffer, "unknown device type %d", type);
				return buffer;
			}
	}
}

void freerdp_device_print(RDPDR_DEVICE* device, UINT32 index, const char * fname, UINT32 lino)
{
        WLog_INFO(TAG, "%s:%u: device[%d] = { id = %d,  type = %s, name = %s }",
                fname, lino, index, device->Id, device_type_label(device->Type),
                (device->Name ? device->Name : "(null)"));
}

void freerdp_device_print_all(rdpSettings* settings, const char * fname, UINT32 lino)
{
	UINT32 index;

	for (index = 0; index < settings->DeviceCount; index++)
	{
                freerdp_device_print((RDPDR_DEVICE*) settings->DeviceArray[index], index, fname, lino);
	}
}

