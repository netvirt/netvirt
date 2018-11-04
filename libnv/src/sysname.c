#include <stdlib.h>

#include "log.h"

#ifndef _WIN32
	#include <stdio.h>
	#include <sys/utsname.h>
#else
#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include "utsname.h"

#define UTSNAME_LENGTH 256
struct utsname {
	char sysname[UTSNAME_LENGTH];
	char nodename[UTSNAME_LENGTH];
	char release[UTSNAME_LENGTH];
	char version[UTSNAME_LENGTH];
	char machine[UTSNAME_LENGTH];
};

int
uname(struct utsname *name) {

	struct utsname	*ret;
	OSVERSIONINFO	 version_info;
	SYSTEM_INFO	 sys_info;
    
	/* get Windows version info */
	ZeroMemory(&version_info, sizeof(OSVERSIONINFO));
	version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&version_info);
    
	/* get hardware info */
	ZeroMemory(&sys_info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&sys_info);

	strcpy(name->sysname, "Windows");
	itoa(version_info.dwBuildNumber, name->release, 10);
	sprintf(name->version, "%i.%i", version_info.dwMajorVersion, version_info.dwMinorVersion);

	if (gethostname(name->nodename, UTSNAME_LENGTH) != 0) {
		if (WSAGetLastError() == WSANOTINITIALISED) {
			WSADATA WSAData;
			WSAStartup(MAKEWORD(1, 0), &WSAData);
			gethostname(name->nodename, UTSNAME_LENGTH);
			WSACleanup();
		} else
			return WSAGetLastError();
	}

	switch(sys_info.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
		strcpy(name->machine, "x86_64");
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		strcpy(name->machine, "ia64");
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		strcpy(name->machine, "x86");
		break;
	case PROCESSOR_ARCHITECTURE_UNKNOWN:
	default:
		strcpy(name->machine, "unknown");
	}

	return 0;
}
#endif

char *
get_sysname()
{
        struct utsname	 buf;
	char		*sysname = NULL;

        if (uname(&buf) < 0) {
		log_warn("%s: uname", __func__);
		goto error;
	}
		
	if (asprintf(&sysname, "%s,%s,%s,%s", buf.sysname, buf.release, buf.version, buf.machine) < 0) {
		log_warnx("%s: asprintf", __func__);
		goto error;
	}

	return (sysname);

error:
	free(sysname);
	return (NULL);
}

