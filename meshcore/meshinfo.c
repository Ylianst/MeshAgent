/*
Copyright 2006 - 2018 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef __APPLE__
#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#if defined(WINSOCK2)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#elif defined(WINSOCK1)
#include <winsock.h>
#include <wininet.h>
#elif defined(_POSIX)
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#ifndef _FREEBSD
	#include <linux/reboot.h>
#endif

#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
#define IFRSIZE   ((int)(size * sizeof (struct ifreq)))
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibCrypto.h"
#include "meshinfo.h"


#ifdef WINSOCK2
// This is the Windows implementation of a method that gets information about local interfaces
int info_GetLocalInterfaces(char* data, int maxdata)
{
#ifdef _MINCORE
	return 0;
#else
	IP_ADAPTER_INFO			*pAdapterInfo;
	IP_ADAPTER_ADDRESSES	*pAdapterAddresses;
	PIP_ADAPTER_INFO		pAdapter;
	PIP_ADAPTER_ADDRESSES	pAdapterAddr;
	ULONG					ulOutBufLen = 0;
	DWORD					dwRetVal;
	unsigned int			j;
	int						adapterCount = 0;
	unsigned long			palen;
	unsigned char			pa[16];
	int						ptr = 0;
	size_t					templen;
	char					temp[1024];
	IPAddr					ip1;
	IPAddr					ip2;

	// Lets see how much memory we need to get the list of local interfaces
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) return 0;
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) { free(pAdapterInfo); if (ulOutBufLen == 0) return 0; pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen); }

	// Get the list of all local interfaces
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS || ulOutBufLen == 0) { free(pAdapterInfo); return 0; }

	// Count how many interfaces are present
	pAdapter = pAdapterInfo;
	while (pAdapter) { adapterCount++; pAdapter = pAdapter->Next; }

	// Lets see how much memory we need to get the list of local adapters
	pAdapterAddresses = (IP_ADAPTER_ADDRESSES *)malloc(sizeof(IP_ADAPTER_ADDRESSES));
	if (pAdapterAddresses == NULL) { free(pAdapterInfo); return 0; }
	ulOutBufLen = sizeof(IP_ADAPTER_ADDRESSES);
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &ulOutBufLen) != ERROR_SUCCESS)
	{
		free(pAdapterAddresses);
		if (ulOutBufLen == 0) return 0;
		pAdapterAddresses = (IP_ADAPTER_ADDRESSES *)malloc(ulOutBufLen);
	}

	// Get the list of all local interfaces
	if ((dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &ulOutBufLen)) != ERROR_SUCCESS || ulOutBufLen == 0) { free(pAdapterInfo); free(pAdapterAddresses); return 0; }

	int r = 0;
	j = 0;
	pAdapter = pAdapterInfo;
	while (pAdapter)
	{
		// Find the corresponding adapter for this interface
		pAdapterAddr = pAdapterAddresses;
		while (pAdapterAddr != NULL && pAdapterAddr->IfIndex != pAdapter->Index) { pAdapterAddr = pAdapterAddr->Next; }
		if (pAdapterAddr == NULL) { free(pAdapterInfo); free(pAdapterAddresses); return 0; }

		if (j > 0) { ptr += (r=sprintf_s(data + ptr, maxdata - ptr, ",")); }
		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, "{"));

		// Interface type
		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, "\"type\":%d", pAdapter->Type));

		// Interface name
		if (wcslen(pAdapterAddr->FriendlyName) > 0) {
			wcstombs_s(&templen, temp, 1023, pAdapterAddr->FriendlyName, wcslen(pAdapterAddr->FriendlyName));
			ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"name\":\"%s\"", temp));
		}

		// Interface description
		if (wcslen(pAdapterAddr->Description) > 0) {
			wcstombs_s(&templen, temp, 1023, pAdapterAddr->Description, wcslen(pAdapterAddr->Description));
			ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"desc\":\"%s\"", temp));
		}

		// Interface MAC address
		if (pAdapter->AddressLength == 6) {
			ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"mac\":\"%02x%02x%02x%02x%02x%02x\"", pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2], pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]));
		}

		// Interface DNS suffix
		if (wcslen(pAdapterAddr->DnsSuffix) > 0) {
			wcstombs_s(&templen, temp, 1023, pAdapterAddr->DnsSuffix, wcslen(pAdapterAddr->DnsSuffix));
			ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"dnssuffix\":\"%s\"", temp));
		}

		// IPv4 address and subnet mask
		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"v4addr\":\"%s\"", pAdapter->IpAddressList.IpAddress.String));
		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"v4mask\":\"%s\"", pAdapter->IpAddressList.IpMask.String));
		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"v4gateway\":\"%s\"", pAdapter->GatewayList.IpAddress.String));

		// Get the gateway MAC address
		ILibInet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &ip1);
		ILibInet_pton(AF_INET, pAdapter->GatewayList.IpAddress.String, &ip2);
		SendARP(ip2, ip1, pa, &palen);
		if (palen == 6) { ptr += (r = sprintf_s(data + ptr, maxdata - ptr, ",\"gatewaymac\":\"%02x%02x%02x%02x%02x%02x\"", pa[0], pa[1], pa[2], pa[3], pa[4], pa[5])); }

		ptr += (r = sprintf_s(data + ptr, maxdata - ptr, "}"));

		j++;
		pAdapter = pAdapter->Next;
	}

	// Free the local interface memory
	free(pAdapterInfo);
	free(pAdapterAddresses);

	return (r < 0 ? 0 : ptr);
#endif
}
#endif

#ifdef _POSIX

// This method reads a stream where the length of the file can't be determined. Useful in POSIX only
int __fastcall utilx_readfile2(char* filename, char** data)
{
	FILE * pFile;
	int count = 0;
	int len = 0;
	*data = NULL;
	if (filename == NULL) return 0;

	pFile = fopen(filename, "rb");
	if (pFile != NULL)
	{
		*data = malloc(1024);
		if (*data == NULL) { fclose(pFile); return 0; }
		do
		{
			len = fread((*data) + count, 1, 1023, pFile);
			count += len;
			if (len == 1023)
			{
				if ((*data = realloc(*data, count + 1024)) == NULL) { ILIBCRITICALEXIT(254); }
			}
		} while (len == 100);
		(*data)[count] = 0;
		fclose(pFile);
	}

	return count;
}

// TODO: Add support for IPv6, and check that it's on the correct interface
int info_GetHwAddress(char* ipaddr, int ipaddrlen, char** hwaddr)
{
	char* arpcache = NULL;
	int len, r = 0;
	char* ptr = NULL;
	char substr[32];

	*hwaddr = NULL;
	if (ipaddrlen >= 30 || (ipaddrlen == 7 && memcmp(ipaddr, "0.0.0.0", 7) == 0)) return 0;
	len = utilx_readfile2("/proc/net/arp", &arpcache);
	if (len == 0) return 0;

	substr[0] = '\n';
	memcpy(substr + 1, ipaddr, ipaddrlen);
	substr[ipaddrlen + 1] = ' ';
	substr[ipaddrlen + 2] = 0;

	ptr = strstr(arpcache, substr);
	if ((ptr != NULL) && (ptr + 61 < arpcache + len) && (ptr[44] == ':') && (ptr[47] == ':') && (ptr[56] == ':'))
	{
		if ((*hwaddr = (char*)malloc(6)) == NULL) ILIBCRITICALEXIT(254);
		for (; r < 6; r++) { (*hwaddr)[r] = util_hexToint(ptr + 42 + (r * 3), 2); }
	}
	free(arpcache);
	return r;
}

// The Linux equal of Windows SendARP
int SendARP(char* DestIP, char* SrcIP, void* pMacAddr, int* PhyAddrLen)
{
	char tmp[50];
	char* ptr = NULL;
	ILibInet_ntop(AF_INET, DestIP, tmp, 50);
	if (*PhyAddrLen < 6) return -1;
	*PhyAddrLen = info_GetHwAddress(tmp, strlen(tmp), &ptr);
	if (ptr != NULL)
	{
		memcpy(pMacAddr, ptr, 6);
		free(ptr);
		return 0;
	}
	return -1;
}

// TODO: See if we can do this for each interface, right now interface is ignored
int info_GetDefaultFqdn(char* ifname, char** fqdn)
{
	char* resolv;
	int len, r = 0;
	struct parser_result* parse;
	struct parser_result_field* p;
	struct parser_result* parse2;
	struct parser_result_field* p2;

	*fqdn = NULL;
	len = utilx_readfile2("/etc/resolv.conf", &resolv);
	if (len == 0) return 0;

	parse = ILibParseString(resolv, 0, len, "\n", 1);
	p = parse->FirstResult;
	while (p != NULL)
	{
		parse2 = ILibParseString(p->data, 0, p->datalength, " ", 1);
		p2 = parse2->FirstResult;
		if (p2->datalength == 6 && memcmp(p2->data, "domain", 6) == 0)
		{
			// We found the system's default FQDN
			r = p2->NextResult->datalength;
			*fqdn = malloc(r + 1);
			memcpy(*fqdn, p2->NextResult->data, r);
			(*fqdn)[r] = 0;
			ILibDestructParserResults(parse2);
			break;
		}
		ILibDestructParserResults(parse2);
		p = p->NextResult; // Skip to next line
	}
	ILibDestructParserResults(parse);
	free(resolv);
	return r;
}

// TODO: Add IPv6 support
int info_GetDefaultGateway(char* ifname, char** gateway)
{
	char* route;
	char* temp;
	int len, r = 0, i;
	int ifnamelen = strlen(ifname);
	struct parser_result* parse;
	struct parser_result_field* p;
	struct parser_result* parse2;
	struct parser_result_field* p2;

	*gateway = NULL;
	len = utilx_readfile2("/proc/net/route", &route);
	if (len == 0) return 0;

	parse = ILibParseString(route, 0, len, "\n", 1);
	p = parse->FirstResult;
	p = p->NextResult; // Skip the first line
	while (p != NULL)
	{
		parse2 = ILibParseString(p->data, 0, p->datalength, "\t", 1);
		p2 = parse2->FirstResult;
		if (ifnamelen == p2->datalength && memcmp(p2->data, ifname, ifnamelen) == 0)
		{
			if (p2->NextResult->datalength == 8 && memcmp(p2->NextResult->data, "00000000", 8) == 0)
			{
				// We found the default gateway for this interface
				r = p2->NextResult->NextResult->datalength / 2;
				*gateway = malloc(r);
				temp = p2->NextResult->NextResult->data;
				for (i = 0; i < r; i++) { (*gateway)[r - (i + 1)] = util_hexToint(temp + (i * 2), 2); }
				ILibDestructParserResults(parse2);
				break;
			}
		}
		ILibDestructParserResults(parse2);
		p = p->NextResult; // Skip to next line
	}
	ILibDestructParserResults(parse);
	free(route);
	return r;
}

// This is the POSIX implementation of a method that gets information about local interfaces
int info_GetLocalInterfaces(char* data, int maxdata)
{
#if defined NACL || defined(_FREEBSD)
	return 0;
#else

	int ptr = 0;
	int sockfd, size = 1, j;
	int adapterCount = 0;
	struct ifreq *ifr;
	struct ifconf ifc;
	char temp[1024];
	char* gateway = NULL;

	// Fetch the list of local interfaces
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) return 0;
	ifc.ifc_len = IFRSIZE;
	ifc.ifc_req = NULL;
	do
	{
		++size;
		// realloc buffer size until no overflow occurs
		if ((ifc.ifc_req = realloc(ifc.ifc_req, IFRSIZE)) == NULL) return 0;
		ifc.ifc_len = IFRSIZE;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) return 0;
	} while (IFRSIZE <= ifc.ifc_len);

	ifr = ifc.ifc_req;
	for (; (char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len; ++ifr)
	{
		if (ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data) continue;  // Duplicate
		if (ioctl(sockfd, SIOCGIFFLAGS, ifr)) continue; // Failed
		if (memcmp(ifr->ifr_name, "lo", 3) == 0) continue; // Loopback

		if (adapterCount > 0) { ptr += sprintf_s(data + ptr, maxdata - ptr, ","); }
		ptr += sprintf_s(data + ptr, maxdata - ptr, "{");

		// Get the name of the interface
		ptr += sprintf_s(data + ptr, maxdata - ptr, "\"name\":\"%s\"", ifr->ifr_name);

		// Get the FQDN (DNS Suffix)
		j = info_GetDefaultFqdn(ifr->ifr_name, &gateway);
		if (j > 0) { ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"dnssuffix\":\"%s\"", gateway); }
		if (gateway != NULL) { free(gateway); gateway = NULL; }

		// Get the Default Gateway IP address
		j = info_GetDefaultGateway(ifr->ifr_name, &gateway);
		if (j == 4) { ILibInet_ntop(AF_INET, gateway, temp, 1024); ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"v4gateway\":\"%s\"", temp); }
		if (gateway != NULL) { free(gateway); gateway = NULL; }

		// Get the Default Gateway MAC address
		j = info_GetHwAddress(temp, strlen(temp), &gateway);
		if (j == 6) { ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"gatewaymac\":\"%02x%02x%02x%02x%02x%02x\"", (unsigned char)gateway[0], (unsigned char)gateway[1], (unsigned char)gateway[2], (unsigned char)gateway[3], (unsigned char)gateway[4], (unsigned char)gateway[5]); }
		if (gateway != NULL) free(gateway);

		// Attempt to figure out the interface type
		j = 0;
		if (strlen(ifr->ifr_name) > 3 && memcmp(ifr->ifr_name, "eth", 3) == 0) { j = 6; }
		//if (strlen(ifr->ifr_name) > 2 && memcmp(ifr->ifr_name, "wl", 2) == 0) { j = 6; } // TODO: Wireless
		if (j > 0) { ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"type\":\"%d\"", j); }

		// Get the hardware MAC address
		if (ioctl(sockfd, SIOCGIFHWADDR, ifr) == 0) {
			if (ifr->ifr_hwaddr.sa_family == 1) {
				ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"mac\":\"%02x%02x%02x%02x%02x%02x\"", (unsigned char)ifr->ifr_hwaddr.sa_data[0], (unsigned char)ifr->ifr_hwaddr.sa_data[1], (unsigned char)ifr->ifr_hwaddr.sa_data[2], (unsigned char)ifr->ifr_hwaddr.sa_data[3], (unsigned char)ifr->ifr_hwaddr.sa_data[4], (unsigned char)ifr->ifr_hwaddr.sa_data[5]);
			}
		}

		// Get the IP address
		if (ioctl(sockfd, SIOCGIFADDR, ifr) == 0) { ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"v4addr\":\"%s\"", inet_ntoa(((struct sockaddr_in*)(&(ifr->ifr_addr)))->sin_addr)); }

		// Get the subnet mask
		if (ioctl(sockfd, SIOCGIFNETMASK, ifr) == 0) { ptr += sprintf_s(data + ptr, maxdata - ptr, ",\"v4mask\":\"%s\"", inet_ntoa(((struct sockaddr_in*)(&(ifr->ifr_addr)))->sin_addr)); }

		ptr += sprintf_s(data + ptr, maxdata - ptr, "}");
		adapterCount++;
	}

	free(ifc.ifc_req);
	close(sockfd);
	return ptr;
#endif
}
#endif

// Returns a JSON text with system information
int MeshInfo_GetSystemInformation(char** data)
{
	int ptr = 0;

	// Setup the response
	if ((*data = (char*)malloc(65536)) == NULL) { ILIBCRITICALEXIT(254); }
	ptr += sprintf_s(*data + ptr, 65536 - ptr, "{\"netif\":[");
	ptr += info_GetLocalInterfaces(*data + ptr, 65536 - ptr);
	ptr += sprintf_s(*data + ptr, 65536 - ptr, "]}");
	if (ptr < 65535)
	{
		(*data)[ptr] = 0;
		if ((*data = realloc(*data, ptr + 1)) == NULL) { ILIBCRITICALEXIT(254); }

		return ptr;
	}
	else
	{
		free(*data);
		*data = NULL;
		return(0);
	}
}


#ifdef WIN32
#if defined(_LINKVM)
DWORD WINAPI kvm_ctrlaltdel(LPVOID Param);
#endif

int MeshInfo_PowerState(enum AgentPowerStateActions flg, int force)
{
#ifdef _MINCORE
	if (flg == 0 || flg > 5) return 0; // NOP
	switch (flg)
	{
	case POWERSTATE_SHUTDOWN: // SHUTDOWN
		InitiateSystemShutdownEx(NULL, NULL, 30, TRUE, FALSE, SHTDN_REASON_MINOR_OTHER);
		break;
	case POWERSTATE_REBOOT: // REBOOT
		InitiateSystemShutdownEx(NULL, NULL, 30, TRUE, TRUE, SHTDN_REASON_MINOR_OTHER);
		break;
	}
	return 1;
#else
	TOKEN_PRIVILEGES tp;
	BOOL fResult = 0;
	HANDLE ht;

	if (flg == POWERSTATE_NOP) return 0; // NOP
	if (flg == POWERSTATE_DISPLAYON) { SetThreadExecutionState(ES_DISPLAY_REQUIRED); SetThreadExecutionState(ES_USER_PRESENT); return 1; } // Turn on display
	if (flg == POWERSTATE_KEEPAWAKE) { SetThreadExecutionState(ES_SYSTEM_REQUIRED); return 1; }  // Keep system awake
	if (flg == POWERSTATE_BEEP) { MessageBeep(0xFFFFFFFF); return 1; }
	if (flg == POWERSTATE_CTRLALTDEL)
	{
#if defined(_LINKVM)
		ht = CreateThread(NULL, 0, kvm_ctrlaltdel, 0, 0, 0);
		if (ht != NULL) CloseHandle(ht);
		return 1;
#else
		return 0;
#endif
	}

	// Attempt to exit
	if (flg > POWERSTATE_HIBERNATE) return 0; // NOP
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ht)) return 0;
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(ht, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	if (GetLastError() != ERROR_SUCCESS) { CloseHandle(ht); return 0; }

	switch (flg)
	{
	case POWERSTATE_LOGOFF: // LOGOFF
		if (force) fResult = ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, SHTDN_REASON_FLAG_PLANNED);
		else fResult = ExitWindowsEx(EWX_LOGOFF, SHTDN_REASON_FLAG_PLANNED);
		break;
	case POWERSTATE_SHUTDOWN: // SHUTDOWN
		fResult = InitiateSystemShutdown(NULL, NULL, 30, TRUE, FALSE);
		break;
	case POWERSTATE_REBOOT: // REBOOT
		fResult = InitiateSystemShutdown(NULL, NULL, 30, TRUE, TRUE);
		break;
	case POWERSTATE_SLEEP: // SLEEP
		fResult = SetSystemPowerState(TRUE, force);
		break;
	case POWERSTATE_HIBERNATE: // HIBERNATE
		fResult = SetSystemPowerState(FALSE, force);
		break;
	}

	if (!fResult) { CloseHandle(ht); return 0; }
	tp.Privileges[0].Attributes = 0;
	AdjustTokenPrivileges(ht, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	CloseHandle(ht);

	return 1;
#endif
}

#elif defined(_VX_CPU) || defined(_FREEBSD)  // If VxWorks, we still need to implement this.

int MeshInfo_PowerState(enum AgentPowerStateActions flg, int force)
{
	// TODO
	return 0;
}

#else

int MeshInfo_PowerState(enum AgentPowerStateActions flg, int force)
{
	switch (flg)
	{
	case POWERSTATE_NOP:
	case POWERSTATE_DISPLAYON:
	case POWERSTATE_KEEPAWAKE:
	case POWERSTATE_BEEP:
	case POWERSTATE_CTRLALTDEL:
		// NO OP
		break;
	case POWERSTATE_LOGOFF: // LOGOFF
		break;
	case POWERSTATE_SHUTDOWN: // SHUTDOWN
#if defined(_ANDROID)
		reboot(RB_POWER_OFF);
#elif defined(__APPLE__)
			// TODO
#elif defined(NACL)
			//do nothing
#else
		sync();
		syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF, 0);
#endif
		return 1;
	case POWERSTATE_REBOOT: // REBOOT
#if defined(_ANDROID) || defined(__APPLE__)
		reboot(RB_AUTOBOOT);
#elif defined(NACL)
			//do nothing
#else
		sync();
		syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART, 0);
#endif
		return 1;
	case POWERSTATE_SLEEP: // SLEEP
#if defined(__APPLE__)
	{
		io_connect_t port = IOPMFindPowerManagement(MACH_PORT_NULL);
		IOPMSleepSystem(port);
		IOServiceClose(port);
	}
#endif
	break;
#ifdef LINUX_REBOOT_CMD_SW_SUSPEND
	case POWERSTATE_HIBERNATE: // HIBERNATE
#if defined(_ANDROID) || defined(__APPLE__)
			// TODO
#else
		sync();
		syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_SW_SUSPEND, 0);
#endif
		return 1;
#endif
	case POWERSTATE_VIBRATE: // VIBRATE
#if defined(ANDROID)
	{
		ai_vibrate(1000);
	}
#endif
	break;
	case POWERSTATE_FLASH: // FLASH
#if defined(ANDROID)
	{
		ai_flash(1000);
	}
#endif
	break;
	}
	return 0;
}

#endif
#endif
