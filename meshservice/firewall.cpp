/*   
Copyright 2006 - 2017 Intel Corporation

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

#if defined(WIN32) && !defined(_MINCORE)

#include <windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>

extern "C"
{

// This is the old version, we now use explicit rules for both TCP and UDP ports
int SetupWindowsFirewallOld(wchar_t* friendlyname, wchar_t* processname)
{
    BSTR fwBstr1 = NULL;
    BSTR fwBstr2 = NULL;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;
    INetFwProfile* fwProfile = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;
	int ret = 0;

	// Setup COM calls & firewall interface
    if (FAILED(CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr))) goto error;

	// Get firewall policy, profile, apps
    if (FAILED(fwMgr->get_LocalPolicy(&fwPolicy))) goto error;
	if (FAILED(fwPolicy->get_CurrentProfile(&fwProfile))) goto error;
    if (FAILED(fwProfile->get_AuthorizedApplications(&fwApps))) goto error;

	// Add an application to the Microsoft Windows XP firewall
	{
		// Create an instance of an authorized application.
		if (FAILED(CoCreateInstance(__uuidof(NetFwAuthorizedApplication), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwAuthorizedApplication), (void**)&fwApp))) goto error;

		// Set the process image file name.
		fwBstr1 = SysAllocString(processname);
		if (fwBstr1 == NULL) goto error;
		if (FAILED(fwApp->put_ProcessImageFileName(fwBstr1))) goto error;

		// Set the application friendly name.
		fwBstr2 = SysAllocString(friendlyname);
		if (SysStringLen(fwBstr2) == 0) goto error;
		if (FAILED(fwApp->put_Name(fwBstr2))) goto error;

		// Add the application to the collection.
		if (FAILED(fwApps->Add(fwApp))) goto error;
	}
	ret = 1;

error:

	// Clean up
    if (fwBstr1 != NULL) SysFreeString(fwBstr1);
    if (fwBstr2 != NULL) SysFreeString(fwBstr2);
    if (fwApp != NULL) fwApp->Release();
    if (fwApps != NULL) fwApps->Release();
    if (fwProfile != NULL) fwProfile->Release();
    if (fwPolicy != NULL) fwPolicy->Release();
    if (fwMgr != NULL) fwMgr->Release();

	return ret;
}

int SetupWindowsFirewall(wchar_t* processname)
{
    BSTR fwBstr2 = NULL;
    INetFwRule* pNetFwRule = NULL;
	INetFwRules* pNetFwRules = NULL;
	INetFwPolicy2* pNetFwPolicy2 = NULL;
	int ret = 0;

	// Convert the friendly name.
	fwBstr2 = SysAllocString(processname);
	if (SysStringLen(fwBstr2) == 0) goto error;

	// Fetch the rules
	if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_ALL, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2))) goto error;
	if (FAILED(pNetFwPolicy2->get_Rules(&pNetFwRules))) goto error;

	// Create a new rule for local P2P UDP traffic
    if (FAILED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_ALL, __uuidof(INetFwRule), (void**)&pNetFwRule))) goto error;
	if (FAILED(pNetFwRule->put_Name(L"Mesh Agent peer-to-peer (UDP)"))) goto error;															// Put the rule name
	if (FAILED(pNetFwRule->put_ApplicationName(fwBstr2))) goto error;																				// Put the application path
	if (FAILED(pNetFwRule->put_Protocol(static_cast<NET_FW_IP_PROTOCOL>(NET_FW_IP_PROTOCOL_UDP)))) goto error;										// Put the protocol (UDP)
	if (FAILED(pNetFwRule->put_LocalPorts(L"16990"))) goto error;																				// Put the ports
	if (FAILED(pNetFwRule->put_Description(L"Meshcentral agent UDP port for local peer-to-peer traffic."))) goto error;						// Put the description
	if (FAILED(pNetFwRule->put_EdgeTraversal(VARIANT_FALSE))) goto error;																			// Set edge traversal
	if (FAILED(pNetFwRule->put_Enabled(VARIANT_TRUE))) goto error;																					// Enable rule
	if (FAILED(pNetFwRules->Add(pNetFwRule))) goto error;																							// Add the new rule
	pNetFwRule->Release();
	pNetFwRule = NULL;

	// Create a new rule for STUN/WebRTC internet traffic
    if (FAILED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_ALL, __uuidof(INetFwRule), (void**)&pNetFwRule))) goto error;
	if (FAILED(pNetFwRule->put_Name(L"Mesh Agent management (UDP)"))) goto error;																// Put the rule name
	if (FAILED(pNetFwRule->put_ApplicationName(fwBstr2))) goto error;																				// Put the application path
	if (FAILED(pNetFwRule->put_Protocol(static_cast<NET_FW_IP_PROTOCOL>(NET_FW_IP_PROTOCOL_UDP)))) goto error;										// Put the protocol (UDP)
	if (FAILED(pNetFwRule->put_LocalPorts(L"16991"))) goto error;																				// Put the ports
	if (FAILED(pNetFwRule->put_Description(L"Meshcentral agent UDP port for internet WebRTC management traffic."))) goto error;				// Put the description
	if (FAILED(pNetFwRule->put_EdgeTraversal(VARIANT_TRUE))) goto error;																			// Set edge traversal
	if (FAILED(pNetFwRule->put_Enabled(VARIANT_TRUE))) goto error;																					// Enable rule
	if (FAILED(pNetFwRules->Add(pNetFwRule))) goto error;																							// Add the new rule
	pNetFwRule->Release();
	pNetFwRule = NULL;

	// Create a new rule for local P2P TCP traffic
    if (FAILED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_ALL, __uuidof(INetFwRule), (void**)&pNetFwRule))) goto error;
	if (FAILED(pNetFwRule->put_Name(L"Mesh Agent peer-to-peer (TCP)"))) goto error;															// Put the rule name
	if (FAILED(pNetFwRule->put_ApplicationName(fwBstr2))) goto error;																				// Put the application path
	if (FAILED(pNetFwRule->put_Protocol(static_cast<NET_FW_IP_PROTOCOL>(NET_FW_IP_PROTOCOL_TCP)))) goto error;										// Put the protocol (TCP)
	if (FAILED(pNetFwRule->put_LocalPorts(L"16990"))) goto error;																				// Put the ports
	if (FAILED(pNetFwRule->put_Description(L"Meshcentral agent TCP port for local peer-to-peer traffic."))) goto error;						// Put the description
	if (FAILED(pNetFwRule->put_Enabled(VARIANT_TRUE))) goto error;																					// Enable rule
	if (FAILED(pNetFwRules->Add(pNetFwRule))) goto error;																							// Add the new rule
	pNetFwRule->Release();
	pNetFwRule = NULL;

	// Create a new rule for TCP management traffic
    if (FAILED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_ALL, __uuidof(INetFwRule), (void**)&pNetFwRule))) goto error;
	if (FAILED(pNetFwRule->put_Name(L"Mesh Agent management (TCP)"))) goto error;																// Put the rule name
	if (FAILED(pNetFwRule->put_ApplicationName(fwBstr2))) goto error;																				// Put the application path
	if (FAILED(pNetFwRule->put_Protocol(static_cast<NET_FW_IP_PROTOCOL>(NET_FW_IP_PROTOCOL_TCP)))) goto error;										// Put the protocol (TCP)
	if (FAILED(pNetFwRule->put_LocalPorts(L"16991"))) goto error;																				// Put the ports
	if (FAILED(pNetFwRule->put_Description(L"Meshcentral agent TCP port for management traffic."))) goto error;								// Put the description
	if (FAILED(pNetFwRule->put_Enabled(VARIANT_TRUE))) goto error;																					// Enable rule
	if (FAILED(pNetFwRules->Add(pNetFwRule))) goto error;																							// Add the new rule
	pNetFwRule->Release();
	pNetFwRule = NULL;

	ret = 1;

error:

	// Clean up
    if (fwBstr2 != NULL) SysFreeString(fwBstr2);
    if (pNetFwRule != NULL) pNetFwRule->Release();
	if (pNetFwRules != NULL) pNetFwRules->Release();
	if (pNetFwPolicy2 != NULL) pNetFwPolicy2->Release();

	if (ret == 0) SetupWindowsFirewallOld(L"Mesh Agent background service", processname);
	return ret;
}

int ClearWindowsFirewall(wchar_t* processname)
{
	HRESULT h = 0;
    BSTR fwBstr = NULL;
	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
    INetFwProfile* fwProfile = NULL;
	INetFwRules* pNetFwRules = NULL;
	INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;
	BSTR s1 = NULL, s2 = NULL, s3 = NULL, s4 = NULL;
	int i, ret = 0;

	// Convert the friendly name.
	if ((s1 = SysAllocString(L"Mesh Agent peer-to-peer (UDP)")) == NULL) goto error;
	if ((s2 = SysAllocString(L"Mesh Agent management (UDP)")) == NULL) goto error;
	if ((s3 = SysAllocString(L"Mesh Agent peer-to-peer (TCP)")) == NULL) goto error;
	if ((s4 = SysAllocString(L"Mesh Agent management (TCP)")) == NULL) goto error;

	// Setup firewall interface
    if (FAILED(CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr))) goto error;

	// Get firewall policy, profile, apps
    if (FAILED(fwMgr->get_LocalPolicy(&fwPolicy))) goto error;
	if (FAILED(fwPolicy->get_CurrentProfile(&fwProfile))) goto error;
    if (FAILED(fwProfile->get_AuthorizedApplications(&fwApps))) goto error;

    // Remove the firewall rules
    fwBstr = SysAllocString(processname);
    if (fwBstr == NULL) goto error;
	for (i = 0; i < 4; i++) { if (FAILED(fwApps->Remove(fwBstr))) goto error; }

	// Fetch the rules & remove our rules
	if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_ALL, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2))) goto error;
	if (FAILED(pNetFwPolicy2->get_Rules(&pNetFwRules))) goto error;
	for (i = 0; i < 4; i++) { h = pNetFwRules->Remove(s1); h = pNetFwRules->Remove(s2); h = pNetFwRules->Remove(s3); h = pNetFwRules->Remove(s4); }

	ret = 1;

error:

    // Cleanup
    if (fwBstr != NULL) SysFreeString(fwBstr);
    if (fwApps != NULL) fwApps->Release();
	if (fwProfile != NULL) fwProfile->Release();
    if (fwPolicy != NULL) fwPolicy->Release();
	if (fwMgr != NULL) fwMgr->Release();
	if (pNetFwRules != NULL) pNetFwRules->Release();
	if (pNetFwPolicy2 != NULL) pNetFwPolicy2->Release();
	if (s1 != NULL) SysFreeString(s1);
	if (s2 != NULL) SysFreeString(s2);
	if (s3 != NULL) SysFreeString(s3);
	if (s4 != NULL) SysFreeString(s4);

    return ret;
}


}

#endif