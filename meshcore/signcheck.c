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
#endif

#ifdef WIN32
#include <windows.h>
#include <Softpub.h>
#include <wchar.h>
#include <Psapi.h>
#endif

#include "MeshDefines.h"
#include "signcheck.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibCrypto.h"


// Trusted mesh agent update certificate hashs
const int TrustedCertificatesCount = 2;
const char TrustedCertificates[2][32] = {
	{ 0xde, 0x6e, 0x97, 0x6d, 0x14, 0xe9, 0x5e, 0xd6, 0x71, 0xe6, 0xd8, 0x14, 0x36, 0xd2, 0x66, 0x43, 0x03, 0x02, 0x8f, 0x5c, 0xf3, 0x63, 0x11, 0x78, 0x95, 0xc1, 0x01, 0xd0, 0xba, 0x22, 0x02, 0x23 },
	{ 0xd1, 0x7a, 0xae, 0x40, 0x9a, 0xef, 0x05, 0xf6, 0x4a, 0x6e, 0x18, 0x55, 0x97, 0xb5, 0x97, 0xd8, 0xb7, 0x8d, 0xb7, 0xae, 0x14, 0x47, 0xe3, 0xfb, 0xa1, 0x81, 0x08, 0xcf, 0x11, 0xcf, 0x67, 0x3c }
};


//! Check the file signature of an executable
/*!
\param filename File path to executable to verify
\param upgrade 1 = 'filename' expected to be a higher version. \n 2 = 'filename' is expected to be the same version
\return 0 = FAIL \n 1 = SUCCESS
*/
int signcheck_verifysign(char* filename, int upgrade)
{
#if defined(WIN32) && !defined(_MINCORE)
	int i, ver = 0, agentid = 0, found = 0;
	size_t len = 0;
	WCHAR str[_MAX_PATH];
	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO sWintrustFileInfo;
	WINTRUST_DATA      sWintrustData;
	char hash[32];
	CRYPT_PROVIDER_DATA const *psProvData = NULL;
	CRYPT_PROVIDER_SGNR *psProvSigner = NULL;
	CRYPT_PROVIDER_CERT *psProvCert = NULL;

	// Setup and check the executable signature hash & certificate
	memset((void*)&sWintrustFileInfo, 0x00, sizeof(WINTRUST_FILE_INFO));
	memset((void*)&sWintrustData, 0x00, sizeof(WINTRUST_DATA));
	mbstowcs_s(&len, str, _MAX_PATH, filename, _MAX_PATH);

	sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	sWintrustFileInfo.pcwszFilePath = str;
	sWintrustFileInfo.hFile = NULL;
	sWintrustData.cbStruct = sizeof(WINTRUST_DATA);
	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	sWintrustData.dwUnionChoice = WTD_CHOICE_FILE;
	sWintrustData.pFile = &sWintrustFileInfo;
	sWintrustData.dwStateAction = WTD_STATEACTION_VERIFY; // Allocates memory that must be cleared
	sWintrustData.dwProvFlags = WTD_HASH_ONLY_FLAG;

	if (WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData) == 0)
	{
		if ((psProvData = WTHelperProvDataFromStateData(sWintrustData.hWVTStateData)) != 0)
		{
			if ((psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0)) != 0)
			{
				if ((psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0)) != 0)
				{
					util_sha256((char*)(psProvCert->pCert->pbCertEncoded), psProvCert->pCert->cbCertEncoded, hash);
					for (i = 0; (int)i < TrustedCertificatesCount; i++) if (memcmp(TrustedCertificates[i], hash, 32) == 0) found = 1;
				}
			}
		}
	}

	// Cleanup
	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);
	if (found == 0) return 0; // Problem, exit now

							  // Get the version number of the executable
	if (GetFileVersionInfo(filename, 0, sizeof(ILibScratchPad2), ILibScratchPad2))
	{
		VS_FIXEDFILEINFO *pFileInfo;
		int buflen;

		if (VerQueryValueA(ILibScratchPad2, "\\", (LPVOID *)&pFileInfo, (PUINT)&buflen))
		{
			ver += HIWORD(pFileInfo->dwFileVersionMS) * 10000;
			ver += LOWORD(pFileInfo->dwFileVersionMS) * 100;
			ver += HIWORD(pFileInfo->dwFileVersionLS);
#ifdef _WIN64
			agentid = LOWORD(pFileInfo->dwFileVersionLS) + 1;
#else
			agentid = LOWORD(pFileInfo->dwFileVersionLS);
#endif
		}
	}

	// Compare architecture
	// Setup the AgentID
	if (agentid != MESH_AGENTID) { ILIBMESSAGE("BAD-ARCH-CHECK"); return 0; } // TODO: Replace AGENTID_WIN32_SERVICE with real value

	// Compare version information
	if (upgrade) return (ver >= MESH_AGENT_VERSION ? 1 : 0);	// Debug: upgrades should normally be stricly better versions.
	return (ver == MESH_AGENT_VERSION ? 1 : 0);
#else
	FILE *pFile = NULL;
	size_t totallen = 0;
	size_t len = 0;
	int endblock[4];
	char* signatureblock = NULL;
	int signatureblocklen = 0;
	SHA256_CTX c;
	char *buf = NULL;
	char *hashs = NULL;
	int hashslen;
	char totalfilehash[32];
	struct util_cert cert;
	size_t i = 0;
	int j = 0;
	char* certbuf = NULL;
	int certbuflen = 0;
	int found = 0;
	char certhash[32];
	int agentid = 0;
	int ver = 0;

	if (filename == NULL) return 0;
	cert.pkey = NULL;
	cert.x509 = NULL;

#ifdef WIN32 
	fopen_s(&pFile, filename, "rb");
#else
	pFile = fopen(filename, "rb");
#endif
	if (pFile == NULL) goto error;

	// Get the file total length
	if (fseek(pFile, 0, SEEK_END)) goto error;
	if ((totallen = ftell(pFile)) < 16) goto error;

	// Seek 16 bytes before the end of the file and read the end block
	if (fseek(pFile, -16, SEEK_END)) goto error;
	if (fread(&endblock, 1, 16, pFile) != 16) goto error;
	endblock[0] = ntohl(endblock[0]);
	endblock[1] = ntohl(endblock[1]);
	endblock[2] = ntohl(endblock[2]);
	endblock[3] = ntohl(endblock[3]);
	if (endblock[1] != 1 || endblock[2] != 0x11BB22DD || endblock[3] != 0x21CB32ED || totallen <= (size_t)(endblock[0] + 16)) goto error;

	// Seek back and get the signature block
	if (fseek(pFile, -(endblock[0] + 16), SEEK_END)) goto error;
	if ((signatureblock = (char*)malloc(endblock[0])) == NULL) goto error;
	signatureblocklen = fread(signatureblock, 1, endblock[0], pFile);

	// Decode and verify the signature block
	hashslen = util_verify(signatureblock, signatureblocklen, &cert, &hashs);
	if (hashslen != 72) goto error;

	// Set the file version and architecture numbers
	ver = ntohl(((int*)hashs)[16]);
	agentid = ntohl(((int*)hashs)[17]);

	// Compare architecture
	if (agentid != g_agentid) { ILIBMESSAGE("BAD-ARCH-CHECK"); fclose(pFile); return 0; }

	// Seek to the start and hash the entire file except for the signature stuff at the end
	SHA256_Init(&c);
	if (fseek(pFile, 0, SEEK_SET)) goto error;
	i = totallen - (size_t)(endblock[0] + 16);
	if ((buf = (char*)malloc(4096)) == NULL) goto error;
	while ((i > 0) && (len = fread(buf, 1, i > 4096 ? 4096 : i, pFile)) > 0) { SHA256_Update(&c, buf, len); i -= len; }
	free(buf);
	if (i != 0) goto error;
	SHA256_Final((unsigned char*)totalfilehash, &c);

	// Check that the file hash is the same as the second hash in the hash block
	if (memcmp(hashs + 32, totalfilehash, 32) != 0) goto error;

	// Get the public certificate block
	certbuflen = util_to_cer(cert, &certbuf);

	// Compute the certificate key hash
	util_sha256(certbuf, certbuflen, certhash);

	// Check if the certificate is trusted
	for (j = 0; j < TrustedCertificatesCount; j++) if (memcmp(TrustedCertificates[j], certhash, 32) == 0) found = 1;

error:
	// Clean up
	util_freecert(&cert);
	if (certbuf != NULL) free(certbuf);
	if (hashs != NULL) free(hashs);
	if (pFile != NULL) fclose(pFile);
	if (signatureblock != NULL) free(signatureblock);
	if (found != 1 || ver == 0 || agentid == 0) return 0;

	// Compare version information
	if (upgrade) return (ver >= MESH_AGENT_VERSION ? 1 : 0);	// Debug: upgrades should normally be stricly better versions.
	return (ver == MESH_AGENT_VERSION ? 1 : 0);
#endif
}
