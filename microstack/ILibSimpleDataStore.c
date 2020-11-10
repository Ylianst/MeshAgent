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

#include "ILibSimpleDataStore.h"
#include "ILibCrypto.h"
#ifndef WIN32
#include <sys/file.h>
#include <unistd.h>
#else
#include <io.h>
#include <fcntl.h>
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


#define SHA384HASHSIZE 48

#ifdef _WIN64
	#define ILibSimpleDataStore_GetPosition(filePtr) _ftelli64(filePtr)
	#define ILibSimpleDataStore_SeekPosition(filePtr, position, seekMode) _fseeki64(filePtr, position, seekMode)
#else
	#define ILibSimpleDataStore_GetPosition(filePtr) ftell(filePtr)
	#define ILibSimpleDataStore_SeekPosition(filePtr, position, seekMode) fseek(filePtr, (long)position, seekMode)
#endif

typedef struct ILibSimpleDataStore_Root
{
	FILE* dataFile;
	char* filePath;
	char scratchPad[4096];
	ILibHashtable keyTable; // keys --> ILibSimpleDataStore_TableEntry
	ILibHashtable cacheTable;
	uint64_t fileSize;
	uint64_t dirtySize;
	uint64_t minimumDirtySize;
	uint64_t warningSize;
	ILibSimpleDataStore_SizeWarningHandler warningSink;
	void* warningSinkUser;
	int error;
	ILibSimpleDataStore_WriteErrorHandler ErrorHandler;
	void *ErrorHandlerUser;
} ILibSimpleDataStore_Root;

/* File Format                 
------------------------------------------
 4 Bytes	- Node size
 4 Bytes	- Key length
 4 Bytes	- Value length
48 Bytes	- SHA384 hash check value
Variable	- Key
Variable	- Value
------------------------------------------ */

#define ILibSimpleDataStore_RecordHeader_ValueOffset(h) (((uint64_t*)(((char*)h) - sizeof(uint64_t)))[0])

#pragma pack(push, 1)
typedef struct ILibSimpleDataStore_RecordHeader_NG
{
	int nodeSize;
	int keyLen;
	int valueLength;
	char hash[SHA384HASHSIZE];
	char key[];
} ILibSimpleDataStore_RecordHeader_NG;
typedef struct ILibSimpleDataStore_RecordHeader_32
{
	int nodeSize;
	int keyLen;
	int valueLength;
	char hash[SHA384HASHSIZE];
	char reserved[4];
	char key[];
} ILibSimpleDataStore_RecordHeader_32;
typedef struct ILibSimpleDataStore_RecordHeader_64
{
	int nodeSize;
	int keyLen;
	int valueLength;
	char hash[SHA384HASHSIZE];
	char reserved[12];
	char key[];
} ILibSimpleDataStore_RecordHeader_64;
#pragma pack(pop)


typedef struct ILibSimpleDataStore_TableEntry
{
	int valueLength;
	char valueHash[SHA384HASHSIZE];
	uint64_t valueOffset;
} ILibSimpleDataStore_TableEntry;
typedef struct ILibSimpleDataStore_CacheEntry
{
	char valueHash[SHA384HASHSIZE];
	int valueLength;
	char value[];
}ILibSimpleDataStore_CacheEntry;

const int ILibMemory_SimpleDataStore_CONTAINERSIZE = sizeof(ILibSimpleDataStore_Root);
void ILibSimpleDataStore_RebuildKeyTable(ILibSimpleDataStore_Root *root);
extern int ILibInflate(char *buffer, size_t bufferLen, char *decompressed, size_t *decompressedLen, uint32_t crc);
extern int ILibDeflate(char *buffer, size_t bufferLen, char *compressed, size_t *compressedLen, uint32_t *crc);
extern uint32_t crc32c(uint32_t crci, const unsigned char *buf, uint32_t len);

// Perform a SHA384 hash of some data
void ILibSimpleDataStore_SHA384(char *data, size_t datalen, char* result) { util_sha384(data, datalen, result); }

void ILibSimpleDataStore_CachedEx(ILibSimpleDataStore dataStore, char* key, size_t keyLen, char* value, size_t valueLen, char *vhash)
{
	if (keyLen > INT32_MAX || valueLen > INT32_MAX) { return; }

	if (vhash != NULL)
	{
		// This is a compresed entry
		char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
		memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
		((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)key, (uint32_t)keyLen);
		key = tmpkey;
		keyLen = (int)ILibMemory_Size(key);
	}
	else
	{
		if (valueLen > 2)
		{
			if (value[0] == '"' && value[valueLen - 1] == '"')
			{
				value = value + 1;
				valueLen -= 2;
			}
			if (valueLen > 2 && strncmp(value, "0x", 2) == 0 && valueLen < 1024)
			{
				char *vtmp = ILibMemory_AllocateA((valueLen - 2) / 2);
				util_hexToBuf(value + 2, valueLen - 2, vtmp);
				value = vtmp;
				valueLen = (int)ILibMemory_AllocateA_Size(value);
			}
		}
	}
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root->cacheTable == NULL) { root->cacheTable = ILibHashtable_Create(); }
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)ILibMemory_Allocate((int)(sizeof(ILibSimpleDataStore_CacheEntry) + valueLen), 0, NULL, NULL);
	entry->valueLength = (int)valueLen; // No loss of data, becuase it's capped to INT32_MAX
	if (valueLen > 0) { memcpy_s(entry->value, valueLen, value, valueLen); }
	if (vhash != NULL)
	{
		memcpy_s(entry->valueHash, sizeof(entry->valueHash), vhash, SHA384HASHSIZE);
	}
	else
	{
		ILibSimpleDataStore_SHA384(value, valueLen, entry->valueHash);   
	}
	
	ILibHashtable_Put(root->cacheTable, NULL, key, (int)keyLen, entry); // No loss of data, becuase capped at INT32_MAX
	if (vhash != NULL) { ILibMemory_Free(key); }
}

typedef struct ILibSimpleDateStore_JSONCache
{
	char *buffer;
	int offset;
	int bufferLen;
}ILibSimpleDateStore_JSONCache;

void ILibSimpleDataStore_Cached_GetJSON_count(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDateStore_JSONCache *cache = (ILibSimpleDateStore_JSONCache*)user;
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)Data;
	
	if (cache->bufferLen == 0) 
	{
		cache->bufferLen = 3; 
	}
	else
	{
		++cache->bufferLen;
	}

	cache->bufferLen += (Key2Len + 3);
	cache->bufferLen += (entry->valueLength + 2);
}
void ILibSimpleDataStore_Cached_GetJSONEx_count(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDateStore_JSONCache *cache = (ILibSimpleDateStore_JSONCache*)user;
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)Data;

	if (cache->bufferLen == 0)
	{
		cache->bufferLen = 3;
	}
	else
	{
		++cache->bufferLen;
	}

	cache->bufferLen += (Key2Len + 5);
	cache->bufferLen += (entry->valueLength + 4);
}
void ILibSimpleDataStore_Cached_GetJSON_write(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDateStore_JSONCache *cache = (ILibSimpleDateStore_JSONCache*)user;
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)Data;
	char *tmpbuffer = NULL;
	size_t tmpbufferLen = 0;

	char* value = entry->value;
	size_t valueLen = entry->valueLength;

	// check if this is a compressed record
	if (Key2Len > sizeof(uint32_t))
	{
		if (((uint32_t*)(Key2 + Key2Len - sizeof(uint32_t)))[0] == crc32c(0, (unsigned char*)Key2, Key2Len - sizeof(uint32_t)))
		{
			Key2Len -= sizeof(uint32_t);
			ILibInflate(entry->value, entry->valueLength, NULL, &tmpbufferLen, 0);
			if (tmpbufferLen > 0)
			{
				tmpbuffer = (char*)ILibMemory_SmartAllocate(tmpbufferLen);
				ILibInflate(entry->value, entry->valueLength, tmpbuffer, &tmpbufferLen, 0);
				value = tmpbuffer;
				valueLen = tmpbufferLen;
			}
		}
	}



	if (cache->offset != 1) { cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, ","); }

	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "\"");
	memcpy_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, Key2, Key2Len); cache->offset += Key2Len;
	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "\":\"");
	memcpy_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, value, (int)valueLen); cache->offset += (int)valueLen;
	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "\"");

	if (tmpbuffer != NULL) { ILibMemory_Free(tmpbuffer); }
}
void ILibSimpleDataStore_Cached_GetJSONEx_write(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDateStore_JSONCache *cache = (ILibSimpleDateStore_JSONCache*)user;
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)Data;

	char *tmpbuffer = NULL;
	size_t tmpbufferLen = 0;

	char* value = entry->value;
	size_t valueLen = entry->valueLength;

	// check if this is a compressed record
	if (Key2Len > sizeof(uint32_t))
	{
		if (((uint32_t*)(Key2 + Key2Len - sizeof(uint32_t)))[0] == crc32c(0, (unsigned char*)Key2, Key2Len - sizeof(uint32_t)))
		{
			Key2Len -= sizeof(uint32_t);
			ILibInflate(entry->value, entry->valueLength, NULL, &tmpbufferLen, 0);
			if (tmpbufferLen > 0)
			{
				tmpbuffer = (char*)ILibMemory_SmartAllocate(tmpbufferLen);
				ILibInflate(entry->value, entry->valueLength, tmpbuffer, &tmpbufferLen, 0);
				value = tmpbuffer;
				valueLen = tmpbufferLen;
			}
		}
	}


	if (cache->offset != 1) { cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, ","); }

	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "\"--");
	memcpy_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, Key2, Key2Len); cache->offset += Key2Len;
	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "=\\\"");
	memcpy_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, value, (int)valueLen); cache->offset += (int)valueLen;
	cache->offset += sprintf_s(cache->buffer + cache->offset, cache->bufferLen - cache->offset, "\\\"\"");
}

int ILibSimpleDataStore_Cached_GetJSONEx(ILibSimpleDataStore dataStore, char *buffer, int bufferLen)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root->cacheTable == NULL)
	{
		if (bufferLen < 3)
		{
			return(3);
		}
		else
		{
			return(sprintf_s(buffer, (size_t)bufferLen, "[]"));
		}
	}
	ILibSimpleDateStore_JSONCache cache;
	cache.buffer = NULL;
	cache.offset = 0;
	cache.bufferLen = 0;
	ILibHashtable_Enumerate(root->cacheTable, ILibSimpleDataStore_Cached_GetJSONEx_count, &cache);

	if (buffer == NULL || bufferLen < cache.bufferLen) { return(cache.bufferLen); }
	cache.buffer = buffer;
	cache.offset = sprintf_s(buffer, bufferLen, "[");
	cache.bufferLen = bufferLen;

	ILibHashtable_Enumerate(root->cacheTable, ILibSimpleDataStore_Cached_GetJSONEx_write, &cache);
	cache.offset += sprintf_s(cache.buffer + cache.offset, cache.bufferLen - cache.offset, "]");
	return(cache.offset);
}
int ILibSimpleDataStore_Cached_GetJSON(ILibSimpleDataStore dataStore, char *buffer, int bufferLen)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root->cacheTable == NULL)
	{
		if (bufferLen < 3)
		{
			return(3);
		}
		else
		{
			return(sprintf_s(buffer, (size_t)bufferLen, "{}"));
		}
	}
	ILibSimpleDateStore_JSONCache cache;
	cache.buffer = NULL;
	cache.offset = 0;
	cache.bufferLen = 0;
	ILibHashtable_Enumerate(root->cacheTable, ILibSimpleDataStore_Cached_GetJSON_count, &cache);

	if (buffer == NULL || bufferLen < cache.bufferLen) { return(cache.bufferLen); }
	cache.buffer = buffer;
	cache.offset = sprintf_s(buffer, bufferLen, "{");
	cache.bufferLen = bufferLen;

	ILibHashtable_Enumerate(root->cacheTable, ILibSimpleDataStore_Cached_GetJSON_write, &cache);
	cache.offset += sprintf_s(cache.buffer + cache.offset, cache.bufferLen - cache.offset, "}");
	return(cache.offset);
}

// Write a key/value pair to file, the hash is already calculated
uint64_t ILibSimpleDataStore_WriteRecord(FILE *f, char* key, int keyLen, char* value, int valueLen, char* hash)
{
	char headerBytes[sizeof(ILibSimpleDataStore_RecordHeader_NG)];
	ILibSimpleDataStore_RecordHeader_NG *header = (ILibSimpleDataStore_RecordHeader_NG*)headerBytes;
	uint64_t offset;
	uint64_t curlen;
	uint64_t written = 0;

	fseek(f, 0, SEEK_END);
	curlen = ILibSimpleDataStore_GetPosition(f);

	header->nodeSize = htonl(sizeof(ILibSimpleDataStore_RecordHeader_NG) + keyLen + valueLen);
	header->keyLen = htonl(keyLen);
	header->valueLength = htonl(valueLen);
	if (hash != NULL) { memcpy_s(header->hash, sizeof(header->hash), hash, SHA384HASHSIZE); } else { memset(header->hash, 0, SHA384HASHSIZE); }

	written += (uint64_t)fwrite(headerBytes, 1, sizeof(ILibSimpleDataStore_RecordHeader_NG), f);
	written += (uint64_t)fwrite(key, 1, keyLen, f);
	offset = ILibSimpleDataStore_GetPosition(f);
	if (value != NULL) { written += (uint64_t)fwrite(value, 1, valueLen, f); }
	fflush(f);

	if (written < (sizeof(ILibSimpleDataStore_RecordHeader_NG) + keyLen + (value!=NULL?valueLen:0)))
	{
		//
		// Unable to write all data, probably because insufficient disc space,
		// so we're going to undo the last write, so we don't corrupt the db,
		//
#ifdef WIN32
		LARGE_INTEGER i;
		i.QuadPart = curlen;
		SetFilePointerEx((HANDLE)_get_osfhandle(_fileno(f)), i, NULL, FILE_BEGIN);
		SetEndOfFile((HANDLE)_get_osfhandle(_fileno(f)));
#else
		ftruncate(fileno(f), curlen);
#endif
		return(0);
	}
	return offset;
}

// Read the next record in the file
ILibSimpleDataStore_RecordHeader_NG* ILibSimpleDataStore_ReadNextRecord(ILibSimpleDataStore_Root *root, int legacySize)
{
	SHA512_CTX c;
	char data[4096];
	char result[SHA384HASHSIZE];
	int i, bytesLeft;

	ILibSimpleDataStore_RecordHeader_NG *node;
	size_t nodeSize;

	if (root == NULL) return NULL;
	node = (ILibSimpleDataStore_RecordHeader_NG*)(root->scratchPad + sizeof(uint64_t));

	// If the current position is the end of the file, exit now.
	if (ILibSimpleDataStore_GetPosition(root->dataFile) == root->fileSize) return NULL;

	// Read sizeof(ILibSimpleDataStore_RecordNode) bytes to get record Size
	switch (legacySize)
	{
		default:
			nodeSize = sizeof(ILibSimpleDataStore_RecordHeader_NG);
			break;
		case 32:
			nodeSize = sizeof(ILibSimpleDataStore_RecordHeader_32);
			break;
		case 64:
			nodeSize = sizeof(ILibSimpleDataStore_RecordHeader_64);
			break;
	}

	i = (int)fread((void*)node, 1, nodeSize, root->dataFile);
	if (i < (int)nodeSize) return NULL;


	// Correct the struct, valueHash stays the same
	node->nodeSize = (int)ntohl(node->nodeSize);
	node->keyLen = (int)ntohl(node->keyLen);
	node->valueLength = (int)ntohl(node->valueLength);
	ILibSimpleDataStore_RecordHeader_ValueOffset(node) = (uint64_t)((uint64_t)ILibSimpleDataStore_GetPosition(root->dataFile) + (uint64_t)node->keyLen);

	if (node->keyLen > (int)((sizeof(ILibScratchPad) - nodeSize - sizeof(uint64_t))))
	{
		// Invalid record
		return(NULL);
	}

	// Read the key name
	i = (int)fread((char*)node + nodeSize, 1, node->keyLen, root->dataFile);
	if (i != node->keyLen) return NULL; // Reading Key Failed

	// Validate Data, in 4k chunks at a time
	bytesLeft = node->valueLength;

	// Hash SHA384 the data
	SHA384_Init(&c);
	while (bytesLeft > 0)
	{
		i = (int)fread(data, 1, bytesLeft > 4096 ? 4096 : bytesLeft, root->dataFile);
		if (i <= 0) { bytesLeft = 0; break; }
		SHA384_Update(&c, data, i);
		bytesLeft -= i;
	}
	SHA384_Final((unsigned char*)result, &c);
	if (node->valueLength > 0)
	{
		// Check the hash
		if (memcmp(node->hash, result, SHA384HASHSIZE) == 0) { return node; } // Data is correct

		// Before we assume this is a bad hash check, we need to verify it's not a compressed node
		if (node->keyLen > sizeof(uint32_t))
		{
			if (crc32c(0, (unsigned char*)node->key, node->keyLen - sizeof(uint32_t)) == ((uint32_t*)(node->key + node->keyLen - sizeof(uint32_t)))[0])
			{
				return(node);
			}
		}

		return NULL; // Data is corrupt
	}
	return node;
}

// Free resources associated with each table entry
void ILibSimpleDataStore_TableClear_Sink(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(Key1);
	UNREFERENCED_PARAMETER(Key2);
	UNREFERENCED_PARAMETER(Key2Len);
	UNREFERENCED_PARAMETER(user);

	free(Data);
}

// Rebuild the in-memory key to record table, done when starting up the data store
void ILibSimpleDataStore_RebuildKeyTable(ILibSimpleDataStore_Root *root)
{
	ILibSimpleDataStore_RecordHeader_NG *node = NULL;
	ILibSimpleDataStore_TableEntry *entry;
	int count;

	if (root == NULL) return;

	ILibHashtable_ClearEx(root->keyTable, ILibSimpleDataStore_TableClear_Sink, root); // Wipe the key table, we will rebulit it
	fseek(root->dataFile, 0, SEEK_SET); // See the start of the file
	root->fileSize = -1; // Indicate we can't write to the data store


	// First, try NG Format
	count = 0;
	while ((node = ILibSimpleDataStore_ReadNextRecord(root, 0)) != NULL)
	{
		// Get the entry from the memory table
		entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, node->key, node->keyLen);
		if (node->valueLength > 0)
		{
			// If the value is not empty, we need to create/overwrite this value in memory
			if (entry == NULL) 
			{
				// Create new entry in table
				++count;  
				entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL);
			}
			else
			{
				// Entry already exists in table
				root->dirtySize += entry->valueLength;
			}
			memcpy_s(entry->valueHash, sizeof(entry->valueHash), node->hash, SHA384HASHSIZE);
			entry->valueLength = node->valueLength;
			entry->valueOffset = ILibSimpleDataStore_RecordHeader_ValueOffset(node);
			ILibHashtable_Put(root->keyTable, NULL, node->key, node->keyLen, entry);
		}
		else if (entry != NULL)
		{
			// If value is empty, remove the in-memory entry.
			root->dirtySize += entry->valueLength;
			--count;
			ILibHashtable_Remove(root->keyTable, NULL, node->key, node->keyLen);
			free(entry);
		}
	}
	
	if (count == 0)
	{
		ILibHashtable_ClearEx(root->keyTable, ILibSimpleDataStore_TableClear_Sink, root); // Wipe the key table, we will rebulit it
		fseek(root->dataFile, 0, SEEK_SET); // See the start of the file
		root->fileSize = -1; // Indicate we can't write to the data store

		// Check if this is Legacy32 Format
		count = 0;
		while ((node = ILibSimpleDataStore_ReadNextRecord(root, 32)) != NULL)
		{
			// Get the entry from the memory table
			entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_32*)node)->key, node->keyLen);
			if (node->valueLength > 0)
			{
				// If the value is not empty, we need to create/overwrite this value in memory
				if (entry == NULL) { ++count;  entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL); }
				memcpy_s(entry->valueHash, sizeof(entry->valueHash), node->hash, SHA384HASHSIZE);
				entry->valueLength = node->valueLength;
				entry->valueOffset = ILibSimpleDataStore_RecordHeader_ValueOffset(node);
				ILibHashtable_Put(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_32*)node)->key, node->keyLen, entry);
			}
			else if (entry != NULL)
			{
				// If value is empty, remove the in-memory entry.
				--count;
				ILibHashtable_Remove(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_32*)node)->key, node->keyLen);
				free(entry);
			}
		}

		if (count == 0)
		{
			// Check if this is Legacy64 Format
			ILibHashtable_ClearEx(root->keyTable, ILibSimpleDataStore_TableClear_Sink, root); // Wipe the key table, we will rebulit it
			fseek(root->dataFile, 0, SEEK_SET); // See the start of the file
			root->fileSize = -1; // Indicate we can't write to the data store

			while ((node = ILibSimpleDataStore_ReadNextRecord(root, 64)) != NULL)
			{
				// Get the entry from the memory table
				entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_64*)node)->key, node->keyLen);
				if (node->valueLength > 0)
				{
					// If the value is not empty, we need to create/overwrite this value in memory
					if (entry == NULL) { ++count;  entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL); }
					memcpy_s(entry->valueHash, sizeof(entry->valueHash), node->hash, SHA384HASHSIZE);
					entry->valueLength = node->valueLength;
					entry->valueOffset = ILibSimpleDataStore_RecordHeader_ValueOffset(node);
					ILibHashtable_Put(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_64*)node)->key, node->keyLen, entry);
				}
				else if (entry != NULL)
				{
					// If value is empty, remove the in-memory entry.
					--count;
					ILibHashtable_Remove(root->keyTable, NULL, ((ILibSimpleDataStore_RecordHeader_64*)node)->key, node->keyLen);
					free(entry);
				}
			}
		}

		// Set the size of the entire data store file, and call 'Compact', to convert the db to NG format
		root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile);
		ILibSimpleDataStore_Compact((ILibSimpleDataStore)root);
	}
	else
	{
		// No need to convert db format, because we're already NG format
		root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile);
	}
}

// Open the data store file
FILE* ILibSimpleDataStore_OpenFileEx2(char* filePath, int forceTruncateIfNonZero, int readonly)
{
	FILE* f = NULL;

#ifdef WIN32
	if (readonly == 0)
	{
		HANDLE h = NULL;
		if (forceTruncateIfNonZero != 0)
		{
			h = CreateFileW(ILibUTF8ToWide(filePath, -1), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				h = CreateFileW(ILibUTF8ToWide(filePath, -1), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			}
		}
		else
		{
			h = CreateFileW(ILibUTF8ToWide(filePath, -1), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				h = CreateFileW(ILibUTF8ToWide(filePath, -1), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			}
		}
		int fd = _open_osfhandle((intptr_t)h, _O_RDWR);
		if (fd == -1) { CloseHandle(h); return(NULL); }
		f = _fdopen(fd, "wb+N");
		if (f == NULL) { CloseHandle(h); return(NULL); }
	}
	else
	{
		HANDLE h = CreateFileW(ILibUTF8ToWide(filePath, -1), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE) { return(NULL); }
		int fd = _open_osfhandle((intptr_t)h, _O_RDONLY);
		if (fd == -1) { CloseHandle(h); return(NULL); }
		f = _fdopen(fd, "rb");
		if (f == NULL) { CloseHandle(h); return(NULL); }
	}
#else
	char *flag = readonly == 0 ? "rb+": "rb";

	if (forceTruncateIfNonZero != 0 || (f = fopen(filePath, flag)) == NULL)
	{
		f = fopen(filePath, "wb+");
	}
	if (f == NULL) { return NULL; } // If we failed to open the file, stop now.
	if (readonly == 0 && flock(fileno(f), LOCK_EX | LOCK_NB) != 0) { fclose(f); return NULL; } // Request exclusive lock on this file, no blocking.
#endif

	return f;
}
#define ILibSimpleDataStore_OpenFile(filePath) ILibSimpleDataStore_OpenFileEx2(filePath, 0, 0)
#define ILibSimpleDataStore_OpenFileEx(filePath, forceTruncate) ILibSimpleDataStore_OpenFileEx2(filePath, forceTruncate, 0)
int ILibSimpleDataStore_Exists(char *filePath)
{
#ifdef WIN32
	return(_waccess(ILibUTF8ToWide(filePath, -1), 0) == 0 ? 1 : 0);
#else
	return(access(filePath, 0) == 0 ? 1 : 0);
#endif
}
// Open the data store file. Optionally allocate spare user memory
__EXPORT_TYPE ILibSimpleDataStore ILibSimpleDataStore_CreateEx2(char* filePath, int userExtraMemorySize, int readonly)
{
	ILibSimpleDataStore_Root* retVal = (ILibSimpleDataStore_Root*)ILibMemory_Allocate(ILibMemory_SimpleDataStore_CONTAINERSIZE, userExtraMemorySize, NULL, NULL);
	
	if (filePath != NULL)
	{
		retVal->filePath = ILibString_Copy(filePath, strnlen_s(filePath, ILibSimpleDataStore_MaxFilePath));
		retVal->dataFile = ILibSimpleDataStore_OpenFileEx2(retVal->filePath, 0, readonly);

		if (retVal->dataFile == NULL)
		{
			free(retVal->filePath);
			free(retVal);
			return NULL;
		}
	}

	retVal->keyTable = ILibHashtable_Create();
	if (retVal->dataFile != NULL) { ILibSimpleDataStore_RebuildKeyTable(retVal); }
	return retVal;
}
void ILibSimpleDataStore_ReOpenReadOnly(ILibSimpleDataStore dataStore, char* filePath)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;

	if (root->dataFile != NULL)
	{
#ifdef _POSIX
		flock(fileno(root->dataFile), LOCK_UN);
#endif
		fclose(root->dataFile);
	}
	else
	{
		root->filePath = ILibString_Copy(filePath, strnlen_s(filePath, ILibSimpleDataStore_MaxFilePath));
	}
	root->dataFile = ILibSimpleDataStore_OpenFileEx2(root->filePath, 0, 1);
	if (root->dataFile != NULL) { ILibSimpleDataStore_RebuildKeyTable(root); }
}
void ILibSimpleDataStore_CacheClear_Sink(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	if (Data != NULL) { free(Data); }

	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(Key1);
	UNREFERENCED_PARAMETER(Key2);
	UNREFERENCED_PARAMETER(Key2Len);
	UNREFERENCED_PARAMETER(user);
}

// Close the data store file
__EXPORT_TYPE void ILibSimpleDataStore_Close(ILibSimpleDataStore dataStore)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;

	if (root == NULL) return;
	ILibHashtable_DestroyEx(root->keyTable, ILibSimpleDataStore_TableClear_Sink, root);
	if (root->cacheTable != NULL) { ILibHashtable_DestroyEx(root->cacheTable, ILibSimpleDataStore_CacheClear_Sink, NULL); }

	if (root->filePath != NULL)
	{
		free(root->filePath);
#ifdef _POSIX
		flock(fileno(root->dataFile), LOCK_UN);
#endif
		fclose(root->dataFile);
	}

	free(root);
}

// Store a key/value pair in the data store
__EXPORT_TYPE int ILibSimpleDataStore_PutEx2(ILibSimpleDataStore dataStore, char* key, size_t keyLen, char* value, size_t valueLen, char *vhash)
{
	if (valueLen > INT32_MAX || valueLen > INT32_MAX || keyLen > INT32_MAX) { return(1); }
	int keyAllocated = 0;
	int allocated = 0;
	char hash[SHA384HASHSIZE];
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	char *origkey = key;
	int origkeylen = (int)keyLen;

	if (root == NULL) { return 0; }
	if (root->dataFile == NULL)
	{
		ILibSimpleDataStore_CachedEx(dataStore, key, keyLen, value, valueLen, vhash);
		return(0);
	}

	if (keyLen > 1 && key[keyLen - 1] == 0) { keyLen -= 1; }
	if (vhash != NULL)
	{
		// If we're going to save a compressed record, then we should delete the corrosponding
		// non compressed entry, to avoid confusion/conflicts
		entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Remove(root->keyTable, NULL, key, (int)keyLen); // No loss of data, capped to INT32_MAX
		if (entry != NULL)
		{
			ILibSimpleDataStore_WriteRecord(root->dataFile, key, (int)keyLen, NULL, 0, NULL); // No dataloss, capped to INT32_MAX
		}

		// Calculate the key to use for the compressed record entry
		char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(int));
		keyAllocated = 1;
		memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
		((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)tmpkey, (uint32_t)keyLen); // No dataloss, capped to INT32_MAX
		key = tmpkey;
		keyLen = (int)ILibMemory_Size(key);
		memcpy_s(hash, sizeof(hash), vhash, SHA384HASHSIZE);
	}

	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, (int)keyLen); // No dataloss, capped to INT32_MAX
	if (vhash == NULL) { ILibSimpleDataStore_SHA384(value, valueLen, hash); }  // Hash the value

	// Create a new record for the key and value
	if (entry == NULL) 
	{
		entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL); 
		allocated = 1;
	}
	else 
	{
		if (memcmp(entry->valueHash, hash, SHA384HASHSIZE) == 0) { return 0; }
		root->dirtySize += entry->valueLength;
	}

	memcpy_s(entry->valueHash, sizeof(entry->valueHash), hash, SHA384HASHSIZE);
	entry->valueLength = (int)valueLen; // No dataloss, capped to INT32_MAX
	entry->valueOffset = ILibSimpleDataStore_WriteRecord(root->dataFile, key, (int)keyLen, value, (int)valueLen, entry->valueHash); // Write the key and value, no dataloss, capped to INT32_MAX
	root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile); // Update the size of the data store;

	if (entry->valueOffset == 0)
	{
		//
		// Write Error, switch to readonly mode,
		// and re-write this record into the cache
		//
		if (allocated) { free(entry); }
		if (keyAllocated) { ILibMemory_Free(key); }
		ILibSimpleDataStore_CachedEx(root, origkey, origkeylen, value, valueLen, vhash);
		ILibSimpleDataStore_ReOpenReadOnly(root, NULL);
		if (root->ErrorHandler != NULL) { root->ErrorHandler(root, root->ErrorHandlerUser); }
		return(0);
	}

	// Add the record to the data store
	ILibHashtable_Put(root->keyTable, NULL, key, (int)keyLen, entry); // No dataloss, capped to INT32_MAX
	if (root->warningSize > 0 && root->fileSize > root->warningSize && root->warningSink != NULL)
	{
		root->warningSink(root, root->fileSize, root->warningSinkUser);
	}
	if (keyAllocated) { ILibMemory_Free(key); }
	return(0);
}

int ILibSimpleDataStore_PutCompressed(ILibSimpleDataStore dataStore, char* key, size_t keyLen, char* value, size_t valueLen)
{
	int ret = 1;
	if (keyLen > INT32_MAX || valueLen > INT32_MAX) { return(ret); }

	char hash[SHA384HASHSIZE];
	char *tmp = NULL;
	size_t tmpLen = 0;
	if (ILibDeflate(value, valueLen, NULL, &tmpLen, NULL) == 0)
	{
		tmp = (char*)ILibMemory_SmartAllocate(tmpLen);
		if (ILibDeflate(value, valueLen, tmp, &tmpLen, NULL) == 0)
		{
			ILibSimpleDataStore_SHA384(value, valueLen, hash);   // Hash the Uncompressed Data
			ILibSimpleDataStore_PutEx2(dataStore, key, keyLen, tmp, (int)tmpLen, hash);
			ret = 0;
		}
		ILibMemory_Free(tmp);
	}
	return(ret);
}


__EXPORT_TYPE int ILibSimpleDataStore_GetInt(ILibSimpleDataStore dataStore, char* key, int defaultValue)
{
	int bufLen = ILibSimpleDataStore_Get(dataStore, key, ILibScratchPad, sizeof(ILibScratchPad));
	if (bufLen == 0 || bufLen >= sizeof(ILibScratchPad)) { return(defaultValue); }
	return(ILib_atoi2_int32(ILibScratchPad, sizeof(ILibScratchPad)));
}

// Get a value from the data store given a key
__EXPORT_TYPE int ILibSimpleDataStore_GetEx(ILibSimpleDataStore dataStore, char* key, size_t keyLen, char *buffer, size_t bufferLen)
{
	if (keyLen > INT32_MAX || bufferLen > INT32_MAX) { return(0); }

	int isCompressed = 0;
	char hash[SHA384HASHSIZE];
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return 0;
	if (keyLen > 1 && key[keyLen - 1] == 0) { keyLen -= 1; }

	if (root->cacheTable != NULL)
	{
		ILibSimpleDataStore_CacheEntry *centry = (ILibSimpleDataStore_CacheEntry*)ILibHashtable_Get(root->cacheTable, NULL, key, (int)keyLen); // No dataloss, capped to INT32_MAX
		if (centry == NULL)
		{
			// Let's check if this is a compressed record entry
			size_t tmplen = 0;
			char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
			memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
			((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)key, (uint32_t)keyLen); // No dataloss, capped to INT32_MAX
			centry = (ILibSimpleDataStore_CacheEntry*)ILibHashtable_Get(root->cacheTable, NULL, tmpkey, (int)ILibMemory_Size(tmpkey));
			if (centry != NULL)
			{
				ILibInflate(centry->value, centry->valueLength, NULL, &tmplen, 0);
				if (buffer != NULL && bufferLen >= (int)tmplen)
				{
					ILibInflate(centry->value, centry->valueLength, buffer, &tmplen, 0);
				}
			}
			ILibMemory_Free(tmpkey);
			if (tmplen > 0) { return((int)tmplen); }
		}
		if (centry != NULL)
		{
			if ((buffer != NULL) && (bufferLen >= (size_t)centry->valueLength)) // If the buffer is not null and can hold the value, place the value in the buffer.
			{
				memcpy_s(buffer, bufferLen, centry->value, centry->valueLength);
				if (bufferLen > (size_t)centry->valueLength) { buffer[centry->valueLength] = 0; } // Add a zero at the end to be nice, if the buffer can take it.

				return(centry->valueLength);
			}
			else if(bufferLen == 0)
			{
				return(centry->valueLength);
			}
			else
			{
				return(0);
			}
		}
	}

	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, (int)keyLen); // No dataloss, capped to INT32_MAX
	if (entry == NULL)
	{
		// Before returning an error, check if this is a compressed record
		char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
		memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
		((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)tmpkey, (uint32_t)keyLen); // no dataloss, capped to INT32_MAX
		entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, tmpkey, (int)ILibMemory_Size(tmpkey));
		ILibMemory_Free(tmpkey);
		if (entry != NULL) { isCompressed = 1; }
	}

	if (entry == NULL) return 0; // If there is no in-memory entry for this key, return zero now.
	if ((buffer != NULL) && (bufferLen >= (size_t)entry->valueLength) && isCompressed == 0) // If the buffer is not null and can hold the value, place the value in the buffer.
	{
		if (ILibSimpleDataStore_SeekPosition(root->dataFile, entry->valueOffset, SEEK_SET) != 0) return 0; // Seek to the position of the value in the data store
		if (fread(buffer, 1, entry->valueLength, root->dataFile) == 0) return 0; // Read the value into the buffer
		util_sha384(buffer, entry->valueLength, hash); // Compute the hash of the read value
		if (memcmp(hash, entry->valueHash, SHA384HASHSIZE) != 0) return 0; // Check the hash, return 0 if not valid
		if (bufferLen > (size_t)entry->valueLength) { buffer[entry->valueLength] = 0; } // Add a zero at the end to be nice, if the buffer can take it.
	}
	else if (isCompressed != 0)
	{
		// This is a compressed record
		char *compressed = ILibMemory_SmartAllocate(entry->valueLength);
		size_t tmplen = bufferLen;
		if (ILibSimpleDataStore_SeekPosition(root->dataFile, entry->valueOffset, SEEK_SET) != 0) return 0; // Seek to the position of the value in the data store
		if (fread(compressed, 1, entry->valueLength, root->dataFile) == 0) return 0; // Read the value into the buffer
		if (ILibInflate(compressed, entry->valueLength, buffer, &tmplen, 0) == 0)
		{
			ILibMemory_Free(compressed);
			if (buffer == NULL) { return((int)tmplen); }

			// Before we return, we need to check the HASH of the uncompressed data
			ILibSimpleDataStore_SHA384(buffer, (int)tmplen, hash);
			if (memcmp(hash, entry->valueHash, SHA384HASHSIZE) == 0)
			{
				return((int)tmplen);
			}
			else
			{
				return(0);
			}
		}
		else
		{
			ILibMemory_Free(compressed);
			return(0);
		}
	}

	return((bufferLen == 0 || bufferLen >= (size_t)entry->valueLength) ? entry->valueLength : 0);
}

// Get the reference to the SHA384 hash value from the datastore for a given a key.
__EXPORT_TYPE char* ILibSimpleDataStore_GetHashEx(ILibSimpleDataStore dataStore, char* key, size_t keyLen)
{
	if (keyLen > INT32_MAX) { return(NULL); }
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry = NULL;
	
	if (root == NULL) return NULL;
	if (root->cacheTable != NULL)
	{
		ILibSimpleDataStore_CacheEntry *centry = (ILibSimpleDataStore_CacheEntry*)ILibHashtable_Get(root->cacheTable, NULL, key, (int)keyLen); // no dataloss, capped to INT32_MAX
		if (centry == NULL)
		{
			// Let's check if this is a compressed record entry
			char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
			memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
			((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)key, (uint32_t)keyLen); // no dataloss, capped to INT32_MAX
			centry = (ILibSimpleDataStore_CacheEntry*)ILibHashtable_Get(root->cacheTable, NULL, tmpkey, (int)ILibMemory_Size(tmpkey));
			if (centry != NULL)
			{
				ILibMemory_Free(tmpkey);
				return(centry->valueHash);
			}
		}
		if (centry != NULL)
		{
			return(centry->valueHash);
		}
	}

	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, (int)keyLen); // no dataloss, capped to INT32_MAX
	if (entry == NULL)
	{
		// Before we return an error, let's check if this is a compressed record
		char* tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
		memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
		((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)key, (uint32_t)keyLen);
		entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, tmpkey, (int)ILibMemory_Size(tmpkey));
		ILibMemory_Free(tmpkey);
	}

	if (entry == NULL) return NULL; // If there is no in-memory entry for this key, return zero now.
	return entry->valueHash;
}
int ILibSimpleDataStore_GetHashSize()
{
	ILibSimpleDataStore_TableEntry e;
	return((int)sizeof(e.valueHash));
}
// Delete a key and value from the data store
__EXPORT_TYPE int ILibSimpleDataStore_DeleteEx(ILibSimpleDataStore dataStore, char* key, size_t keyLen)
{
	if (keyLen > INT32_MAX) { return(0); }
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return 0;
	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Remove(root->keyTable, NULL, key, (int)keyLen); // no dataloss, capped to INT32_MAX
	if (entry == NULL)
	{
		// Check to see if this is a compressed record, before we return an error
		char *tmpkey = (char*)ILibMemory_SmartAllocate(keyLen + sizeof(uint32_t));
		memcpy_s(tmpkey, ILibMemory_Size(tmpkey), key, keyLen);
		((uint32_t*)(tmpkey + keyLen))[0] = crc32c(0, (unsigned char*)key, (uint32_t)keyLen); // no dataloss, capped to INT32_MAX
		entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Remove(root->keyTable, NULL, tmpkey, (int)ILibMemory_Size(tmpkey));
		if (entry != NULL)
		{
			if (ILibSimpleDataStore_WriteRecord(root->dataFile, tmpkey, (int)ILibMemory_Size(tmpkey), NULL, 0, NULL) == 0)
			{
				if (root->ErrorHandler != NULL) { root->ErrorHandler(root, root->ErrorHandlerUser); }
			}
			free(entry);
			ILibMemory_Free(tmpkey);
			return 1;
		}
		ILibMemory_Free(tmpkey);
	}
	else
	{
		if (ILibSimpleDataStore_WriteRecord(root->dataFile, key, (int)keyLen, NULL, 0, NULL) == 0) // no dataloss, capped to INT32_MAX
		{
			if (root->ErrorHandler != NULL) { root->ErrorHandler(root, root->ErrorHandlerUser); }
		}
		free(entry); 
		return 1;
	}
	return 0;
}

// Lock the data store file
__EXPORT_TYPE void ILibSimpleDataStore_Lock(ILibSimpleDataStore dataStore)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root == NULL) return;
	ILibHashtable_Lock(root->keyTable);
}

// Unlock the data store file
__EXPORT_TYPE void ILibSimpleDataStore_UnLock(ILibSimpleDataStore dataStore)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root == NULL) return;
	ILibHashtable_UnLock(root->keyTable);
}

// Called by the compaction method, for each key in the enumeration we write the key/value to the temporary data store
void ILibSimpleDataStore_Compact_EnumerateSink(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDataStore_TableEntry *entry = (ILibSimpleDataStore_TableEntry*)Data;
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)((void**)user)[0];
	FILE *compacted = (FILE*)((void**)user)[1];
	uint64_t offset;
	char value[4096];
	int valueLen;
	int bytesLeft = entry->valueLength;
	int totalBytesWritten = 0;
	int bytesWritten = 0;

	if (root == NULL) return;
	if (root->error != 0) return; // There was an error, ABORT!

	if (Key2Len > 1)
	{
		if (Key2[Key2Len - 1] == 0)
		{
			Key2Len -= 1;
		}
	}
	offset = ILibSimpleDataStore_WriteRecord(compacted, Key2, Key2Len, NULL, entry->valueLength, entry->valueHash);
	if (offset == 0) { root->error = 1; return; }
	while (bytesLeft > 0)
	{
		if (ILibSimpleDataStore_SeekPosition(root->dataFile, entry->valueOffset + totalBytesWritten, SEEK_SET) == 0)
		{
			valueLen = (int)fread(value, 1, bytesLeft > 4096 ? 4096 : bytesLeft, root->dataFile);
			bytesWritten = (int)fwrite(value, 1, valueLen, compacted);
			if (bytesWritten != valueLen)
			{
				// Error
				root->error = 1;
				break;
			}
			totalBytesWritten += bytesWritten;
			bytesLeft -= valueLen;
		}
		else
		{
			// Error
			root->error = 1;
			break;
		}
	}
	
	if (root->error == 0) { entry->valueOffset = offset; }
}

// Used to help with key enumeration
void ILibSimpleDataStore_EnumerateKeysSink(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibSimpleDataStore_KeyEnumerationHandler handler = (ILibSimpleDataStore_KeyEnumerationHandler)((void**)user)[0];
	ILibSimpleDataStore_KeyEnumerationHandler dataStore = (ILibSimpleDataStore)((void**)user)[1];
	ILibSimpleDataStore_KeyEnumerationHandler userX = ((void**)user)[2];

	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(Key1);
	UNREFERENCED_PARAMETER(Key2);
	UNREFERENCED_PARAMETER(Key2Len);

	if (Key2Len > sizeof(uint32_t))
	{
		// Check if this is a compressed entry
		if (crc32c(0, (unsigned char*)Key2, Key2Len - sizeof(uint32_t)) == ((uint32_t*)(Key2 + Key2Len - sizeof(uint32_t)))[0])
		{
			Key2Len -= sizeof(uint32_t);
		}
	}

	handler(dataStore, Key2, Key2Len, userX); // Call the user
}

// Enumerate each key in the data store, call the handler for each key
__EXPORT_TYPE void ILibSimpleDataStore_EnumerateKeys(ILibSimpleDataStore dataStore, ILibSimpleDataStore_KeyEnumerationHandler handler, void * user)
{
	void* users[3];
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root == NULL) return;

	users[0] = (void*)handler;
	users[1] = (void*)dataStore;
	users[2] = (void*)user;

	if (handler != NULL) { ILibHashtable_Enumerate(root->keyTable, ILibSimpleDataStore_EnumerateKeysSink, users); }
}
void ILibSimpleDataStore_ConfigWriteErrorHandler(ILibSimpleDataStore dataStore, ILibSimpleDataStore_WriteErrorHandler handler, void *user)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	root->ErrorHandler = handler;
	root->ErrorHandlerUser = user;
}
__EXPORT_TYPE void ILibSimpleDataStore_ConfigSizeLimit(ILibSimpleDataStore dataStore, uint64_t sizeLimit, ILibSimpleDataStore_SizeWarningHandler handler, void *user)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	root->warningSize = sizeLimit;
	root->warningSink = sizeLimit > 0 ? handler : NULL;
	root->warningSinkUser = sizeLimit > 0 ? user : NULL;
}
__EXPORT_TYPE void ILibSimpleDataStore_ConfigCompact(ILibSimpleDataStore dataStore, uint64_t minimumDirtySize)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	root->minimumDirtySize = minimumDirtySize;
}
// Compact the data store
__EXPORT_TYPE int ILibSimpleDataStore_Compact(ILibSimpleDataStore dataStore)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	char* tmp;
	FILE* compacted;
	void* state[2];
	int retVal = 0;

	if (root == NULL || root->dirtySize < root->minimumDirtySize || root->filePath == NULL) return 1; // Error
	tmp = ILibString_Cat(root->filePath, -1, ".tmp", -1); // Create the name of the temporary data store

	// Start by opening a temporary .tmp file. Will be used to write the compacted data store.
	if ((compacted = ILibSimpleDataStore_OpenFileEx(tmp, 1)) == NULL) { free(tmp); return 1; }

	// Enumerate all keys and write them all into the temporary data store
	state[0] = root;
	state[1] = compacted;
	root->error = 0;
	ILibHashtable_Enumerate(root->keyTable, ILibSimpleDataStore_Compact_EnumerateSink, state);

	// Check if the enumeration went as planned
	if (root->error == 0)
	{
		// Success in writing new temporary file
#ifdef _POSIX
		flock(fileno(root->dataFile), LOCK_UN);
#endif
		fclose(root->dataFile); // Close the data store
		fclose(compacted); // Close the temporary data store

		// Now we copy the temporary data store over the data store, making it the new valid version
#ifdef WIN32
		WCHAR tmptmp[4096];
		MultiByteToWideChar(CP_UTF8, 0, (LPCCH)tmp, -1, (LPWSTR)tmptmp, (int)sizeof(tmptmp) / 2);
		if (CopyFileW(tmptmp, ILibUTF8ToWide(root->filePath, -1), FALSE) == FALSE) { retVal = 1; }
		DeleteFileW(tmptmp);
#else
		if (rename(tmp, root->filePath) != 0) { retVal = 1; }
#endif

		// We then open the newly compacted data store
		if ((root->dataFile = ILibSimpleDataStore_OpenFile(root->filePath)) != NULL) { root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile); } else { retVal = 1; }
	}

	free(tmp); // Free the temporary file name
	return retVal; // Return 1 if we got an error, 0 if everything finished correctly
}

int ILibSimpleDataStore_IsCacheOnly(ILibSimpleDataStore ds)
{
	return(((ILibSimpleDataStore_Root*)ds)->dataFile == NULL ? 1 : 0);
}