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
	int error;
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
	int valueLength;
	char value[];
}ILibSimpleDataStore_CacheEntry;

const int ILibMemory_SimpleDataStore_CONTAINERSIZE = sizeof(ILibSimpleDataStore_Root);
void ILibSimpleDataStore_RebuildKeyTable(ILibSimpleDataStore_Root *root);


// Perform a SHA384 hash of some data
void ILibSimpleDataStore_SHA384(char *data, int datalen, char* result) { util_sha384(data, datalen, result); }

void ILibSimpleDataStore_Cached(ILibSimpleDataStore dataStore, char* key, int keyLen, char* value, int valueLen)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	if (root->cacheTable == NULL) { root->cacheTable = ILibHashtable_Create(); }
	ILibSimpleDataStore_CacheEntry *entry = (ILibSimpleDataStore_CacheEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_CacheEntry) + valueLen, 0, NULL, NULL);
	entry->valueLength = valueLen;
	memcpy_s(entry->value, valueLen, value, valueLen);
	
	ILibHashtable_Put(root->cacheTable, NULL, key, keyLen, entry);
}

// Write a key/value pair to file, the hash is already calculated
uint64_t ILibSimpleDataStore_WriteRecord(FILE *f, char* key, int keyLen, char* value, int valueLen, char* hash)
{
	char headerBytes[sizeof(ILibSimpleDataStore_RecordHeader_NG)];
	ILibSimpleDataStore_RecordHeader_NG *header = (ILibSimpleDataStore_RecordHeader_NG*)headerBytes;
	uint64_t offset;

	fseek(f, 0, SEEK_END);
	header->nodeSize = htonl(sizeof(ILibSimpleDataStore_RecordHeader_NG) + keyLen + valueLen);
	header->keyLen = htonl(keyLen);
	header->valueLength = htonl(valueLen);
	if (hash != NULL) { memcpy_s(header->hash, sizeof(header->hash), hash, SHA384HASHSIZE); } else { memset(header->hash, 0, SHA384HASHSIZE); }

	if (fwrite(headerBytes, 1, sizeof(ILibSimpleDataStore_RecordHeader_NG), f)) {}
	if (fwrite(key, 1, keyLen, f)) {}
	offset = ILibSimpleDataStore_GetPosition(f);
	if (value != NULL) { if (fwrite(value, 1, valueLen, f)) {} }
	fflush(f);
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
			if (entry == NULL) { ++count;  entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL); }
			memcpy_s(entry->valueHash, sizeof(entry->valueHash), node->hash, SHA384HASHSIZE);
			entry->valueLength = node->valueLength;
			entry->valueOffset = ILibSimpleDataStore_RecordHeader_ValueOffset(node);
			ILibHashtable_Put(root->keyTable, NULL, node->key, node->keyLen, entry);
		}
		else if (entry != NULL)
		{
			// If value is empty, remove the in-memory entry.
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
			h = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				h = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			}
		}
		else
		{
			h = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				h = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			}
		}
		int fd = _open_osfhandle((intptr_t)h, _O_RDWR);
		if (fd == -1) { CloseHandle(h); return(NULL); }
		f = _fdopen(fd, "wb+N");
		if (f == NULL) { CloseHandle(h); return(NULL); }
	}
	else
	{
		HANDLE h = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
	return(_access(filePath, 0) == 0 ? 1 : 0);
#else
	return(access(filePath, 0) == 0 ? 1 : 0);
#endif
}
// Open the data store file. Optionally allocate spare user memory
__EXPORT_TYPE ILibSimpleDataStore ILibSimpleDataStore_CreateEx2(char* filePath, int userExtraMemorySize, int readonly)
{
	ILibSimpleDataStore_Root* retVal = (ILibSimpleDataStore_Root*)ILibMemory_Allocate(ILibMemory_SimpleDataStore_CONTAINERSIZE, userExtraMemorySize, NULL, NULL);
	
	retVal->filePath = ILibString_Copy(filePath, (int)strnlen_s(filePath, ILibSimpleDataStore_MaxFilePath));
	retVal->dataFile = ILibSimpleDataStore_OpenFileEx2(retVal->filePath, 0, readonly);

	if (retVal->dataFile == NULL)
	{
		free(retVal->filePath);
		free(retVal);
		return NULL;
	}

	retVal->keyTable = ILibHashtable_Create();
	ILibSimpleDataStore_RebuildKeyTable(retVal);
	return retVal;
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

	free(root->filePath);

#ifdef _POSIX
	flock(fileno(root->dataFile), LOCK_UN);
#endif

	fclose(root->dataFile);
	free(root);
}

// Store a key/value pair in the data store
__EXPORT_TYPE int ILibSimpleDataStore_PutEx(ILibSimpleDataStore dataStore, char* key, int keyLen, char* value, int valueLen)
{
	char hash[SHA384HASHSIZE];
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return 0;
	if (keyLen > 1 && key[keyLen - 1] == 0) { keyLen -= 1; }
	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, keyLen);
	ILibSimpleDataStore_SHA384(value, valueLen, hash); // Hash the value

	// Create a new record for the key and value
	if (entry == NULL) {
		entry = (ILibSimpleDataStore_TableEntry*)ILibMemory_Allocate(sizeof(ILibSimpleDataStore_TableEntry), 0, NULL, NULL); }
	else {
		if (memcmp(entry->valueHash, hash, SHA384HASHSIZE) == 0) { return 0; }
	}

	memcpy_s(entry->valueHash, sizeof(entry->valueHash), hash, SHA384HASHSIZE);
	entry->valueLength = valueLen;
	entry->valueOffset = ILibSimpleDataStore_WriteRecord(root->dataFile, key, keyLen, value, valueLen, entry->valueHash); // Write the key and value
	root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile); // Update the size of the data store;

	// Add the record to the data store
	return ILibHashtable_Put(root->keyTable, NULL, key, keyLen, entry) == NULL ? 0 : 1;
}

// Get a value from the data store given a key
__EXPORT_TYPE int ILibSimpleDataStore_GetEx(ILibSimpleDataStore dataStore, char* key, int keyLen, char *buffer, int bufferLen)
{
	char hash[SHA384HASHSIZE];
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return 0;
	if (keyLen > 1 && key[keyLen - 1] == 0) { keyLen -= 1; }

	if (root->cacheTable != NULL)
	{
		ILibSimpleDataStore_CacheEntry *centry = (ILibSimpleDataStore_CacheEntry*)ILibHashtable_Get(root->cacheTable, NULL, key, keyLen);
		if (centry != NULL)
		{
			if ((buffer != NULL) && (bufferLen >= centry->valueLength)) // If the buffer is not null and can hold the value, place the value in the buffer.
			{
				memcpy_s(buffer, bufferLen, centry->value, centry->valueLength);
				return(centry->valueLength);
			}
			else
			{
				return(centry->valueLength);
			}
		}
	}

	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, keyLen);

	if (entry == NULL) return 0; // If there is no in-memory entry for this key, return zero now.
	if ((buffer != NULL) && (bufferLen >= entry->valueLength)) // If the buffer is not null and can hold the value, place the value in the buffer.
	{
		if (ILibSimpleDataStore_SeekPosition(root->dataFile, entry->valueOffset, SEEK_SET) != 0) return 0; // Seek to the position of the value in the data store
		if (fread(buffer, 1, entry->valueLength, root->dataFile) == 0) return 0; // Read the value into the buffer
		util_sha384(buffer, entry->valueLength, hash); // Compute the hash of the read value
		if (memcmp(hash, entry->valueHash, SHA384HASHSIZE) != 0) return 0; // Check the hash, return 0 if not valid
		if (bufferLen > entry->valueLength) { buffer[entry->valueLength] = 0; } // Add a zero at the end to be nice, if the buffer can take it.
	}
	return entry->valueLength;
}

// Get the reference to the SHA384 hash value from the datastore for a given a key.
__EXPORT_TYPE char* ILibSimpleDataStore_GetHashEx(ILibSimpleDataStore dataStore, char* key, int keyLen)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return NULL;
	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Get(root->keyTable, NULL, key, keyLen);

	if (entry == NULL) return NULL; // If there is no in-memory entry for this key, return zero now.
	return entry->valueHash;
}

// Delete a key and value from the data store
__EXPORT_TYPE int ILibSimpleDataStore_DeleteEx(ILibSimpleDataStore dataStore, char* key, int keyLen)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	ILibSimpleDataStore_TableEntry *entry;
	
	if (root == NULL) return 0;
	entry = (ILibSimpleDataStore_TableEntry*)ILibHashtable_Remove(root->keyTable, NULL, key, keyLen);
	if (entry != NULL) { ILibSimpleDataStore_WriteRecord(root->dataFile, key, keyLen, NULL, 0, NULL); free(entry); return 1; }
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

// Compact the data store
__EXPORT_TYPE int ILibSimpleDataStore_Compact(ILibSimpleDataStore dataStore)
{
	ILibSimpleDataStore_Root *root = (ILibSimpleDataStore_Root*)dataStore;
	char* tmp;
	FILE* compacted;
	void* state[2];
	int retVal = 0;

	if (root == NULL) return 1; // Error
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
		if (CopyFileA(tmp, root->filePath, FALSE) == FALSE) { retVal = 1; }
		DeleteFile(tmp);
#else
		if (rename(tmp, root->filePath) != 0) { retVal = 1; }
#endif

		// We then open the newly compacted data store
		if ((root->dataFile = ILibSimpleDataStore_OpenFile(root->filePath)) != NULL) { root->fileSize = ILibSimpleDataStore_GetPosition(root->dataFile); } else { retVal = 1; }
	}

	free(tmp); // Free the temporary file name
	return retVal; // Return 1 if we got an error, 0 if everything finished correctly
}
