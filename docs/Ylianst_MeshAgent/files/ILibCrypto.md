## ILibCrypto.c

### Abstract
ILibCrypto provides cryptographic functions for the Mesh Agent, in a platform agnostic fashion.

### Functions

**util_md5(data, datalen,  result)**  
Writes the MD5 hash of *data* into *result*

**util_md5hex(data, datalen, result)**  
Writes the MD5 hash of *data* into *result* as a HEX string

**util_sha1(data, datalen, result)**  
Writes the SHA1 hash of *data* into *result*

**util_tohex(data, len, result)**  
Writes *data* into *result* as a HEX string

**util_tohex2(data, len, result)**  
Writes *data* into *results* as a HEX string, separating each byte with a colon

**util_tohex_lower(data, len, result)**  
Writes *data* into *result* as a lower case HEX string

**util_hexToint(hexString, hexStringLength)**  
Converts a HEX string into an integer value

**util_hexToBuf(hexString, hexStringLength, result)**  
Writes *hexString* into *result* as an array of bytes

**util_sha256(data, datalen, result)**  
Writes the SHA256 hash of *data* into *result*

**util_sha384(data, datalen, result)**  
Writes the SHA384 hash of *data* into *result*

**util_sha384file(filename, result)**  
Writes the SHA384 hash of the specified file into *result*

// File and data methods
**util_writefile(filename, data, datalen)**  
Writes *data* into the specified file, overwriting if the file exists.

**util_appendfile(filename, data, datalen)**  
Appends *data* to the end of the specified file

**util_readfile(filename, data, maxlen)**  
Reads the specified number of bytes from the specified file

**util_deletefile(filename)**  
Deletes the specified file

**util_crc(buffer, len, initial_value)**  
Performas a crc on *buffer* using the specified initial crc value

**util_MoveFile(lpExistingFileName, lpNewFileName)**  
Moves the specified file to the specified location

**util_CopyFile(lpExistingFileName, lpNewFileName, bFailIfExists)**  
Copies the specified file to the specified location

**util_random(length, result)**  
Writes *length* number of random bytes into *result*

**util_randomtext(length, result)**  
Writes *length* number of random letters into *result*

**SHA512_Init(ctx)**  
Initializes a SHA512 context

**SHA384_Init(ctx)**  
Initializes a SHA384 context

**SHA256_Init(ctx)**  
Initializes a SHA256 context

**SHA1_Init(ctx)**  
Initializes a SHA1 context

**MD5_Init(ctx)**  
Initializes an MD5 context

**SHA512_Update(ctx, data, len)**  
Updates the SHA512 hash with *data*

**SHA384_Update(ctx, data, len)**  
Updates the SHA384 hash with *data*

**SHA256_Update(ctx, data, len)**  
Updates the SHA256 hash with *data*

**SHA1_Update(ctx, data, len)**  
Updates the SHA1 hash with *data*

**MD5_Update(ctx, data, len)**  
Updates the MD5 hash with *data*

**SHA512_Final(md, ctx)**  
Generates the final SHA512 hash value

**SHA384_Final(md, ctx)**  
Generates the final SHA384 hash value

**SHA256_Final(md, ctx)**  
Generates the final SHA256 hash value

**SHA1_Final(md, ctx)**  
Generates the final SHA1 hash value

**MD5_Final(md, ctx)**  
Generates the final MD5 hash value

**util_openssl_init()**  
Initialize OpenSSL

**util_openssl_uninit()**  
Uninitialize OpenSSL, releases any used resources

**util_free(char* ptr)**  
Release resources allocated by *ptr*

// Certificate & crypto methods
**util_freecert(struct util_cert* cert)**  
Releases the specified certificate

**util_to_p12(cert, password, data)**  
Encodes the specified certificate into *data* as PKCS12

**util_from_p12(data, datalen, password, cert)**  
Decodes the specified PKCS12 encoded *data*

**util_to_cer(cert, data)**  
Encodes the specified *Cert* into *data* in CER format

**util_from_cer(data, datalen, cert)**  
Decodes the CER encoded *data*

**util_from_pem(filename, cert)**  
Reads a certificate from the specified PEM file

**util_from_pem_string(data, datalen, cert)**  
Reads a certificate from the specified PEM string

**util_from_pkcs7b_string(data, datalen, result, resultLen)**  
Decodes the specified pkcs7b string

**util_mkCertEx(rootcert, cert, bits, days, name, certtype, initialcert, noUsages)**  
**util_mkCert(rootcert, cert, bits, days, name, certtype, initialcert)**  
Generates a certificate using the specified parameters

void  __fastcall util_printcert(struct util_cert cert);
void  __fastcall util_printcert_pk(struct util_cert cert);

**util_certhash(cert, result)**  
**util_certhash2(X509cert, result)**  
Writes the SHA384 Digest into *result*

**util_keyhash(cert, result)**  
**util_keyhash2(X509cert, result)**  
Writes the SHA384 Digest of the public key into *result*

**util_sign(cert, data, datalen, signature)**  
Sign this specified *data*. The first 32 bytes of the block must be avaialble to add the certificate hash.

**util_verify(signature, signlen, cert, data)**  
Verify the *signature* of *data*. The first 32 bytes of *data* must contain the certificate hash.

**util_encrypt(cert, data, datalen, encdata)**  
**util_encrypt2(certs, data, datalen, encdata)**  
Encrypt *data* into *encdata*

**util_decrypt(encdata, encdatalen, cert, data)**  
Decrypt the specified data block

**util_rsaencrypt(cert, data, datalen, encdata)**  
Encrypt a block of data using raw RSA. This is used to handle data in the most compact possible way.

**util_rsadecrypt(cert, data, datalen, decdata)**  
Decrypt a block of data using raw RSA

**util_rsaverify(cert, data, datalen, sign, signlen)**  
Verify the RSA signature of a block using SHA1 hash
