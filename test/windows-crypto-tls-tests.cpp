#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <initializer_list>
#include "../microstack/ILibTLSContext.h"
static void check(bool ok){if(!ok){ERR_print_errors_fp(stderr);exit(2);}}
static void pump(BIO* from,BIO* to,bool corrupt=false){
 unsigned char data[65536];int n;
 while((n=BIO_read(from,data,sizeof(data)))>0){if(corrupt){data[n-1]^=1;corrupt=false;}check(BIO_write(to,data,n)==n);}
}
static EVP_PKEY* key(){
 EVP_PKEY_CTX* c=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);EVP_PKEY* k=NULL;check(c!=NULL);
 check(EVP_PKEY_keygen_init(c)>0&&EVP_PKEY_CTX_set_rsa_keygen_bits(c,2048)>0&&EVP_PKEY_keygen(c,&k)>0);
 EVP_PKEY_CTX_free(c);return k;
}
static X509* certificate(EVP_PKEY* k){
 X509* x=X509_new();check(x!=NULL);check(X509_set_version(x,2)==1);
 check(ASN1_INTEGER_set(X509_get_serialNumber(x),1)==1);
 check(X509_gmtime_adj(X509_getm_notBefore(x),-60)!=NULL&&X509_gmtime_adj(X509_getm_notAfter(x),3600)!=NULL);
 check(X509_set_pubkey(x,k)==1);X509_NAME* name=X509_get_subject_name(x);
 check(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char*)"meshagent-crypto-test.invalid",-1,-1,0)==1);
 check(X509_set_issuer_name(x,name)==1);
 X509_EXTENSION* ext=X509V3_EXT_conf_nid(NULL,NULL,NID_subject_alt_name,(char*)"DNS:meshagent-crypto-test.invalid");
 check(ext!=NULL&&X509_add_ext(x,ext,-1)==1);X509_EXTENSION_free(ext);
 check(X509_sign(x,k,EVP_sha256())>0);return x;
}
static void run(int version,bool trust,bool correctHost,bool corrupt,EVP_PKEY* k,X509* cert){
 SSL_CTX* server=SSL_CTX_new(TLS_server_method());SSL_CTX* client=SSL_CTX_new(TLS_client_method());check(server&&client);
 for(SSL_CTX* c:{server,client}){
  ILibSSL_CTX_SetProtocolOptions(c,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
  check((SSL_CTX_get_mode(c)&(SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER))==0);
  check((SSL_CTX_get_options(c)&SSL_OP_NO_EXTENDED_MASTER_SECRET)==0);
  check((SSL_CTX_get_options(c)&(SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3))==(SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3));
  check(SSL_CTX_set_min_proto_version(c,version)==1&&SSL_CTX_set_max_proto_version(c,version)==1);
  check(SSL_CTX_set_cipher_list(c,"ECDHE-RSA-AES128-GCM-SHA256")==1);
  check(SSL_CTX_set_ciphersuites(c,"TLS_AES_256_GCM_SHA384")==1);
 }
 check(SSL_CTX_use_certificate(server,cert)==1&&SSL_CTX_use_PrivateKey(server,k)==1);
 SSL_CTX_set_verify(client,SSL_VERIFY_PEER,NULL);
 if(trust)check(X509_STORE_add_cert(SSL_CTX_get_cert_store(client),cert)==1);
 SSL* s=SSL_new(server);SSL* c=SSL_new(client);check(s&&c);
 check(SSL_set1_host(c,correctHost?"meshagent-crypto-test.invalid":"wrong.invalid")==1);
 SSL_set_bio(s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_bio(c,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));
 SSL_set_accept_state(s);SSL_set_connect_state(c);bool failed=false,complete=false;
 for(int i=0;i<100;i++){
  for(SSL* p:{c,s}){
   int r=SSL_do_handshake(p);if(r!=1){int e=SSL_get_error(p,r);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE){failed=true;break;}}
   pump(SSL_get_wbio(p),SSL_get_rbio(p==c?s:c));
  }
  if(failed)break;
  if(SSL_is_init_finished(c)&&SSL_is_init_finished(s)){complete=true;break;}
 }
 if(!trust||!correctHost){check(failed&&SSL_get_verify_result(c)!=X509_V_OK);}
 else{
  check(complete&&!failed&&SSL_get_verify_result(c)==X509_V_OK);
  check(SSL_version(c)==version);
  const char* cipher=SSL_get_cipher_name(c);
  check(strcmp(cipher,version==TLS1_2_VERSION?"ECDHE-RSA-AES128-GCM-SHA256":"TLS_AES_256_GCM_SHA384")==0);
  unsigned char message[65536],decoded[65536];memset(message,0x6d,sizeof(message));
  int length=corrupt?16384:(int)sizeof(message);
  check(SSL_write(c,message,length)==length);pump(SSL_get_wbio(c),SSL_get_rbio(s),corrupt);
  int n=SSL_read(s,decoded,length);
  if(corrupt)check(n<=0&&SSL_get_error(s,n)==SSL_ERROR_SSL);
  else {
   check(n>0);int total=n;
   while(total<length){n=SSL_read(s,decoded+total,length-total);check(n>0);total+=n;}
   check(total==length&&memcmp(message,decoded,length)==0);
  }
 }
 SSL_free(c);SSL_free(s);SSL_CTX_free(client);SSL_CTX_free(server);ERR_clear_error();
}
int main(){
 EVP_PKEY* k=key();X509* cert=certificate(k);
 for(int version:{TLS1_2_VERSION,TLS1_3_VERSION}){
  run(version,true,true,false,k,cert);run(version,false,true,false,k,cert);
  run(version,true,false,false,k,cert);run(version,true,true,true,k,cert);
 }
 X509_free(cert);EVP_PKEY_free(k);
 puts("PASS: TLS 1.2/1.3 AES-GCM records; untrusted certificates, wrong hostnames and corrupt records rejected");
 return 0;
}
