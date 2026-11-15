#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdlib>
static volatile unsigned char sink;
static void require(bool ok){if(!ok){ERR_print_errors_fp(stderr);exit(2);}}
static void kat(const EVP_CIPHER* cipher, const unsigned char* expected, const unsigned char* expectedTag){
 unsigned char key[32]={},iv[12]={},plain[16]={},out[32]={},tag[16]={},decoded[32]={};int n=0,last=0;
 EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();require(c!=NULL);
 require(EVP_EncryptInit_ex(c,cipher,NULL,key,iv)==1);
 require(EVP_EncryptUpdate(c,out,&n,plain,16)==1&&n==16);
 require(EVP_EncryptFinal_ex(c,out+n,&last)==1&&last==0);
 require(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1);
 require(memcmp(out,expected,16)==0&&memcmp(tag,expectedTag,16)==0);
 for(int bad=0;bad<2;bad++){
  require(EVP_DecryptInit_ex(c,cipher,NULL,key,iv)==1);
  require(EVP_DecryptUpdate(c,decoded,&n,out,16)==1);
  if(bad)tag[0]^=1;
  require(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,tag)==1);
  int result=EVP_DecryptFinal_ex(c,decoded+n,&last);
  require(bad?result<=0:result==1&&memcmp(decoded,plain,16)==0);
 }
 EVP_CIPHER_CTX_free(c);ERR_clear_error();
}
int main(){
 int cp[4];__cpuid(cp,1);
 printf("{\"version\":\"%s\",\"aesni\":%s,\"pclmul\":%s}\n",OpenSSL_version(OPENSSL_VERSION),(cp[2]&(1<<25))?"true":"false",(cp[2]&(1<<1))?"true":"false");
#ifdef OPENSSL_CPU_INFO
 printf("{\"dispatch\":\"%s\"}\n",OpenSSL_version(OPENSSL_CPU_INFO));
#endif
 const unsigned char e128[]={0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
 const unsigned char t128[]={0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
 const unsigned char e256[]={0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18};
 const unsigned char t256[]={0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};
 kat(EVP_aes_128_gcm(),e128,t128);kat(EVP_aes_256_gcm(),e256,t256);
 puts("{\"knownAnswerTests\":true,\"badTagRejected\":true}");
 LARGE_INTEGER f;QueryPerformanceFrequency(&f);
 for(int bits:{128,256})for(int size:{1024,16384,65536}){
  std::vector<unsigned char> input(size,0x53),out(size+16);unsigned char key[32]={},iv[12]={},tag[16];
  EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();require(c!=NULL);
  require(EVP_EncryptInit_ex(c,bits==128?EVP_aes_128_gcm():EVP_aes_256_gcm(),NULL,key,iv)==1);
  LARGE_INTEGER start,end;QueryPerformanceCounter(&start);unsigned long long count=0,cyclesStart=0,cyclesEnd=0;
  QueryProcessCycleTime(GetCurrentProcess(),&cyclesStart);
  do{
   for(int batch=0;batch<32;batch++){
    ++count;for(int j=0;j<8;j++)iv[11-j]=(unsigned char)(count>>(j*8));int n=0,last=0;
    require(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)==1);
    require(EVP_EncryptUpdate(c,out.data(),&n,input.data(),size)==1&&n==size);
    require(EVP_EncryptFinal_ex(c,out.data()+n,&last)==1);
    require(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1);sink^=tag[0];
   }
   QueryPerformanceCounter(&end);
  }while((double)(end.QuadPart-start.QuadPart)/f.QuadPart<0.5);
  QueryProcessCycleTime(GetCurrentProcess(),&cyclesEnd);
  double seconds=(double)(end.QuadPart-start.QuadPart)/f.QuadPart;
  printf("{\"bits\":%d,\"recordBytes\":%d,\"MBps\":%.3f,\"cyclesPerByte\":%.5f}\n",bits,size,count*(double)size/seconds/1e6,(cyclesEnd-cyclesStart)/(count*(double)size));
  EVP_CIPHER_CTX_free(c);
 }
 PROCESS_MEMORY_COUNTERS_EX m={};m.cb=sizeof(m);require(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&m,sizeof(m))!=0);
 printf("{\"privateBytes\":%llu,\"workingSet\":%llu}\n",(unsigned long long)m.PrivateUsage,(unsigned long long)m.WorkingSetSize);
}
