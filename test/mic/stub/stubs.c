#include "opus/opus.h"
#include <stdint.h>
#include <stdlib.h>
struct OpusDecoder { int m; };
static struct OpusDecoder g_d = {1};
extern int g_decodeCalls;
OpusDecoder* opus_decoder_create(int32_t fs,int ch,int*err){ (void)fs;(void)ch; *err=0; return (OpusDecoder*)&g_d; }
int opus_decode(OpusDecoder*d,const unsigned char*p,int32_t len,int16_t*pcm,int n,int fec){
    (void)d;(void)p;(void)len;(void)fec; g_decodeCalls++; for(int i=0;i<n;i++) pcm[i]=0; return n; }
void opus_decoder_destroy(OpusDecoder*d){ (void)d; }
