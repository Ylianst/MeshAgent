#include "opus/opus.h"
#include <stdint.h>
#include <stdlib.h>
struct OpusEncoder { int m; };
static struct OpusEncoder g_e = {1};
extern int g_encodeCalls;
OpusEncoder* opus_encoder_create(int32_t fs,int ch,int app,int*err){ (void)fs;(void)ch;(void)app; *err=0; return (OpusEncoder*)&g_e; }
int opus_encoder_ctl(OpusEncoder*e,int r,...){ (void)e;(void)r; return 0; }
int opus_encode(OpusEncoder*e,const int16_t*pcm,int frames,unsigned char*out,int32_t max){
    (void)e;(void)pcm;(void)max; if(frames!=960) return -1; g_encodeCalls++; out[0]=1; return 40; }
void opus_encoder_destroy(OpusEncoder*e){ (void)e; }
