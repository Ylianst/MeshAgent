#ifndef OPUS_STUB
#define OPUS_STUB
#include <stdint.h>
typedef struct OpusDecoder OpusDecoder;
#define OPUS_OK 0
OpusDecoder* opus_decoder_create(int32_t,int,int*);
int opus_decode(OpusDecoder*,const unsigned char*,int32_t,int16_t*,int,int);
void opus_decoder_destroy(OpusDecoder*);
#endif
