/* SPDX-License-Identifier: Apache-2.0 */
/* Synthetic resampler timing only; not a desktop/network/browser benchmark. */
#include "meshcore/KVM/Linux/linux_kvm_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
int main(void)
{
    for(int size=0;size<2;++size) {
        unsigned w=size?3840:1920,h=size?2160:1080,ow,oh;size_t bytes=(size_t)w*h*3;
        unsigned char *src=malloc(bytes),*dst=malloc(bytes);
        if(!src||!dst) return 1;
        kvm_capture_scaled_size(w,h,512,&ow,&oh);
        for(int scene=0;scene<3;++scene) {
            double elapsed=0;
            for(int frame=0;frame<8;++frame) {
                for(size_t p=0;p<bytes;++p) src[p]=scene==0?128:scene==1?(p/3+frame)%256:(p*37+frame*19)%256;
                double begin=now();kvm_capture_scale_rgb(src,w,h,dst,ow,oh);elapsed+=now()-begin;
            }
            printf("%ux%u synthetic %s: half-scale %.3f ms/frame; %u output pixels; witness=%u\n",w,h,scene==0?"idle":scene==1?"scroll":"animation",elapsed*1000/8,ow*oh,dst[0]);
        }
        free(src);free(dst);
    }
    return 0;
}
