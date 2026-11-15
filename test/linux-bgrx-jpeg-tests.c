/* Actual DRM tile/JPEG boundary, with independent RGB reference and test-only
 * allocation/codec failures. Never supplies a production fault switch. */
#define _GNU_SOURCE
#include "../meshcore/KVM/Linux/linux_kvm_drm.c"
int SCREEN_NUM, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_DEPTH=24;
int TILE_WIDTH=32,TILE_HEIGHT=32,TILE_WIDTH_COUNT,TILE_HEIGHT_COUNT,COMPRESSION_RATIO=50;
int g_shutdown,slave2master[2],master2slave[2]={-1,-1};
struct tileInfo_t **g_tileInfo;
static int passed,failed,packet_failure,codec_failure;
#define CHECK(x) do{if(x)++passed;else{++failed;fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);}}while(0)
void *linux_tile_test_malloc(size_t n){if(packet_failure){packet_failure=0;return NULL;}return malloc(n);}
int ILibMemory_Copy_s(void *d,size_t c,void *s,size_t n){if(n>c)abort();memcpy(d,s,n);return 0;}
char *ILibCriticalLog(const char *m,const char *f,int l,int a,int b){(void)m;(void)f;(void)l;(void)a;(void)b;abort();}
void ILib_POSIX_CrashHandler(int n){(void)n;abort();}
void __real_jpeg_start_compress(j_compress_ptr,boolean);
void __wrap_jpeg_start_compress(j_compress_ptr c,boolean tables)
{__real_jpeg_start_compress(c,tables);if(codec_failure){codec_failure=0;ERREXIT(c,JERR_OUT_OF_MEMORY);}}
struct wire {unsigned char *data;size_t size;};
static void refresh(void){for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)g_tileInfo[r][c].crc=0xff;}
static struct wire collect(unsigned char *rgb,size_t size,const linux_tile_rgb32_frame *f,int expect)
{
    FILE *file=tmpfile();if(!file)abort();slave2master[1]=fileno(file);
    char *desktop=NULL;long long capacity=0;
    int result=f?kvm_drm_send_tiles(NULL,0,NULL,NULL,f):kvm_drm_send_dirty_tiles(rgb,size,&desktop,&capacity);
    CHECK(result==expect);long length=ftell(file);if(length<0)abort();
    struct wire out={malloc(length?length:1),(size_t)length};rewind(file);
    CHECK(fread(out.data,1,out.size,file)==out.size);fclose(file);free(desktop);return out;
}
static void equal(struct wire a,struct wire b){CHECK(a.size==b.size);CHECK(a.size!=b.size||!memcmp(a.data,b.data,a.size));free(a.data);free(b.data);}
static void save(int *crc){for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)*crc++=g_tileInfo[r][c].crc;}
static void restore(const int *crc){for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)g_tileInfo[r][c].crc=*crc++;}
static void release(void){for(int r=0;r<TILE_HEIGHT_COUNT;++r)free(g_tileInfo[r]);free(g_tileInfo);g_tileInfo=NULL;}
static void image_case(int w,int h,unsigned fmt,int quality)
{
#ifdef LINUX_BGRX_TRACE
    fprintf(stderr,"case %dx%d format %u quality %d\n",w,h,fmt,quality);
#endif
    const jpeg_pixel_format formats[]={JPEG_BGRX32,JPEG_RGBX32,JPEG_XBGR32,JPEG_XRGB32};
    const unsigned channels[4][3]={{2,1,0},{0,1,2},{3,2,1},{1,2,3}};
    SCREEN_WIDTH=w;SCREEN_HEIGHT=h;TILE_WIDTH_COUNT=w/32;TILE_HEIGHT_COUNT=(h+31)/32;reset_tile_info(0);
    size_t pitch=(size_t)w*4+12,capacity=pitch*TILE_HEIGHT_COUNT*32,visible=(size_t)w*h*3;
    unsigned char *allocation=malloc(capacity+2),*raw=allocation+1,*rgb=malloc(visible);
    memset(allocation,0xA7,capacity+2);memset(raw,0,capacity);
    for(int y=0;y<h;++y)for(int x=0;x<w;++x){
        for(unsigned c=0;c<3;++c)rgb[((size_t)y*w+x)*3+c]=raw[(size_t)y*pitch+x*4+channels[fmt][c]]=(unsigned char)(x*13+y*7+c*51);
        raw[(size_t)y*pitch+x*4+(fmt<2?3:0)]=(unsigned char)(x*29+y); // X is not image data.
    }
    linux_tile_rgb32_frame f={raw,capacity,pitch,formats[fmt]};set_tile_compression(1,quality);
    int *reference=malloc((size_t)TILE_WIDTH_COUNT*TILE_HEIGHT_COUNT*sizeof(int));
    for(int step=0;step<4;++step){
        if(step==1){rgb[visible-1]^=23;raw[(size_t)(h-1)*pitch+(w-1)*4+channels[fmt][2]]^=23;}
        if(step==2)for(int y=0;y<h;++y)for(int x=0;x<w;++x)raw[(size_t)y*pitch+x*4+(fmt<2?3:0)]^=0xff;
        if(step==3){rgb[0]^=7;raw[channels[fmt][0]]^=7;}
        int *before=malloc((size_t)TILE_WIDTH_COUNT*TILE_HEIGHT_COUNT*sizeof(int));save(before);
        int ratio=COMPRESSION_RATIO;
        struct wire expected=collect(rgb,visible,NULL,0);int afterRatio=COMPRESSION_RATIO;
        save(reference);restore(before);COMPRESSION_RATIO=ratio;
        struct wire actual=collect(NULL,0,&f,0);
        CHECK(COMPRESSION_RATIO==afterRatio);
        for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)
            CHECK(g_tileInfo[r][c].crc==reference[r*TILE_WIDTH_COUNT+c]);
        if(step==2)CHECK(expected.size==0&&actual.size==0);
        equal(expected,actual);free(before);
    }
    refresh();packet_failure=1;struct wire out=collect(NULL,0,&f,1);free(out.data);CHECK(packet_failure==0&&g_shutdown==0);
    out=collect(NULL,0,&f,0);CHECK(out.size>8);free(out.data);
    refresh();codec_failure=1;out=collect(NULL,0,&f,1);free(out.data);CHECK(codec_failure==0&&g_shutdown==0);
    // The worker switches back to ordinary RGB after a direct encode failure.
    out=collect(rgb,visible,NULL,0);CHECK(out.size>8);free(out.data);
    CHECK(allocation[0]==0xA7&&allocation[capacity+1]==0xA7);
    linux_tile_rgb32_frame invalid=f;invalid.capacity=capacity-1;CHECK(update_tile_checksums_rgb32(&invalid)==-1);
    invalid=f;invalid.stride=(size_t)w*4-1;CHECK(update_tile_checksums_rgb32(&invalid)==-1);
    invalid=f;invalid.format=JPEG_RGB24;CHECK(update_tile_checksums_rgb32(&invalid)==-1);
    void *packet=(void *)1;long long length=1;
    CHECK(getTileAt_rgb32(1,0,&packet,&length,&f,0,0)==-1&&packet==NULL&&length==0);
    free(reference);free(rgb);free(allocation);release();jpeg_encoder_cleanup();
}
int main(void)
{
    if(!jpeg_rgb32_supported(JPEG_BGRX32)){fprintf(stderr,"RGB32 JPEG unavailable in this test build\n");return 2;}
    for(unsigned format=0;format<4;++format)for(int h=1;h<=65;h=h==1?31:h==31?32:h==32?33:h==33?65:66)
        for(int q=0;q<3;++q)image_case(160,h,format,(int[]){1,50,90}[q]);
    image_case(3840,2160,0,50);
    CHECK(!jpeg_rgb32_supported(JPEG_RGB24)&&!jpeg_rgb32_supported((jpeg_pixel_format)99));
    unsigned char pixel[4]={1,2,3,4};
    CHECK(write_JPEG_buffer_pixels(pixel,1,1,3,50,JPEG_BGRX32)==-1&&!jpeg_buffer);
    CHECK(write_JPEG_buffer_pixels(pixel,1,1,4,50,(jpeg_pixel_format)99)==-1&&!jpeg_buffer);
    CHECK(kvm_drm_jpeg_format(DRM_FORMAT_RGB565)==JPEG_RGB24);
    CHECK(kvm_drm_jpeg_format(DRM_FORMAT_ARGB8888)==JPEG_BGRX32);
    CHECK(kvm_drm_jpeg_format(DRM_FORMAT_ABGR8888)==JPEG_RGBX32);
    CHECK(kvm_drm_jpeg_format(DRM_FORMAT_RGBA8888)==JPEG_XBGR32);
    CHECK(kvm_drm_jpeg_format(DRM_FORMAT_BGRA8888)==JPEG_XRGB32);
    printf("Direct RGB32 JPEG wire/recovery: %d passed, %d failed\n",passed,failed);return failed!=0;
}
