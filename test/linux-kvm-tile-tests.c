/* SPDX-License-Identifier: Apache-2.0 */
#include "meshcore/KVM/Linux/linux_tile.h"
#include "meshcore/meshdefines.h"
#include <stdint.h>

int SCREEN_NUM, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_DEPTH;
int TILE_WIDTH = 32, TILE_HEIGHT = 32, TILE_WIDTH_COUNT, TILE_HEIGHT_COUNT;
int COMPRESSION_RATIO = 50;
struct tileInfo_t **g_tileInfo;
extern unsigned char *jpeg_buffer;
extern int jpeg_buffer_length;
extern int util_crc(int, int, long long, void *, long long, int, int);
extern int calc_opt_compr_send(int, int, int, int, void *, long long, void **, long long *);
static int passed, failed;
#define CHECK(x) do { if (x) ++passed; else { ++failed; fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); } } while (0)
int ILibMemory_Copy_s(void *dst, size_t cap, void *src, size_t len)
{ if (len > cap) abort(); memcpy(dst,src,len); return 0; }
char *ILibCriticalLog(const char *msg,const char *file,int line,int a,int b)
{ (void)msg;(void)file;(void)line;(void)a;(void)b; abort(); }
void ILib_POSIX_CrashHandler(int code) { (void)code; abort(); }

static uint32_t reference(const unsigned char *image,size_t stride,int row,int col)
{
    uint32_t hash=0;
    for (int y=0;y<TILE_HEIGHT;++y)
    {
        const unsigned char *p=image+((size_t)row*TILE_HEIGHT+y)*stride+(size_t)col*TILE_WIDTH*3;
        size_t bytes=(size_t)TILE_WIDTH*3;
        for(size_t x=0;x+4<=bytes;x+=4)
        { uint32_t v; memcpy(&v,p+x,4); hash=(hash*16777619u)^v; }
        uint32_t tail=0; size_t n=bytes<3?bytes:3; memcpy(&tail,p+bytes-n,n);
        hash=(hash*16777619u)^tail;
    }
    return hash;
}
static void release_tiles(void)
{
    if(g_tileInfo) {for(int r=0;r<TILE_HEIGHT_COUNT;++r)free(g_tileInfo[r]);free(g_tileInfo);g_tileInfo=NULL;}
}
static void geometry(int cols,int rows,int tile)
{
    release_tiles(); TILE_WIDTH=TILE_HEIGHT=tile;
    SCREEN_WIDTH=cols*tile; SCREEN_HEIGHT=rows*tile;
    TILE_WIDTH_COUNT=cols; TILE_HEIGHT_COUNT=rows; reset_tile_info(0);
}
static void test_hashes(void)
{
    for(int tile=1;tile<=32;tile=tile==1?7:tile==7?32:33)
    for(int cols=1;cols<=13;++cols)
    {
        geometry(cols,3,tile);
        size_t stride=(size_t)SCREEN_WIDTH*3,size=stride*SCREEN_HEIGHT;
        unsigned char *allocation=malloc(size+1),*image=allocation+1; // unaligned, exact end
        for(size_t i=0;i<size;++i)image[i]=(unsigned char)(i*137u+i/17u);
        CHECK(update_tile_checksums(image,size)==0);
        for(int r=0;r<3;++r)for(int c=0;c<cols;++c)
        { CHECK((uint32_t)g_tileInfo[r][c].crc==reference(image,stride,r,c)); CHECK(g_tileInfo[r][c].flag==TILE_MARKED_NOT_SENT); }
        CHECK(update_tile_checksums(image,size)==0);
        for(int r=0;r<3;++r)for(int c=0;c<cols;++c)CHECK(g_tileInfo[r][c].flag==TILE_DONT_SEND);
        // Every sampled source byte, including the final byte, belongs to its
        // own tile. No adjacent-tile byte is part of the bounded row tail.
        size_t step=size/37+1;
        for(size_t i=0;i<size;i+=step)
        {
            int r=(int)(i/stride)/tile,c=(int)((i%stride)/3)/tile;
            image[i]^=1; CHECK(update_tile_checksums(image,size)==0);
            for(int rr=0;rr<3;++rr)for(int cc=0;cc<cols;++cc)
                CHECK(g_tileInfo[rr][cc].flag==((rr==r&&cc==c)?TILE_MARKED_NOT_SENT:TILE_DONT_SEND));
            image[i]^=1; update_tile_checksums(image,size);
        }
        image[size-1]^=1; CHECK(update_tile_checksums(image,size)==0);
        CHECK(g_tileInfo[2][cols-1].flag==TILE_MARKED_NOT_SENT);
        CHECK(update_tile_checksums(image,size-1)==-1);
        CHECK(update_tile_checksums(NULL,size)==-1);
        free(allocation);
    }
}
struct packets {unsigned char *data;size_t size;int count;};
static struct packets collect(unsigned char *image,size_t size,int bulk)
{
    struct packets result={0};
    for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)g_tileInfo[r][c].flag=TILE_TODO;
    if(bulk)CHECK(update_tile_checksums(image,size)==0);
    for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)
    {
        if(g_tileInfo[r][c].flag==TILE_SENT||g_tileInfo[r][c].flag==TILE_DONT_SEND)continue;
        void *packet=NULL;long long length=0;
        getTileAt(c*TILE_WIDTH,r*TILE_HEIGHT,&packet,&length,image,size,r,c);
        if(packet)
        {
            result.data=realloc(result.data,result.size+(size_t)length);
            memcpy(result.data+result.size,packet,(size_t)length);result.size+=(size_t)length;++result.count;free(packet);
        }
    }
    return result;
}
static void test_packets(void)
{
    geometry(9,4,32); SCREEN_WIDTH-=5;SCREEN_HEIGHT-=3; // padded edge tiles
    size_t size=(size_t)288*128*3;
    unsigned char *image=malloc(size),*saved=malloc(size);
    for(size_t i=0;i<size;++i)image[i]=(unsigned char)(i*29u+i/97u);
    for(int phase=0;phase<5;++phase)
    {
        struct tileInfo_t before[4][9];
        for(int r=0;r<4;++r)memcpy(before[r],g_tileInfo[r],sizeof(before[r]));
        memcpy(saved,image,size);
        struct packets scalar=collect(image,size,0);
        for(int r=0;r<4;++r)memcpy(g_tileInfo[r],before[r],sizeof(before[r]));
        struct packets bulk=collect(image,size,1);
        CHECK(scalar.count==bulk.count&&scalar.size==bulk.size);
        CHECK(!scalar.size||memcmp(scalar.data,bulk.data,scalar.size)==0);
        CHECK(memcmp(saved,image,size)==0);
        if(phase==1)CHECK(bulk.count==0);
        free(scalar.data);free(bulk.data);
        if(phase==1){image[2*3]^=127;image[size-1]^=127;}
        if(phase==2)memset(image+288*3*40,0,288*3*33);
        if(phase==3)for(int r=0;r<4;++r)for(int c=0;c<9;++c)g_tileInfo[r][c].crc=0xff;
    }
    free(image);free(saved);
}
static void test_strided_jpeg(void)
{
    const int w=37,h=19;size_t stride=157,size=stride*(h-1)+w*3;
    unsigned char *image=malloc(size+1),*src=image+1,*packed=malloc(w*h*3);
    for(size_t i=0;i<size;++i)src[i]=(unsigned char)(i*77u+i/31u);
    for(int y=0;y<h;++y)memcpy(packed+y*w*3,src+y*stride,w*3);
    for(int q=1;q<=100;q=q==1?50:100==q?101:100)
    {
        CHECK(write_JPEG_buffer(packed,w,h,q)==0);
        int length=jpeg_buffer_length;unsigned char *expected=malloc(length);memcpy(expected,jpeg_buffer,length);
        CHECK(write_JPEG_buffer_strided(src,w,h,stride,q)==0);
        CHECK(length==jpeg_buffer_length&&memcmp(expected,jpeg_buffer,length)==0);free(expected);
    }
    CHECK(write_JPEG_buffer_strided(src,w,h,w*3-1,50)==-1&&jpeg_buffer==NULL&&jpeg_buffer_length==0);
    CHECK(write_JPEG_buffer_strided(src,w,h,SIZE_MAX,50)==-1);
    CHECK(write_JPEG_buffer_strided(NULL,w,h,stride,50)==-1);
    void *packet=(void *)1;long long length=1;geometry(2,2,32);
    CHECK(calc_opt_compr_send(-1,0,32,32,src,size,&packet,&length)==-1&&packet==NULL&&length==0);
    CHECK(calc_opt_compr_send(0,0,64,64,src,1,&packet,&length)==-1&&jpeg_buffer==NULL);
    free(image);free(packed);
}
static void test_jumbo_packet(void)
{
#if JPEGMAXBUF == 0
    geometry(60,48,32);size_t size=(size_t)SCREEN_WIDTH*SCREEN_HEIGHT*3;
    unsigned char *image=malloc(size);uint32_t rng=17;
    for(size_t i=0;i<size;++i){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;image[i]=(unsigned char)rng;}
    struct packets scalar=collect(image,size,0);
    reset_tile_info(TILE_HEIGHT_COUNT);
    struct packets bulk=collect(image,size,1);
    CHECK(scalar.count==bulk.count&&scalar.size==bulk.size&&scalar.size>65535);
    CHECK(scalar.size==bulk.size&&memcmp(scalar.data,bulk.data,scalar.size)==0);
    CHECK(((unsigned)bulk.data[0]<<8|bulk.data[1])==MNG_JUMBO);
    free(scalar.data);free(bulk.data);free(image);
#endif
}
int main(void)
{
    test_hashes();test_packets();test_strided_jpeg();test_jumbo_packet();release_tiles();jpeg_encoder_cleanup();
    printf("Tile batching/strided JPEG: %d passed, %d failed\n",passed,failed);return failed!=0;
}
