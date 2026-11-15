/* Exercise the real encoder/tile implementation, including fault recovery. */
#define main tile_suite_main
#include "linux-kvm-tile-tests.c"
#undef main
static int output_allocs, output_grows, codec_creates;
static int fail_output_alloc, fail_output_grow, fail_packet, fail_codec;
void *linux_jpeg_test_malloc(size_t n)
{ ++output_allocs; if (fail_output_alloc) { fail_output_alloc=0; return NULL; } return malloc(n); }
void *linux_jpeg_test_realloc(void *p,size_t n)
{ ++output_grows; if (fail_output_grow) { fail_output_grow=0; return NULL; } return realloc(p,n); }
void *linux_tile_test_malloc(size_t n)
{ if (fail_packet) { fail_packet=0; return NULL; } return malloc(n); }
void __real_jpeg_CreateCompress(j_compress_ptr,int,size_t);
void __wrap_jpeg_CreateCompress(j_compress_ptr c,int version,size_t size)
{
    ++codec_creates;
    if (fail_codec==1) { fail_codec=0; ERREXIT(c,JERR_OUT_OF_MEMORY); }
    __real_jpeg_CreateCompress(c,version,size);
    if (fail_codec==2) { fail_codec=0; ERREXIT(c,JERR_OUT_OF_MEMORY); }
}
void __real_jpeg_start_compress(j_compress_ptr,boolean);
void __wrap_jpeg_start_compress(j_compress_ptr c,boolean tables)
{
    __real_jpeg_start_compress(c,tables);
    if (fail_codec==3) { fail_codec=0; ERREXIT(c,JERR_OUT_OF_MEMORY); }
}
JDIMENSION __real_jpeg_write_scanlines(j_compress_ptr,JSAMPARRAY,JDIMENSION);
JDIMENSION __wrap_jpeg_write_scanlines(j_compress_ptr c,JSAMPARRAY rows,JDIMENSION count)
{
    if (fail_codec==4 && c->next_scanline>=5) { fail_codec=0; ERREXIT(c,JERR_OUT_OF_MEMORY); }
    return __real_jpeg_write_scanlines(c,rows,count);
}
static void noise(unsigned char *p,size_t n)
{ uint32_t x=17; for(size_t i=0;i<n;++i){x^=x<<13;x^=x>>17;x^=x<<5;p[i]=(unsigned char)x;} }
static unsigned char *reference_jpeg(unsigned char *image,int w,int h,size_t stride,int quality,unsigned long *size)
{
    struct jpeg_compress_struct c={0};struct jpeg_error_mgr e;unsigned char *out=NULL;
    c.err=jpeg_std_error(&e);jpeg_create_compress(&c);jpeg_mem_dest(&c,&out,size);
    c.image_width=w;c.image_height=h;c.input_components=3;c.in_color_space=JCS_RGB;
    jpeg_set_defaults(&c);
    for(int i=0;i<3;++i)c.comp_info[i].h_samp_factor=c.comp_info[i].v_samp_factor=1;
    jpeg_set_quality(&c,quality,TRUE);jpeg_start_compress(&c,TRUE);
    while(c.next_scanline<c.image_height){JSAMPROW row=image+c.next_scanline*stride;jpeg_write_scanlines(&c,&row,1);}
    jpeg_finish_compress(&c);jpeg_destroy_compress(&c);return out;
}
static void verify_image(unsigned char *image,int w,int h,size_t stride,int quality)
{
    unsigned long length=0;unsigned char *expected=reference_jpeg(image,w,h,stride,quality,&length);
    CHECK(write_JPEG_buffer_strided(image,w,h,stride,quality)==0);
#if JPEGMAXBUF > 0
    if(length>JPEGMAXBUF){CHECK(jpeg_buffer==NULL&&jpeg_buffer_length>JPEGMAXBUF);free(expected);return;}
#endif
    CHECK(jpeg_buffer!=NULL&&jpeg_buffer_length==(int)length);
    if(jpeg_buffer&&jpeg_buffer_length==(int)length)CHECK(memcmp(jpeg_buffer,expected,length)==0);
    struct jpeg_decompress_struct d={0};struct jpeg_error_mgr e;d.err=jpeg_std_error(&e);
    jpeg_create_decompress(&d);jpeg_mem_src(&d,expected,length);CHECK(jpeg_read_header(&d,TRUE)==JPEG_HEADER_OK);
    CHECK(d.image_width==(unsigned)w&&d.image_height==(unsigned)h);
    for(int i=0;i<3;++i)CHECK(d.comp_info[i].h_samp_factor==1&&d.comp_info[i].v_samp_factor==1);
    jpeg_destroy_decompress(&d);free(expected);
}
static void test_reuse_and_quality(void)
{
    unsigned char image[128*128*3+128];noise(image,sizeof(image));jpeg_encoder_cleanup();
    CHECK(write_JPEG_buffer_strided(image,37,19,128,50)==0);
    int creates=codec_creates,allocs=output_allocs,grows=output_grows,length=jpeg_buffer_length;
    unsigned char *expected=malloc(length);memcpy(expected,jpeg_buffer,length);
    for(int i=0;i<100;++i){CHECK(write_JPEG_buffer_strided(image,37,19,128,50)==0);CHECK(jpeg_buffer_length==length&&memcmp(jpeg_buffer,expected,length)==0);}
    CHECK(codec_creates==creates&&output_allocs==allocs&&output_grows==grows);free(expected);
    int qualities[]={1,50,90,100,50,1};
    for(size_t i=0;i<sizeof(qualities)/sizeof(qualities[0]);++i){verify_image(image,37,19,128,qualities[i]);verify_image(image,128,128,384,qualities[i]);}
    jpeg_encoder_cleanup();jpeg_encoder_cleanup();verify_image(image,37,19,128,50);
    /* Packed compatibility retains caller ownership and identical JPEG bytes. */
    CHECK(write_JPEG_buffer(image,37,19,50)==0);free(jpeg_buffer);jpeg_buffer=NULL;
    verify_image(image,37,19,128,50);jpeg_encoder_cleanup();
}
static void test_failures(void)
{
    unsigned char image[128*128*3];noise(image,sizeof(image));
    for(int stage=1;stage<=4;++stage){
        jpeg_encoder_cleanup();fail_codec=stage;
        CHECK(write_JPEG_buffer_strided(image,128,128,384,50)==-1);
        CHECK(fail_codec==0&&jpeg_buffer==NULL&&jpeg_buffer_length==0);
        verify_image(image,37,19,384,50);
    }
    jpeg_encoder_cleanup();fail_output_alloc=1;
    CHECK(write_JPEG_buffer_strided(image,128,128,384,50)==-1&&jpeg_buffer==NULL&&jpeg_buffer_length==0);
    verify_image(image,37,19,384,50);
    jpeg_encoder_cleanup();fail_output_grow=1;
    CHECK(write_JPEG_buffer_strided(image,128,128,384,100)==-1&&jpeg_buffer==NULL&&jpeg_buffer_length==0);
    CHECK(fail_output_grow==0);verify_image(image,37,19,384,50);
    /* A packet allocation failure after checksum update must resend the SAME
     * image on retry, including tiles already processed before the failure. */
    geometry(4,4,32);CHECK(update_tile_checksums(image,sizeof(image))==0);
    void *packet=(void*)1;long long size=1;fail_packet=1;
    CHECK(getTileAt(0,0,&packet,&size,image,sizeof(image),0,0)==-1&&packet==NULL&&size==0);
    for(int r=0;r<4;++r)for(int c=0;c<4;++c)CHECK(g_tileInfo[r][c].crc==0xff);
    struct packets retry=collect(image,sizeof(image),1);CHECK(retry.count>0&&retry.size>0);
    unsigned char *saved=malloc(retry.size);memcpy(saved,retry.data,retry.size);
    verify_image(image,37,19,384,90);CHECK(memcmp(saved,retry.data,retry.size)==0);
    free(saved);free(retry.data);
    /* Codec failure after checksum publication has the same retry requirement. */
    reset_tile_info(TILE_HEIGHT_COUNT);CHECK(update_tile_checksums(image,sizeof(image))==0);fail_codec=4;
    CHECK(getTileAt(0,0,&packet,&size,image,sizeof(image),0,0)==-1&&packet==NULL&&size==0);
    retry=collect(image,sizeof(image),1);CHECK(retry.count>0);free(retry.data);
    release_tiles();jpeg_encoder_cleanup();
}
static void test_large_buffer_retention(void)
{
#if JPEGMAXBUF == 0
    size_t n=1536u*1536u*3u;unsigned char *image=malloc(n);noise(image,n);
    CHECK(write_JPEG_buffer_strided(image,1536,1536,1536*3,100)==0&&jpeg_buffer_length>4*1024*1024);
    jpeg_discard_output();int allocs=output_allocs;
    CHECK(write_JPEG_buffer_strided(image,32,32,1536*3,50)==0&&output_allocs==allocs+1);
    free(image);jpeg_encoder_cleanup();
#endif
}
int main(void)
{
    test_reuse_and_quality();test_failures();test_large_buffer_retention();
    printf("JPEG reuse/recovery: %d passed, %d failed\n",passed,failed);return failed!=0;
}
