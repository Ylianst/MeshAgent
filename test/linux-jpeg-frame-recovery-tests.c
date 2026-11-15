/* Test the actual Wayland tile-send boundary: retryable image failures must
 * remain distinct from a broken relay pipe, and static frames must resend. */
#define _GNU_SOURCE
#include "../meshcore/KVM/Linux/linux_kvm_drm.c"
int SCREEN_NUM, SCREEN_WIDTH=64, SCREEN_HEIGHT=64, SCREEN_DEPTH=24;
int TILE_WIDTH=32,TILE_HEIGHT=32,TILE_WIDTH_COUNT=2,TILE_HEIGHT_COUNT=2,COMPRESSION_RATIO=50;
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
static void test_direct_tile_conversion(void)
{
 const uint32_t formats[]={DRM_FORMAT_XRGB8888,DRM_FORMAT_XBGR8888,DRM_FORMAT_RGBX8888,DRM_FORMAT_BGRX8888};
 const unsigned channels[4][3]={{2,1,0},{0,1,2},{3,2,1},{1,2,3}};
 for(unsigned fmt=0;fmt<4;++fmt)for(unsigned h=33;h<=65;h+=32)
 {
  SCREEN_WIDTH=64;SCREEN_HEIGHT=h;TILE_WIDTH_COUNT=2;TILE_HEIGHT_COUNT=(h+31)/32;
  g_tileInfo=NULL;reset_tile_info(0);
  size_t rgbSize=64*h*3,pitch=64*4+12;
  unsigned char *source=malloc(pitch*h),*expected=malloc(rgbSize);
  for(size_t i=0;i<pitch*h;++i)source[i]=(unsigned char)(i*13+i/47);
  for(unsigned y=0;y<h;++y)for(unsigned x=0;x<64;++x)for(unsigned c=0;c<3;++c)
   expected[(y*64+x)*3+c]=source[y*pitch+x*4+channels[fmt][c]];
  char *desktop=NULL;long long desktopSize=0;
  FILE *reference=tmpfile(),*direct=tmpfile();CHECK(reference&&direct);
  slave2master[1]=fileno(reference);
  CHECK(kvm_drm_send_dirty_tiles(expected,rgbSize,&desktop,&desktopSize)==0);
  long length=ftell(reference);CHECK(length>8);rewind(reference);
  unsigned char *wire=malloc(length);CHECK(fread(wire,1,length,reference)==(size_t)length);
  memset(desktop,0xA7,desktopSize);
  kvm_drm_scanout_frame frame={0};frame.width=64;frame.height=h;frame.pitch=pitch;frame.format=formats[fmt];frame.modifier=DRM_FORMAT_MOD_LINEAR;
  char error[256];size_t converted=0;
  CHECK(kvm_drm_convert_to_rgb24(&frame,source,(unsigned char *)desktop,desktopSize,&converted,error,sizeof(error)));
  CHECK(converted==rgbSize&&!memcmp(desktop,expected,rgbSize));
  for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<2;++c)g_tileInfo[r][c].crc=0xff;
  slave2master[1]=fileno(direct);char *owned=desktop;
  CHECK(kvm_drm_send_dirty_tiles((unsigned char *)desktop,rgbSize,&desktop,&desktopSize)==0);
  CHECK(desktop==owned&&ftell(direct)==length);rewind(direct);
  unsigned char *actual=malloc(length);CHECK(fread(actual,1,length,direct)==(size_t)length);
  CHECK(!memcmp(wire,actual,length)); // Includes JPEG headers and zeroed bottom padding.
  free(actual);free(wire);fclose(reference);fclose(direct);free(desktop);free(source);free(expected);
  for(int r=0;r<TILE_HEIGHT_COUNT;++r){free(g_tileInfo[r]);}
  free(g_tileInfo);g_tileInfo=NULL;
 }
}
int main(void)
{
 unsigned char image[64*64*3];for(size_t i=0;i<sizeof(image);++i)image[i]=(unsigned char)(i*77);
 char *desktop=NULL;long long size=0;reset_tile_info(0);CHECK(pipe(slave2master)==0);
 packet_failure=1;CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==1);
 CHECK(g_shutdown==0&&packet_failure==0);
 CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==0);
 unsigned char wire[16384];ssize_t bytes=read(slave2master[0],wire,sizeof(wire));CHECK(bytes>8);
 CHECK(wire[0]==0&&wire[1]==MNG_KVM_PICTURE);
 /* An unchanged subsequent frame produces no packet. */
 fcntl(slave2master[0],F_SETFL,O_NONBLOCK);
 CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==0);
 CHECK(read(slave2master[0],wire,sizeof(wire))==-1&&errno==EAGAIN);
 for(int r=0;r<2;++r)for(int c=0;c<2;++c)g_tileInfo[r][c].crc=0xff;
 codec_failure=1;CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==1);
 CHECK(g_shutdown==0&&codec_failure==0);
 CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==0);
 CHECK(read(slave2master[0],wire,sizeof(wire))>8);
 close(slave2master[1]);
 for(int r=0;r<2;++r)for(int c=0;c<2;++c)g_tileInfo[r][c].crc=0xff;
 CHECK(kvm_drm_send_dirty_tiles(image,sizeof(image),&desktop,&size)==-1);
 close(slave2master[0]);free(desktop);jpeg_encoder_cleanup();
 for(int r=0;r<2;++r){free(g_tileInfo[r]);}
 free(g_tileInfo);
 g_tileInfo=NULL;test_direct_tile_conversion();jpeg_encoder_cleanup();
 printf("JPEG frame retry boundary: %d passed, %d failed\n",passed,failed);return failed!=0;
}
