// Windows native regression tests. Build with test\windows-kvm-tests.cmd.
#define WIN32_LEAN_AND_MEAN
#define _LINKVM
#include <winsock2.h>
#include <windows.h>
#include <objidl.h>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <chrono>
#include "microstack/ILibCrypto.h"
#include "meshcore/meshdefines.h"
// Exercise production tile code with only logging/packet allocation isolated.
#undef ILibMemory_Allocate
#define ILibMemory_Allocate(a,b,c,d) malloc(a)
#undef ILibCriticalLog
#define ILibCriticalLog(a,b,c,d,e) ((void)0)

// Inject an input-desktop change at either identity check without changing the host desktop.
static int desktopChecks, mismatchAt;
static HDESK WINAPI testOpenInputDesktop(DWORD flags,BOOL inherit,ACCESS_MASK access)
{ return mismatchAt && ++desktopChecks == mismatchAt ? (HDESK)(uintptr_t)0x41 : OpenInputDesktop(flags,inherit,access); }
static BOOL WINAPI testGetUserObjectInformationW(HANDLE object,int index,PVOID output,DWORD size,LPDWORD needed)
{
 if(object!=(HANDLE)(uintptr_t)0x41)return GetUserObjectInformationW(object,index,output,size,needed);
 const WCHAR name[]=L"Winlogon";if(needed)*needed=sizeof(name);if(size<sizeof(name))return FALSE;memcpy(output,name,sizeof(name));return TRUE;
}
static BOOL WINAPI testCloseDesktop(HDESK desktop){return desktop==(HDESK)(uintptr_t)0x41?TRUE:CloseDesktop(desktop);}
static bool failCursorIcon;
static BOOL WINAPI testGetIconInfo(HICON icon,PICONINFO output){return failCursorIcon?FALSE:GetIconInfo(icon,output);}
#define GetIconInfo testGetIconInfo
#define OpenInputDesktop testOpenInputDesktop
#define GetUserObjectInformationW testGetUserObjectInformationW
#define CloseDesktop testCloseDesktop

static bool failJpegAllocation, failJpegGrowth;
enum EncoderFault { NoFault, CreateFault, SaveFault, EndSeekFault, StartSeekFault, ReadFault, ShortReadFault, PacketFault };
static EncoderFault encoderFault;
static int liveEncoderStreams;
class FaultStream : public IStream {
 IStream* inner;ULONG refs=1;
 public:explicit FaultStream(IStream* stream):inner(stream){++liveEncoderStreams;}
 ~FaultStream(){inner->Release();--liveEncoderStreams;}
 HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** out){if(id==IID_IUnknown||id==IID_ISequentialStream||id==IID_IStream){*out=this;AddRef();return S_OK;}*out=NULL;return E_NOINTERFACE;}
 ULONG STDMETHODCALLTYPE AddRef(){return ++refs;}
 ULONG STDMETHODCALLTYPE Release(){ULONG n=--refs;if(!n)delete this;return n;}
 HRESULT STDMETHODCALLTYPE Read(void* p,ULONG n,ULONG* read){if(encoderFault==ReadFault)return E_FAIL;if(encoderFault==ShortReadFault&&n)return inner->Read(p,n-1,read);return inner->Read(p,n,read);}
 HRESULT STDMETHODCALLTYPE Write(const void* p,ULONG n,ULONG* written){if(encoderFault==SaveFault)return STG_E_WRITEFAULT;return inner->Write(p,n,written);}
 HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER move,DWORD origin,ULARGE_INTEGER* pos){if((origin==STREAM_SEEK_END&&encoderFault==EndSeekFault)||(origin==STREAM_SEEK_SET&&encoderFault==StartSeekFault))return STG_E_SEEKERROR;return inner->Seek(move,origin,pos);}
 HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER size){return inner->SetSize(size);}
 HRESULT STDMETHODCALLTYPE CopyTo(IStream* out,ULARGE_INTEGER n,ULARGE_INTEGER* read,ULARGE_INTEGER* written){return inner->CopyTo(out,n,read,written);}
 HRESULT STDMETHODCALLTYPE Commit(DWORD flags){return inner->Commit(flags);}
 HRESULT STDMETHODCALLTYPE Revert(){return inner->Revert();}
 HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER offset,ULARGE_INTEGER n,DWORD type){return inner->LockRegion(offset,n,type);}
 HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER offset,ULARGE_INTEGER n,DWORD type){return inner->UnlockRegion(offset,n,type);}
 HRESULT STDMETHODCALLTYPE Stat(STATSTG* stat,DWORD flags){return inner->Stat(stat,flags);}
 HRESULT STDMETHODCALLTYPE Clone(IStream** stream){return inner->Clone(stream);}
};
static HRESULT testCreateStreamOnHGlobal(HGLOBAL memory,BOOL release,IStream** stream)
{ if(encoderFault==CreateFault){*stream=NULL;return E_OUTOFMEMORY;}HRESULT result=CreateStreamOnHGlobal(memory,release,stream);if(SUCCEEDED(result)&&encoderFault!=NoFault)*stream=new FaultStream(*stream);return result; }
static void* testPacketMalloc(size_t size){return encoderFault==PacketFault?NULL:malloc(size);}
#define CreateStreamOnHGlobal testCreateStreamOnHGlobal
static void* testJpegMalloc(size_t size) { return failJpegAllocation ? NULL : malloc(size); }
static void* testJpegRealloc(void* p,size_t size) { return failJpegGrowth ? NULL : realloc(p,size); }
#define MESH_JPEG_MALLOC testJpegMalloc
#define MESH_JPEG_REALLOC testJpegRealloc
#define malloc testPacketMalloc
#include "meshcore/KVM/Windows/tile.cpp"
#undef malloc
extern "C" {
int TILE_WIDTH=32,TILE_HEIGHT=32,SCREEN_WIDTH,SCREEN_HEIGHT,SCREEN_X,SCREEN_Y;
int SCALED_WIDTH,SCALED_HEIGHT,PIXEL_SIZE=4,TILE_WIDTH_COUNT,TILE_HEIGHT_COUNT;
int COMPRESSION_RATIO,SCALING_FACTOR,SCALING_FACTOR_NEW,FRAME_RATE_TIMER;
tileInfo_t** tileInfo;
}
int __fastcall util_crc(unsigned char* data,int len,int initial){unsigned int h=(unsigned int)initial;for(int i=0;i+3<len;i+=4){unsigned int word;memcpy(&word,data+i,4);h=(h*0x01000193u)^word;}return(int)h;}
static int checks;
static void check_requirement(bool ok,int line){++checks;if(!ok){fprintf(stderr,"failed at line %d\n",line);throw std::runtime_error("Windows KVM regression failed");}}
#define require(ok) check_requirement((ok),__LINE__)
static void hash_tests(int w,int h){
 SCALED_WIDTH=w;SCALED_HEIGHT=h;int pw=adjust_screen_size(w),ph=adjust_screen_size(h);
 TILE_WIDTH_COUNT=pw/32;TILE_HEIGHT_COUNT=ph/32;
 std::vector<unsigned int> pixels((size_t)pw*ph);for(size_t i=0;i<pixels.size();++i)pixels[i]=(unsigned int)(i*2654435761u);
 std::vector<std::vector<tileInfo_t>> rows(TILE_HEIGHT_COUNT,std::vector<tileInfo_t>(TILE_WIDTH_COUNT));
 std::vector<tileInfo_t*> refs;for(auto& r:rows)refs.push_back(r.data());tileInfo=refs.data();
 prepare_tile_checksums(pixels.data());
 for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)require(tileInfo[r][c].crc==tile_crc(c*32,r*32,pixels.data(),32,32));
 // This unit test starts its next checksum pass after the fixture frame was delivered.
 for(auto& r:rows)for(auto& t:r)t.pending=0;
 prepare_tile_checksums(pixels.data());for(auto& r:rows)for(auto& t:r)require(t.flags==TILE_DONT_SEND);
 // Mutate top-left visible pixel and check bottom-up row selection, including batch tails.
 pixels[(size_t)(ph-1)*pw]^=0x12345678;prepare_tile_checksums(pixels.data());require(rows[0][0].flags==TILE_MARKED_NOT_SENT);
 for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c)if(r||c)require(rows[r][c].flags==TILE_DONT_SEND);
 tileInfo=NULL;
}
static std::vector<BYTE> old_encode(int w,int h,const void* data){
 BITMAPINFO bi=get_bmp_info(w,h);BITMAPFILEHEADER fh={};fh.bfType=0x4d42;fh.bfOffBits=sizeof(fh)+sizeof(BITMAPINFOHEADER);fh.bfSize=fh.bfOffBits+bi.bmiHeader.biSizeImage;
 IStream *bmp=NULL,*encoded=NULL;require(CreateStreamOnHGlobal(NULL,TRUE,&bmp)==S_OK);require(CreateStreamOnHGlobal(NULL,TRUE,&encoded)==S_OK);
 bmp->Write(&fh,sizeof(fh),NULL);bmp->Write(&bi,sizeof(BITMAPINFOHEADER),NULL);bmp->Write(data,bi.bmiHeader.biSizeImage,NULL);LARGE_INTEGER zero={};bmp->Seek(zero,STREAM_SEEK_SET,NULL);
 Image* image=Image::FromStream(bmp);require(image&&image->GetLastStatus()==Ok);require(image->Save(encoded,&encoderClsid,&encParam)==Ok);
 STATSTG st={};encoded->Stat(&st,STATFLAG_NONAME);HGLOBAL mem;GetHGlobalFromStream(encoded,&mem);BYTE* bytes=(BYTE*)GlobalLock(mem);std::vector<BYTE> result(bytes,bytes+(size_t)st.cbSize.QuadPart);GlobalUnlock(mem);delete image;encoded->Release();bmp->Release();return result;
}
static void encoding_tests(int type){
 set_tile_compression(type,50);
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false;
#endif

 SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;
 std::vector<BYTE> pixels(160*96*4);for(size_t i=0;i<pixels.size();++i)pixels[i]=(BYTE)(i*13+i/73);
 for(int x:{0,32,96})for(int y:{0,32}){
  int w=64,h=64;std::vector<BYTE> crop(w*h*4);void* target=crop.data();unsigned int saved=tilebuffersize;tilebuffersize=(unsigned int)crop.size();get_tile_buffer(x,y,&target,pixels.data(),w,h);tilebuffersize=saved;
  auto expected=old_encode(w,h,crop.data());void* packet=NULL;long long bytes=0;calc_opt_compr_send(x,y,w,h,pixels.data(),&packet,&bytes);require(packet!=NULL);int offset=bytes>65508?16:8;require((size_t)(bytes-offset)==expected.size());require(!memcmp((BYTE*)packet+offset,expected.data(),expected.size()));free(packet);
 }
}
static std::vector<std::vector<BYTE>> collect_tiles(void* pixels, bool batch){
 if(batch)prepare_tile_checksums(pixels);std::vector<std::vector<BYTE>> packets;
 for(int r=0;r<TILE_HEIGHT_COUNT;++r)for(int c=0;c<TILE_WIDTH_COUNT;++c){
  if(tileInfo[r][c].flags==TILE_SENT||tileInfo[r][c].flags==TILE_DONT_SEND)continue;
  void* packet=NULL;long long size=0;int result=get_tile_at(c*32,r*32,&packet,&size,pixels,r,c);
  if(result<0)return packets; // Match the worker: retry next frame, not in a tight loop.
  if(packet){packets.emplace_back((BYTE*)packet,(BYTE*)packet+size);free(packet);}
 }return packets;
}
static void encoding_recovery_tests(){
 require(sizeof(tileInfo_t)==8); // The persistent bit occupies existing padding.
 for(bool initial:{false,true})for(bool batch:{false,true})for(bool fast:{false,true})for(bool sparse:{false,true})for(int fault=CreateFault;fault<=PacketFault;++fault){
  SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;TILE_WIDTH_COUNT=5;TILE_HEIGHT_COUNT=3;set_tile_compression(1,50);
  useCaptureDamage=false;useFastJpeg=fast;fastJpeg.Reset();
  std::vector<unsigned> pixels(160*96);for(size_t i=0;i<pixels.size();++i)pixels[i]=(unsigned)(i*2654435761u);
  std::vector<std::vector<tileInfo_t>> rows(3,std::vector<tileInfo_t>(5));std::vector<tileInfo_t*> refs;
  for(auto& row:rows)refs.push_back(row.data());tileInfo=refs.data();
  if(initial){for(auto& row:rows)for(auto& tile:row)tile.pending=1;}
  else {
   // Separate changes make a successful first packet precede a failed packet.
   collect_tiles(pixels.data(),true);
   pixels[160*95]^=0x234567;pixels[160*95+128]^=0x345678;
   prepare_tile_checksums(pixels.data());
   void* first=NULL;long long firstSize=0;require(get_tile_at(0,0,&first,&firstSize,pixels.data(),0,0)==0&&first);free(first);
  }
  LONG revision=captureRevision;
  encoderFault=(EncoderFault)fault;failJpegAllocation=fast;
  for(auto& row:rows)for(auto& tile:row)tile.flags=TILE_TODO;
  auto failed=collect_tiles(pixels.data(),batch);require(failed.empty());require(captureRevision!=revision);
  require(rows[0][4].pending&&liveEncoderStreams==0);
  // Repeated failures retain the retry without marking the image delivered.
  for(auto& row:rows)for(auto& tile:row)tile.flags=TILE_TODO;
  require(collect_tiles(pixels.data(),batch).empty());require(rows[0][4].pending&&liveEncoderStreams==0);
  encoderFault=NoFault;failJpegAllocation=false;
  if(sparse){desktopDuplication.damage.Begin(160,96,32,32,false);useCaptureDamage=true;}
  for(auto& row:rows)for(auto& tile:row)tile.flags=TILE_TODO;
  auto retry=collect_tiles(pixels.data(),batch);require(retry.size()==1); // Static image, even with empty damage.
  for(auto& row:rows)for(auto& tile:row)require(!tile.pending);
  for(auto& row:rows)for(auto& tile:row)tile.flags=TILE_TODO;
  require(collect_tiles(pixels.data(),batch).empty()); // No perpetual full refresh after success.
  useCaptureDamage=false;desktopDuplication.damage.Clear();tileInfo=NULL;
 }
 useFastJpeg=false;
}
static void coalescing_tests(){
 SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;TILE_WIDTH_COUNT=5;TILE_HEIGHT_COUNT=3;set_tile_compression(1,50);
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false;
#endif

 std::vector<unsigned int> pixels(160*96);for(size_t i=0;i<pixels.size();++i)pixels[i]=(unsigned int)(i*2654435761u);
 std::vector<std::vector<tileInfo_t>> initial(3,std::vector<tileInfo_t>(5));
 for(int r=0;r<3;++r)for(int c=0;c<5;++c)initial[r][c].crc=tile_crc(c*32,r*32,pixels.data(),32,32);
 for(int scenario=0;scenario<4;++scenario){
  auto scalar=initial,batched=initial;
  if(scenario==1)pixels[160*95]^=0x123456;
  if(scenario==2)for(size_t i=0;i<pixels.size();i+=17)pixels[i]^=0x234567;
  if(scenario==3)for(int r=0;r<3;++r)for(int c=0;c<5;++c)scalar[r][c].crc=batched[r][c].crc=0xff;
  std::vector<tileInfo_t*> refs(3);for(int r=0;r<3;++r)refs[r]=scalar[r].data();tileInfo=refs.data();
  auto expected=collect_tiles(pixels.data(),false);for(int r=0;r<3;++r)refs[r]=batched[r].data();auto actual=collect_tiles(pixels.data(),true);
  require(actual==expected);if(scenario==0)require(actual.empty());else require(!actual.empty());
 }tileInfo=NULL;
}

static void damage_packet_tests(){
 SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;TILE_WIDTH_COUNT=5;TILE_HEIGHT_COUNT=3;set_tile_compression(1,50);
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false;
#endif

 std::vector<unsigned int> pixels(160*96);for(size_t i=0;i<pixels.size();++i)pixels[i]=(unsigned int)(i*2654435761u);
 std::vector<std::vector<tileInfo_t>> initial(3,std::vector<tileInfo_t>(5));
 for(int r=0;r<3;++r)for(int c=0;c<5;++c)initial[r][c].crc=tile_crc(c*32,r*32,pixels.data(),32,32);
 pixels[160*95+159]^=0x123456;
 auto scalar=initial,damaged=initial;std::vector<tileInfo_t*> refs(3);for(int r=0;r<3;++r)refs[r]=scalar[r].data();tileInfo=refs.data();
 useCaptureDamage=false;auto expected=collect_tiles(pixels.data(),false);
 for(int r=0;r<3;++r)refs[r]=damaged[r].data();
 desktopDuplication.damage.Begin(160,96,32,32,false);RECT rect={159,0,160,1};desktopDuplication.damage.Mark(rect,160,96);useCaptureDamage=true;
 auto actual=collect_tiles(pixels.data(),true);require(actual==expected&&!actual.empty());
 useCaptureDamage=false;desktopDuplication.damage.Clear();tileInfo=NULL;
}
static void sparse_checksum_tests(){
 bool supported=checksum_crc_available();
 for(bool crc:{false,true}){if(crc&&!supported)continue;useChecksumCrc=crc;
  SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;TILE_WIDTH_COUNT=5;TILE_HEIGHT_COUNT=3;
  std::vector<unsigned> pixels(160*96,0x18273645);
  std::vector<std::vector<tileInfo_t>> rows(3,std::vector<tileInfo_t>(5));std::vector<tileInfo_t*> refs;
  for(auto& row:rows)refs.push_back(row.data());tileInfo=refs.data();useCaptureDamage=false;prepare_tile_checksums(pixels.data());
  for(auto& row:rows)for(auto& tile:row)tile.pending=0; // Previous fixture image delivered.
  for(int c=0;c<5;++c){
   pixels[160*95+c*32]^=0x234567;
   auto before=rows;desktopDuplication.damage.Begin(160,96,32,32,false);RECT rect={c*32,0,c*32+1,1};
   desktopDuplication.damage.Mark(rect,160,96);useCaptureDamage=true;prepare_tile_checksums(pixels.data());
   for(int r=0;r<3;++r)for(int x=0;x<5;++x){
    require(rows[r][x].crc==tile_crc(x*32,r*32,pixels.data(),32,32));
    require(rows[r][x].flags==(r==0&&x==c?TILE_MARKED_NOT_SENT:TILE_DONT_SEND));
    if(r!=0||x!=c)require(rows[r][x].crc==before[r][x].crc);
   }
   for(auto& row:rows)for(auto& tile:row)tile.pending=0;
  }
 }useChecksumCrc=supported;useCaptureDamage=false;desktopDuplication.damage.Clear();tileInfo=NULL;
}
static bool tileSourceFirst;
static int tileSourceDestructions;
class TileSource : public WinDDSource {
 std::vector<BYTE> pixels;
 public:TileSource():pixels(97*65*4,123){}~TileSource(){++tileSourceDestructions;}
 HRESULT Acquire(DXGI_OUTDUPL_FRAME_INFO& info){if(!tileSourceFirst)return DXGI_ERROR_WAIT_TIMEOUT;tileSourceFirst=false;info.PointerPosition.Visible=TRUE;info.LastMouseUpdateTime.QuadPart=1;return S_OK;}
 HRESULT Damage(std::vector<RECT>&,std::vector<DXGI_OUTDUPL_MOVE_RECT>&){return S_FALSE;}
 HRESULT Readback(bool,bool,const BYTE*& data,UINT& pitch){data=pixels.data();pitch=97*4;return S_OK;}
 void Unmap(){}HRESULT ReleaseFrame(){return S_OK;}HRESULT Health(){return S_OK;}
};
static HRESULT tileFactory(const RECT&,WinDDSource** result){*result=new TileSource();return S_OK;}
static void desktop_identity_tests(){
 SCREEN_WIDTH=SCALED_WIDTH=97;SCREEN_HEIGHT=SCALED_HEIGHT=65;SCREEN_X=SCREEN_Y=0;SCALING_FACTOR=1024;
 void* pixels=NULL;long long size=0;long mouse[3]={};
 for(int when=1;when<=2;++when){
  reset_capture_buffer();desktopChecks=0;mismatchAt=when;
  require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FAILED);require(!pixels&&!size&&!capturePixels&&!hCapturedBitmap);
 }
 mismatchAt=desktopChecks=0;
 desktopDuplication=WinDesktopDuplication(tileFactory);tileSourceFirst=true;
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);require(lastWasDuplication);
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_UNCHANGED);require(!pixels&&!size);
 // Refresh must return a full private snapshot even without a new DXGI frame.
 invalidate_desktop_capture();require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);
 for(size_t i=0;i<desktopDuplication.damage.tiles.size();++i)require(desktopDuplication.damage.tiles[i]==1);
 // A failed encode must wake the real cached-snapshot path without a new frame.
 TILE_WIDTH_COUNT=4;TILE_HEIGHT_COUNT=3;set_tile_compression(1,50);useFastJpeg=false;
 std::vector<std::vector<tileInfo_t>> retryRows(3,std::vector<tileInfo_t>(4));std::vector<tileInfo_t*> retryRefs;
 for(auto& row:retryRows)retryRefs.push_back(row.data());tileInfo=retryRefs.data();
 encoderFault=CreateFault;void* packet=NULL;long long packetSize=0;
 prepare_tile_checksums(pixels);require(get_tile_at(0,0,&packet,&packetSize,pixels,0,0)<0);require(!packet&&!packetSize);
 encoderFault=NoFault;require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);
 require(!collect_tiles(pixels,true).empty());require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_UNCHANGED);
 tileInfo=NULL;
 // A transient cursor failure must retry the cached private surface, rather than freeze it.
 failCursorIcon=true;mouse[0]=1;
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);require(!captureCursorValid);
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);require(!captureCursorValid);
 failCursorIcon=false;mouse[0]=0;
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FRAME);require(captureCursorValid);
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_UNCHANGED);
 desktopChecks=0;mismatchAt=2;
 require(get_desktop_buffer(&pixels,&size,mouse)==WIN_CAPTURE_FAILED);require(!pixels&&!size&&!capturePixels&&!hCapturedBitmap);require(tileSourceDestructions==1);
 mismatchAt=desktopChecks=0;desktopDuplication=WinDesktopDuplication();
}

static void strided_encoding_tests(){
 for(int type:{1,2,3})for(auto size:std::vector<std::pair<int,int>>{{1919,1079},{3840,2160}}){
  SCALED_WIDTH=size.first;SCALED_HEIGHT=size.second;PIXEL_SIZE=4;set_tile_compression(type,50);
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false;
#endif

  int pw=adjust_screen_size(SCALED_WIDTH),ph=adjust_screen_size(SCALED_HEIGHT);
  std::vector<BYTE> pixels((size_t)pw*ph*4);for(size_t i=0;i<pixels.size();++i)pixels[i]=(BYTE)(i*17+i/71);
  auto original=pixels;
  for(auto corner:std::vector<std::pair<int,int>>{{0,0},{32,32},{pw-64,ph-64}}){
   int x=corner.first,y=corner.second;std::vector<BYTE> crop(64*64*4);void* out=crop.data();unsigned saved=tilebuffersize;tilebuffersize=(unsigned)crop.size();get_tile_buffer(x,y,&out,pixels.data(),64,64);tilebuffersize=saved;
   auto expected=old_encode(64,64,crop.data());void* packet=NULL;long long bytes=0;calc_opt_compr_send(x,y,64,64,pixels.data(),&packet,&bytes);
   require(packet!=NULL);int offset=bytes>65508?16:8;require(bytes-offset==(long long)expected.size());require(!memcmp((BYTE*)packet+offset,expected.data(),expected.size()));free(packet);require(pixels==original);require(!tilebuffer&&!tilebuffersize);
  }
  for(auto bad:std::vector<std::pair<int,int>>{{-1,0},{0,-1},{pw-63,0},{0,ph-63},{INT_MAX,INT_MAX}}){
   void* packet=(void*)1;long long bytes=1;calc_opt_compr_send(bad.first,bad.second,64,64,pixels.data(),&packet,&bytes);require(!packet&&!bytes);
  }
 }
}

static void jumbo_tests(){
 SCALED_WIDTH=SCALED_HEIGHT=512;PIXEL_SIZE=4;std::vector<BYTE> pixels(512*512*4);unsigned int random=123;
 for(size_t i=0;i<pixels.size();++i){random^=random<<13;random^=random>>17;random^=random<<5;pixels[i]=(BYTE)random;}
 for(int type:{1,2,3}){set_tile_compression(type,50);
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false;
#endif
auto expected=old_encode(512,512,pixels.data());void* packet=NULL;long long size=0;calc_opt_compr_send(0,0,512,512,pixels.data(),&packet,&size);require(packet!=NULL);require(expected.size()>65500);require(size==(long long)expected.size()+16);require(ntohs(((unsigned short*)packet)[0])==MNG_JUMBO);require(ntohl(((unsigned int*)packet)[1])==expected.size()+8);require(!memcmp((BYTE*)packet+16,expected.data(),expected.size()));free(packet);}
}
static void capture_tests(){
 SCREEN_WIDTH=SCALED_WIDTH=97;SCREEN_HEIGHT=SCALED_HEIGHT=65;SCREEN_X=SCREEN_Y=0;SCALING_FACTOR=1024;
 void* pixels=NULL;long long bytes=0;long mouse[3]={};require(get_desktop_buffer(&pixels,&bytes,mouse)==0);require(bytes==128*96*4);HBITMAP first=hCapturedBitmap;void* firstPixels=pixels;
 require(get_desktop_buffer(&pixels,&bytes,mouse)==0);require(hCapturedBitmap==first&&pixels==firstPixels);
 SCALING_FACTOR=512;SCALED_WIDTH=48;SCALED_HEIGHT=32;require(get_desktop_buffer(&pixels,&bytes,mouse)==0);require(bytes==64*32*4);
 SCREEN_X=10;require(get_desktop_buffer(&pixels,&bytes,mouse)==0);require(captureSourceX==10);
 SCALED_WIDTH=0;require(get_desktop_buffer(&pixels,&bytes,mouse)==1);require(pixels==NULL&&bytes==0&&capturePixels==NULL&&hCapturedBitmap==NULL);
 reset_capture_buffer();reset_capture_buffer();
}

static unsigned reference_crc(const BYTE* bytes,size_t count,unsigned initial){
 unsigned c=initial;for(size_t i=0;i<count;++i){c^=bytes[i];for(int b=0;b<8;++b)c=(c>>1)^((c&1)?0x82f63b78u:0);}return c;
}
static void checksum_reference_tests(){
 bool supported=checksum_crc_available();
 for(bool crc:{false,true}){if(crc&&!supported)continue;useChecksumCrc=crc;
  SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;
  std::vector<BYTE> pixels(160*96*4);unsigned state=91;for(auto& b:pixels){state^=state<<13;state^=state>>17;state^=state<<5;b=(BYTE)state;}
  for(int width:{1,3,31,32,33})for(int height:{1,7,32}){
   unsigned expected=0;for(int y=96-32-height;y<96-32;++y){auto row=pixels.data()+((size_t)y*160+32)*4;expected=crc?reference_crc(row,width*4,expected):(unsigned)util_crc(row,width*4,expected);}
   require((unsigned)tile_crc(32,32,pixels.data(),width,height)==expected);
  }
 }
 useChecksumCrc=supported;
}
#ifdef MESH_WINDOWS_TURBOJPEG
static std::vector<BYTE> decode_jpeg(const BYTE* source,size_t size,int w,int h, jpeg_decompress_struct* header=NULL){
 jpeg_decompress_struct c={};jpeg_error_mgr error;c.err=jpeg_std_error(&error);jpeg_create_decompress(&c);jpeg_mem_src(&c,source,(unsigned long)size);require(jpeg_read_header(&c,TRUE)==JPEG_HEADER_OK);require(c.image_width==(unsigned)w&&c.image_height==(unsigned)h);
 require(c.comp_info[0].h_samp_factor==2&&c.comp_info[0].v_samp_factor==2);require(c.comp_info[1].h_samp_factor==1&&c.comp_info[1].v_samp_factor==1);
 c.out_color_space=JCS_RGB;jpeg_start_decompress(&c);std::vector<BYTE> rgb((size_t)w*h*3);while(c.output_scanline<c.output_height){JSAMPROW row=rgb.data()+(size_t)c.output_scanline*w*3;jpeg_read_scanlines(&c,&row,1);}jpeg_finish_decompress(&c);jpeg_destroy_decompress(&c);return rgb;
}
static void jpeg_fast_tests(){
 SCALED_WIDTH=160;SCALED_HEIGHT=96;PIXEL_SIZE=4;std::vector<BYTE> pixels(160*96*4);
 for(int y=0;y<96;++y)for(int x=0;x<160;++x){size_t i=((size_t)y*160+x)*4;pixels[i]=x;pixels[i+1]=y*2;pixels[i+2]=x+y;pixels[i+3]=(BYTE)(x^y);}
 auto original=pixels;
 for(int quality:{1,40,50,90})for(auto corner:std::vector<std::pair<int,int>>{{0,0},{32,32},{96,32}}){
  set_tile_compression(1,quality);require(useFastJpeg);int x=corner.first,y=corner.second;
  std::vector<BYTE> crop(64*64*4);void* target=crop.data();tilebuffersize=(unsigned)crop.size();get_tile_buffer(x,y,&target,pixels.data(),64,64);tilebuffersize=0;
  auto reference=old_encode(64,64,crop.data());auto oldRgb=decode_jpeg(reference.data(),reference.size(),64,64);
  void* packet=NULL;long long size=0;calc_opt_compr_send(x,y,64,64,pixels.data(),&packet,&size);require(packet&&size>8);require(ntohs(((unsigned short*)packet)[0])==MNG_KVM_PICTURE);require(ntohs(((unsigned short*)packet)[2])==x&&ntohs(((unsigned short*)packet)[3])==y);
  auto rgb=decode_jpeg((BYTE*)packet+8,(size_t)size-8,64,64);free(packet);
  size_t difference=0;for(size_t i=0;i<rgb.size();++i)difference+=abs((int)rgb[i]-(int)oldRgb[i]);require((double)difference/rgb.size()<2.0);require(pixels==original);require(!fastJpeg.packet);
  // Compare quantization tables: requested quality must not silently decrease.
  jpeg_decompress_struct a={},b={};jpeg_error_mgr ea,eb;a.err=jpeg_std_error(&ea);b.err=jpeg_std_error(&eb);jpeg_create_decompress(&a);jpeg_create_decompress(&b);
  jpeg_mem_src(&a,reference.data(),(unsigned long)reference.size());jpeg_read_header(&a,TRUE);
  calc_opt_compr_send(x,y,64,64,pixels.data(),&packet,&size);jpeg_mem_src(&b,(BYTE*)packet+8,(unsigned long)size-8);jpeg_read_header(&b,TRUE);
  for(int table=0;table<2;++table)for(int k=0;k<64;++k)require(b.quant_tbl_ptrs[table]->quantval[k]<=a.quant_tbl_ptrs[table]->quantval[k]);
  jpeg_destroy_decompress(&a);jpeg_destroy_decompress(&b);free(packet);
 }
 // Allocation and growth failures fall back to the existing encoder and can recover.
 for(bool growth:{false,true}){
  SCALED_WIDTH=SCALED_HEIGHT=512;pixels.resize(512*512*4);unsigned random=123;for(auto& v:pixels){random^=random<<13;random^=random>>17;random^=random<<5;v=(BYTE)random;}
  set_tile_compression(1,50);auto expected=old_encode(512,512,pixels.data());failJpegAllocation=!growth;failJpegGrowth=growth;
  void* packet=NULL;long long size=0;calc_opt_compr_send(0,0,512,512,pixels.data(),&packet,&size);require(packet&&size==(long long)expected.size()+16);require(!memcmp((BYTE*)packet+16,expected.data(),expected.size()));require(!fastJpeg.codec.mem&&!fastJpeg.packet);free(packet);
  failJpegAllocation=failJpegGrowth=false;calc_opt_compr_send(0,0,512,512,pixels.data(),&packet,&size);require(packet&&size>65516);require(ntohs(((unsigned short*)packet)[0])==MNG_JUMBO);require(ntohl(((unsigned int*)packet)[1])==size-8);decode_jpeg((BYTE*)packet+16,(size_t)size-16,512,512);free(packet);
 }
 set_tile_compression(2,50);require(!useFastJpeg);set_tile_compression(3,50);require(!useFastJpeg);set_tile_compression(99,50);require(!useFastJpeg);set_tile_compression(1,50);require(useFastJpeg);
 reset_capture_buffer();require(!fastJpeg.codec.mem&&!fastJpeg.packet);
}
#endif

#ifdef MESH_WINDOWS_TURBOJPEG
static void jpeg_configuration_tests(){
 WinJpegEncoder reused;
 for(int round=0;round<2;++round)for(int quality:{1,50,50,90,20,50})for(auto d:std::vector<std::pair<int,int>>{{1,1},{37,19},{256,192}}){
  int stride=d.first*4+12;std::vector<BYTE> pixels((size_t)stride*d.second);
  for(size_t i=0;i<pixels.size();++i)pixels[i]=(BYTE)(i*37+i/19);
  auto original=pixels;WinJpegEncoder fresh;void *actual=NULL,*expected=NULL;unsigned long a=0,b=0;
  const BYTE* top=pixels.data()+(size_t)(d.second-1)*stride;
  require(reused.Encode(top,d.first,d.second,stride,quality,&actual,&a));
  require(fresh.Encode(top,d.first,d.second,stride,quality,&expected,&b));
  require(a==b&&!memcmp((BYTE*)actual+16,(BYTE*)expected+16,a));require(pixels==original);
  free(actual);free(expected);
 }
 reused.Reset();
 // A failed destination allocation destroys configuration; the next image must
 // be independently decodable and identical to a fresh encoder again.
 BYTE pixel[4]={23,57,91,0};void* output=NULL;unsigned long size=0;failJpegAllocation=true;
 require(!reused.Encode(pixel,1,1,4,50,&output,&size));failJpegAllocation=false;
 require(reused.Encode(pixel,1,1,4,50,&output,&size));decode_jpeg((BYTE*)output+16,size,1,1);free(output);
 printf("PASS: Windows reused JPEG configuration matches fresh encoders\n");
}
static void encoder_bench(){
 set_tile_compression(1,50);PIXEL_SIZE=4;
 for(auto d:std::vector<std::pair<int,int>>{{64,64},{256,192},{1920,1080},{3840,2160}}){
  SCALED_WIDTH=d.first;SCALED_HEIGHT=d.second;int pw=adjust_screen_size(d.first),ph=adjust_screen_size(d.second);
  std::vector<BYTE> pixels((size_t)pw*ph*4);for(int y=0;y<ph;++y)for(int x=0;x<pw;++x){auto p=&pixels[((size_t)y*pw+x)*4];p[0]=(BYTE)(x/7+y/9);p[1]=(BYTE)(x/13+y/3);p[2]=(BYTE)((x^y)/5);p[3]=0;}
  auto original=pixels;
  for(bool fast:{false,true}){
   useFastJpeg=fast;void* packet=NULL;long long size=0;calc_opt_compr_send(0,0,d.first,d.second,pixels.data(),&packet,&size);require(packet!=NULL);
   int header=size>65508?16:8;decode_jpeg((BYTE*)packet+header,(size_t)size-header,d.first,d.second);free(packet);
   int count=d.first>2000?12:d.first>1000?20:100;auto start=std::chrono::steady_clock::now();long long total=0;
   for(int n=0;n<count;++n){calc_opt_compr_send(0,0,d.first,d.second,pixels.data(),&packet,&size);require(packet!=NULL);total+=size;free(packet);}
   printf("JPEG %dx%d %s %.4f ms %lld bytes\n",d.first,d.second,fast?"turbo":"GDI+",std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count()/count,total/count);require(pixels==original);
  }
 }
 useFastJpeg=true;
}
#endif
static void hash_bench(){
 SCALED_WIDTH=1920;SCALED_HEIGHT=1080;TILE_WIDTH_COUNT=60;TILE_HEIGHT_COUNT=34;useCaptureDamage=false;
 std::vector<unsigned> pixels(1920*1088);for(size_t i=0;i<pixels.size();++i)pixels[i]=(unsigned)(i*2654435761u);
 std::vector<std::vector<tileInfo_t>> rows(34,std::vector<tileInfo_t>(60));std::vector<tileInfo_t*> refs;for(auto& row:rows)refs.push_back(row.data());tileInfo=refs.data();
 bool available=checksum_crc_available();
 for(bool simd:{false,true}){if(simd&&!available)continue;useChecksumCrc=simd;auto start=std::chrono::steady_clock::now();for(int n=0;n<120;++n)prepare_tile_checksums(pixels.data());printf("hash %s: %.4f ms/1080p\n",simd?"CRC32C":"FNV",std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count()/120);}
 tileInfo=NULL;useChecksumCrc=available;
}
int main(int argc,char** argv){try{
#ifdef MESH_WINDOWS_TURBOJPEG
 if(argc==2&&!strcmp(argv[1],"--jpeg-configuration-only")){
  jpeg_configuration_tests();printf("PASS: %d JPEG configuration assertions\n",checks);return 0;
 }
#endif
 if(argc==2&&!strcmp(argv[1],"--encoding-recovery-only")){
  require(initialize_gdiplus()!=0);encoding_recovery_tests();teardown_gdiplus();
  printf("PASS: %d Windows encoding recovery assertions\n",checks);return 0;
 }
#ifdef MESH_WINDOWS_TURBOJPEG
 useFastJpeg=false; // Preserve byte-identical regression coverage of the GDI+ fallback.
#endif
 hash_bench();checksum_reference_tests();
 require(initialize_gdiplus()!=0);for(bool simd:{false,true}){if(simd&&!checksum_crc_available())continue;useChecksumCrc=simd;for(auto d:std::vector<std::pair<int,int>>{{1,1},{97,65},{160,96},{1919,1079},{3840,2160}})hash_tests(d.first,d.second);}
 for(int type:{1,2,3})encoding_tests(type);
 coalescing_tests();damage_packet_tests();sparse_checksum_tests();strided_encoding_tests();jumbo_tests();encoding_recovery_tests();
#ifdef MESH_WINDOWS_TURBOJPEG
 jpeg_fast_tests();jpeg_configuration_tests();encoder_bench();
#endif
 capture_tests();desktop_identity_tests();teardown_gdiplus();require(!capturePixels&&!hCapturedBitmap&&!hCaptureDC);printf("PASS: %d Windows capture/checksum/encoding assertions\n",checks);return 0;
}catch(const std::exception& e){fprintf(stderr,"%s after %d assertions\n",e.what(),checks);return 1;}}
