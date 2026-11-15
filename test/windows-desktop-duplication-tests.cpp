// Production DXGI reader with injected source faults; no live keyboard/mouse input.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include "meshcore/KVM/Windows/windows_desktop_duplication.h"

struct FakeState
{
    std::deque<HRESULT> acquire;
    std::vector<RECT> dirty;
    std::vector<DXGI_OUTDUPL_MOVE_RECT> moves;
    std::vector<BYTE> pixels;
    HRESULT createResult, damageResult, mapResult, releaseResult;
    int creates, destroys, maps, unmaps, releases, violations, healthCalls, failHealthAt;
    UINT pitch;
    bool held, mapped, staged, pointer, direct, lastDirect;
    FakeState() : createResult(S_OK), damageResult(S_OK), mapResult(S_OK), releaseResult(S_OK), creates(0), destroys(0),
        maps(0), unmaps(0), releases(0), violations(0), healthCalls(0), failHealthAt(0),
        pitch(97 * 4 + 16),
        held(false), mapped(false), staged(false), pointer(true), direct(false), lastDirect(false)
    { pixels.resize((size_t)pitch * 65); for (size_t i = 0; i < pixels.size(); ++i) pixels[i] = (BYTE)(i * 13 + 7); }
};
static FakeState* active;
class FakeSource : public WinDDSource
{
    FakeState& s;
public:
    explicit FakeSource(FakeState& state) : s(state) {}
    ~FakeSource() { ++s.destroys; if (s.mapped || s.held) ++s.violations; }
    HRESULT Acquire(DXGI_OUTDUPL_FRAME_INFO& info)
    {
        HRESULT hr = s.acquire.empty() ? DXGI_ERROR_WAIT_TIMEOUT : s.acquire.front();
        if (!s.acquire.empty()) s.acquire.pop_front();
        if (SUCCEEDED(hr))
        {
            if (s.held) ++s.violations;
            s.held = true; info.LastPresentTime.QuadPart = 1; info.LastMouseUpdateTime.QuadPart = 1;
            info.PointerPosition.Visible = s.pointer; info.TotalMetadataBufferSize = 128;
        }
        return hr;
    }
    HRESULT Damage(std::vector<RECT>& dirty, std::vector<DXGI_OUTDUPL_MOVE_RECT>& moves)
    {
        if (!s.held) ++s.violations;
        dirty = s.dirty; moves = s.moves; return s.damageResult;
    }
    HRESULT Readback(bool newFrame, bool allowDirect, const BYTE*& pixels, UINT& pitch)
    {
        if (!newFrame && allowDirect && s.lastDirect) return S_FALSE;
        if (!newFrame && s.lastDirect) return E_ACCESSDENIED;
        if ((newFrame && !s.held) || (!newFrame && !s.staged)) ++s.violations;
        if (FAILED(s.mapResult)) return s.mapResult;
        s.staged = true; s.lastDirect = newFrame && allowDirect && s.direct;
        s.mapped = true; ++s.maps; pixels = s.pixels.data(); pitch = s.pitch; return S_OK;
    }
    void Unmap() { if (s.mapped) { s.mapped = false; ++s.unmaps; } }
    HRESULT ReleaseFrame() { if (!s.held) ++s.violations; s.held = false; ++s.releases; return s.releaseResult; }
    HRESULT Health() { return ++s.healthCalls == s.failHealthAt ? DXGI_ERROR_DEVICE_REMOVED : S_OK; }
};
static HRESULT fakeFactory(const RECT&, WinDDSource** result)
{ ++active->creates; *result = SUCCEEDED(active->createResult) ? new FakeSource(*active) : NULL; return active->createResult; }
static int checks;
static void require(bool ok) { ++checks; if (!ok) throw std::runtime_error("Desktop Duplication regression failed"); }
static RECT selected = { 0,0,97,65 };
static WinDesktopDuplication::Result capture(WinDesktopDuplication& reader, std::vector<BYTE>& output, bool force=false, bool cursor=false, bool wanted=false)
{ bool draw=false; return reader.Capture(output.data(),output.size(),128*4,96,selected,32,32,force,cursor,wanted,draw); }
static void full(const WinDDDamage& damage) { require(damage.tiles.size()==12); for(size_t i=0;i<damage.tiles.size();++i)require(damage.tiles[i]==1); }
static void row_tests()
{
    FakeState s; std::vector<BYTE> output(128*96*4,0xcd);
    require(WinDDCopyRows(output.data(),output.size(),128*4,96,s.pixels.data(),s.pitch,97,65));
    for(int y=0;y<65;++y)require(!memcmp(output.data()+(size_t)(95-y)*512,s.pixels.data()+(size_t)y*s.pitch,97*4));
    for(int y=0;y<31;++y)for(int x=0;x<512;++x)require(output[(size_t)y*512+x]==0);
    for(int y=31;y<96;++y)for(int x=97*4;x<512;++x)require(output[(size_t)y*512+x]==0);
    require(!WinDDCopyRows(output.data(),output.size()-1,512,96,s.pixels.data(),s.pitch,97,65));
    require(!WinDDCopyRows(output.data(),output.size(),512,64,s.pixels.data(),s.pitch,97,65));
    require(!WinDDCopyRows(output.data(),output.size(),512,96,s.pixels.data(),1,97,65));
    require(!WinDDCopyRows(output.data(),output.size(),512,96,NULL,s.pitch,97,65));
}
static void lifecycle_tests()
{
    FakeState s; active=&s; WinDesktopDuplication reader(fakeFactory); std::vector<BYTE> output(128*96*4);
    // No first frame: retain the source for its next notification; never return old pixels.
    require(capture(reader,output)==WinDesktopDuplication::Fallback);require(s.creates==1&&s.destroys==0);
    s.acquire.push_back(S_OK); require(capture(reader,output)==WinDesktopDuplication::Frame); full(reader.damage);
    require(s.creates==1&&s.maps==1&&s.unmaps==1&&s.releases==1&&s.violations==0);
    require(capture(reader,output)==WinDesktopDuplication::Unchanged);require(s.maps==1&&s.releases==1);
    // Explicit refresh and pointer updates may read the private staging texture on timeout.
    require(capture(reader,output,true)==WinDesktopDuplication::Frame);full(reader.damage);require(s.maps==2&&s.releases==1);
    require(capture(reader,output,false,true)==WinDesktopDuplication::Frame);full(reader.damage);
    s.dirty.push_back(RECT{31,31,33,33}); DXGI_OUTDUPL_MOVE_RECT move={};move.SourcePoint.x=64;move.DestinationRect=RECT{0,32,32,64};s.moves.push_back(move);
    s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);
    int marked=0;for(size_t i=0;i<reader.damage.tiles.size();++i)marked+=reader.damage.tiles[i]!=0;require(marked==5);
    s.dirty[0]=RECT{-1,0,32,32};s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);full(reader.damage);
    s.damageResult=S_FALSE;s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);full(reader.damage);
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0&&s.destroys==1);
    require(capture(reader,output)==WinDesktopDuplication::Fallback); // Reset invalidates timeout cache.
    reader.Reset();require(s.destroys==2);
}
static void failure_tests()
{
    for(int failure=0;failure<7;++failure)
    {
        FakeState s; active=&s;WinDesktopDuplication reader(fakeFactory);std::vector<BYTE> output(128*96*4);
        s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);
        if(failure==0)s.acquire.push_back(DXGI_ERROR_ACCESS_LOST);
        else
        {
            s.acquire.push_back(S_OK);
            if(failure==1)s.damageResult=E_ACCESSDENIED;
            if(failure==2)s.mapResult=E_OUTOFMEMORY;
            if(failure==3)s.pitch=1;
            if(failure==4)s.releaseResult=DXGI_ERROR_ACCESS_LOST;
            if(failure==5)s.failHealthAt=s.healthCalls+1;
            if(failure==6)s.failHealthAt=s.healthCalls+2;
        }
        require(capture(reader,output)==WinDesktopDuplication::Fallback);
        require(s.maps==s.unmaps&&s.violations==0&&s.destroys==1);
        require(capture(reader,output)==WinDesktopDuplication::Fallback);require(s.creates==1); // Backoff, not stale-cache reuse.
        reader.Reset();s.acquire.clear();require(capture(reader,output)==WinDesktopDuplication::Fallback);require(s.creates==2);
        reader.Reset();require(s.violations==0);
    }
    FakeState denied;active=&denied;denied.createResult=E_ACCESSDENIED;WinDesktopDuplication reader(fakeFactory);std::vector<BYTE> output(128*96*4);
    require(capture(reader,output)==WinDesktopDuplication::Fallback);require(capture(reader,output)==WinDesktopDuplication::Fallback);require(denied.creates==1);
    reader.Reset();denied.createResult=S_OK;denied.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);
    reader.Reset();require(denied.violations==0);
    FakeState baked;active=&baked;baked.pointer=false;baked.acquire.push_back(S_OK);WinDesktopDuplication cursorReader(fakeFactory);
    require(capture(cursorReader,output,false,false,true)==WinDesktopDuplication::Frame);require(baked.maps==1&&baked.releases==1&&baked.violations==0);
}
static void sparse_copy_tests()
{
    FakeState s; active=&s; WinDesktopDuplication reader(fakeFactory);
    std::vector<BYTE> output(128*96*4,0xcd), reference(output.size());
    s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);
    // Many disjoint/clipped tiles, moves, and invalid metadata must match full copies.
    for(int n=0;n<60;++n)
    {
        int x=(n*17)%97,y=(n*13)%65;
        RECT rect={x,y,(std::min)(97,x+2),(std::min)(65,y+3)};
        s.dirty.assign(1,rect);s.moves.clear();
        for(int r=rect.top;r<rect.bottom;++r)for(int c=rect.left*4;c<rect.right*4;++c)s.pixels[(size_t)r*s.pitch+c]^=0x57;
        if(n%7==0){DXGI_OUTDUPL_MOVE_RECT move={};move.SourcePoint={0,0};move.DestinationRect={64,32,97,65};s.moves.push_back(move);
            for(int r=32;r<65;++r)for(int c=64*4;c<97*4;++c)s.pixels[(size_t)r*s.pitch+c]^=0x31;}
        s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);
        require(WinDDCopyRows(reference.data(),reference.size(),512,96,s.pixels.data(),s.pitch,97,65));require(output==reference);
    }
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0);
}
static void direct_snapshot_tests()
{
    FakeState s;s.direct=true;active=&s;WinDesktopDuplication reader(fakeFactory);
    std::vector<BYTE> output(128*96*4),replacement(output.size(),0xcd);
    s.acquire.push_back(S_OK);require(capture(reader,output)==WinDesktopDuplication::Frame);auto first=output;
    require(capture(reader,output,true)==WinDesktopDuplication::Frame);require(s.maps==1&&output==first);full(reader.damage);
    require(capture(reader,output,false,true)==WinDesktopDuplication::Frame);require(s.maps==1&&output==first);
    // Different storage is never authorized by the old snapshot's lifetime.
    require(capture(reader,replacement,true)==WinDesktopDuplication::Fallback);require(s.creates==2&&s.maps==1);
    s.acquire.push_back(S_OK);require(capture(reader,replacement)==WinDesktopDuplication::Frame);require(replacement==first);
    // In-band cursor rendering requires a restorable staging copy or safe fallback.
    require(capture(reader,replacement,false,true,true)==WinDesktopDuplication::Fallback);
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0);
    s.acquire.push_back(S_OK);require(capture(reader,replacement,false,false,true)==WinDesktopDuplication::Frame);
    require(!s.lastDirect);require(capture(reader,replacement,true,false,true)==WinDesktopDuplication::Frame);
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0);
    // A cursor already baked into the OS image needs no destructive overlay.
    s.pointer=false;s.acquire.push_back(S_OK);require(capture(reader,replacement,false,false,true)==WinDesktopDuplication::Frame);
    require(s.lastDirect);int maps=s.maps;
    require(capture(reader,replacement,true,false,true)==WinDesktopDuplication::Frame);require(s.maps==maps);
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0);
}
static void cursor_overlay_tests()
{
    FakeState s;s.direct=true;active=&s;WinDesktopDuplication reader(fakeFactory);std::vector<BYTE> output(128*96*4),clean(output.size());
    s.dirty.push_back(RECT{0,0,1,1});
    s.acquire.push_back(S_OK);require(capture(reader,output,false,false,true)==WinDesktopDuplication::Frame);clean=output;
    output[(size_t)40*512+300]^=0x71; // Model a drawn cursor outside the next dirty region.
    s.acquire.push_back(S_OK);require(capture(reader,output,false,false,true)==WinDesktopDuplication::Frame);require(output==clean);full(reader.damage);
    output[(size_t)40*512+300]^=0x71;
    s.pointer=false;s.acquire.push_back(S_OK);require(capture(reader,output,false,false,true)==WinDesktopDuplication::Frame);require(output==clean);full(reader.damage);
    s.acquire.push_back(S_OK);require(capture(reader,output,false,false,true)==WinDesktopDuplication::Frame);require(reader.damage.Dirty(0,0)&&!reader.damage.Dirty(1,1));
    reader.Reset();require(s.maps==s.unmaps&&s.violations==0);
}
int main(){try{row_tests();lifecycle_tests();failure_tests();sparse_copy_tests();direct_snapshot_tests();cursor_overlay_tests();printf("PASS: %d Desktop Duplication assertions\n",checks);return 0;}
catch(const std::exception& e){fprintf(stderr,"%s after %d assertions\n",e.what(),checks);return 1;}}
