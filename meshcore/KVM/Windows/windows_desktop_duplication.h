/* Desktop Duplication is optional. No DXGI/D3D import is required at process startup. */
#ifndef MESH_WINDOWS_DESKTOP_DUPLICATION_H
#define MESH_WINDOWS_DESKTOP_DUPLICATION_H

#include <d3d11.h>
#include <dxgi1_2.h>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <memory>
#include <new>
#include <limits.h>

struct WinDDDamage
{
    int columns, rows, tileWidth, tileHeight;
    std::vector<unsigned char> tiles;
    WinDDDamage() : columns(0), rows(0), tileWidth(32), tileHeight(32) {}
    void Clear() { columns = rows = 0; tiles.clear(); }
    void Begin(int width, int height, int tw, int th, bool full)
    {
        columns = width / tw; rows = height / th; tileWidth = tw; tileHeight = th;
        tiles.assign((size_t)columns * rows, full ? 1 : 0);
    }
    void Full() { std::fill(tiles.begin(), tiles.end(), (unsigned char)1); }
    bool Dirty(int row, int col) const { return tiles[(size_t)row * columns + col] != 0; }
    bool Mark(const RECT& rect, int width, int height)
    {
        if (rect.left < 0 || rect.top < 0 || rect.right < rect.left || rect.bottom < rect.top || rect.right > width || rect.bottom > height)
        { Full(); return false; }
        if (rect.left == rect.right || rect.top == rect.bottom) return true;
        for (int y = rect.top / tileHeight; y <= (rect.bottom - 1) / tileHeight; ++y)
            for (int x = rect.left / tileWidth; x <= (rect.right - 1) / tileWidth; ++x)
                tiles[(size_t)y * columns + x] = 1;
        return true;
    }
};

// Copy only visible pixels from the mapped surface; never expose GPU row padding.
static bool WinDDCopyRows(BYTE* destination, size_t capacity, int stride, int paddedHeight,
    const BYTE* source, UINT sourcePitch, int width, int height, const WinDDDamage* damage = NULL)
{
    if (!destination || !source || width <= 0 || height <= 0 || width > INT_MAX / 4 ||
        stride < width * 4 || paddedHeight < height || sourcePitch < (UINT)width * 4 ||
        (size_t)stride > SIZE_MAX / (size_t)paddedHeight || capacity < (size_t)stride * paddedHeight ||
        (size_t)sourcePitch > SIZE_MAX / (size_t)height) return false;
    // An unchanged tile still belongs to the same private snapshot. Merge adjacent
    // dirty tiles into row spans, clipping edge tiles to visible source pixels.
    // Dense damage uses the simpler full-row loop instead.
    if (damage && damage->tileWidth > 0 && damage->tileHeight > 0 &&
        damage->columns == stride / 4 / damage->tileWidth && stride / 4 % damage->tileWidth == 0 &&
        damage->rows == paddedHeight / damage->tileHeight && paddedHeight % damage->tileHeight == 0 &&
        damage->tiles.size() == (size_t)damage->columns * damage->rows &&
        std::count(damage->tiles.begin(), damage->tiles.end(), (unsigned char)0) > (ptrdiff_t)(damage->tiles.size() / 2))
    {
        for (int r = 0; r < damage->rows; ++r)
        {
            int top = r * damage->tileHeight, bottom = (std::min)(height, top + damage->tileHeight);
            if (top >= height) break;
            for (int c = 0; c < damage->columns; )
            {
                if (!damage->Dirty(r, c)) { ++c; continue; }
                int left = c * damage->tileWidth;
                do { ++c; } while (c < damage->columns && damage->Dirty(r, c));
                int right = (std::min)(width, c * damage->tileWidth);
                if (left >= right) continue;
                for (int y = top; y < bottom; ++y)
                    memcpy(destination + (size_t)(paddedHeight - y - 1) * stride + (size_t)left * 4,
                        source + (size_t)y * sourcePitch + (size_t)left * 4, (size_t)(right - left) * 4);
            }
        }
        return true; // Padding was cleared by the mandatory initial full copy.
    }
    ZeroMemory(destination, (size_t)(paddedHeight - height) * stride);
    for (int y = 0; y < height; ++y)
    {
        BYTE* row = destination + (size_t)(paddedHeight - y - 1) * stride;
        memcpy(row, source + (size_t)y * sourcePitch, (size_t)width * 4);
        ZeroMemory(row + (size_t)width * 4, stride - (size_t)width * 4);
    }
    return true;
}

// The narrow source interface also lets tests inject loss/access/map failures.
class WinDDSource
{
public:
    virtual ~WinDDSource() {}
    virtual HRESULT Acquire(DXGI_OUTDUPL_FRAME_INFO& info) = 0;
    virtual HRESULT Damage(std::vector<RECT>& dirty, std::vector<DXGI_OUTDUPL_MOVE_RECT>& moves) = 0;
    // S_FALSE means reuse the caller's existing clean private snapshot on timeout.
    // It is allowed only when no server-rendered cursor can have modified it.
    virtual HRESULT Readback(bool newFrame, bool allowDirect, const BYTE*& pixels, UINT& pitch) = 0;
    virtual void Unmap() = 0;
    virtual HRESULT ReleaseFrame() = 0;
    virtual HRESULT Health() = 0;
};

template<class T> static void WinDDRelease(T*& value) { if (value) { value->Release(); value = NULL; } }

class WinDXGISource : public WinDDSource
{
    HMODULE dxgi, d3d;
    IDXGIOutput* output;
    IDXGIOutputDuplication* duplication;
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    ID3D11Texture2D* staging;
    IDXGIResource* frame;
    RECT bounds;
    DXGI_OUTDUPL_FRAME_INFO frameInfo;
    bool held, mapped, staged, systemMemory, directMapped, directSnapshot;
    HRESULT unmapResult;

    static HMODULE SystemLibrary(const WCHAR* name)
    {
        WCHAR path[MAX_PATH]; UINT length = GetSystemDirectoryW(path, _countof(path));
        if (!length || length >= _countof(path) || length + wcslen(name) + 2 > _countof(path)) return NULL;
        wcscat_s(path, _countof(path), L"\\"); wcscat_s(path, _countof(path), name);
        return LoadLibraryW(path); // Absolute trusted system path; no current-directory search.
    }

public:
    WinDXGISource() : dxgi(NULL), d3d(NULL), output(NULL), duplication(NULL), device(NULL), context(NULL),
        staging(NULL), frame(NULL), held(false), mapped(false), staged(false), systemMemory(false),
        directMapped(false), directSnapshot(false), unmapResult(S_OK) { ZeroMemory(&bounds, sizeof(bounds)); ZeroMemory(&frameInfo, sizeof(frameInfo)); }
    ~WinDXGISource()
    {
        Unmap(); ReleaseFrame(); WinDDRelease(staging); WinDDRelease(duplication);
        WinDDRelease(context); WinDDRelease(device); WinDDRelease(output);
        if (d3d) FreeLibrary(d3d); if (dxgi) FreeLibrary(dxgi);
    }
    static HRESULT Create(const RECT& selected, WinDDSource** result)
    {
        *result = NULL;
        std::unique_ptr<WinDXGISource> source(new(std::nothrow) WinDXGISource());
        if (!source) return E_OUTOFMEMORY;
        source->dxgi = SystemLibrary(L"dxgi.dll"); source->d3d = SystemLibrary(L"d3d11.dll");
        if (!source->dxgi || !source->d3d) return E_NOINTERFACE;
        typedef HRESULT(WINAPI* CreateFactory)(REFIID, void**);
        CreateFactory factoryFunction = (CreateFactory)GetProcAddress(source->dxgi, "CreateDXGIFactory1");
        PFN_D3D11_CREATE_DEVICE deviceFunction = (PFN_D3D11_CREATE_DEVICE)GetProcAddress(source->d3d, "D3D11CreateDevice");
        if (!factoryFunction || !deviceFunction) return E_NOINTERFACE;
        IDXGIFactory1* factory = NULL;
        HRESULT hr = factoryFunction(__uuidof(IDXGIFactory1), (void**)&factory);
        if (FAILED(hr)) return hr;
        HRESULT outcome = DXGI_ERROR_UNSUPPORTED;
        for (UINT a = 0; ; ++a)
        {
            IDXGIAdapter1* adapter = NULL; hr = factory->EnumAdapters1(a, &adapter);
            if (FAILED(hr)) break;
            for (UINT o = 0; ; ++o)
            {
                IDXGIOutput* candidate = NULL; hr = adapter->EnumOutputs(o, &candidate);
                if (FAILED(hr)) break;
                DXGI_OUTPUT_DESC desc = {};
                hr = candidate->GetDesc(&desc);
                if (SUCCEEDED(hr) && desc.AttachedToDesktop && desc.Rotation == DXGI_MODE_ROTATION_IDENTITY &&
                    EqualRect(&selected, &desc.DesktopCoordinates))
                {
                    D3D_FEATURE_LEVEL level;
                    outcome = deviceFunction(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                        NULL, 0, D3D11_SDK_VERSION, &source->device, &level, &source->context);
                    IDXGIOutput1* output1 = NULL;
                    if (SUCCEEDED(outcome)) outcome = candidate->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);
                    if (SUCCEEDED(outcome)) outcome = output1->DuplicateOutput(source->device, &source->duplication);
                    WinDDRelease(output1);
                    if (SUCCEEDED(outcome))
                    {
                        DXGI_OUTDUPL_DESC format = {}; source->duplication->GetDesc(&format);
                        source->systemMemory = format.DesktopImageInSystemMemory != FALSE;
                        if (format.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || format.Rotation != DXGI_MODE_ROTATION_IDENTITY ||
                            format.ModeDesc.Width != (UINT)(selected.right - selected.left) || format.ModeDesc.Height != (UINT)(selected.bottom - selected.top))
                            outcome = DXGI_ERROR_UNSUPPORTED;
                    }
                    if (SUCCEEDED(outcome)) { source->output = candidate; source->bounds = selected; candidate = NULL; }
                    WinDDRelease(candidate); WinDDRelease(adapter); WinDDRelease(factory);
                    if (SUCCEEDED(outcome)) *result = source.release();
                    return outcome;
                }
                WinDDRelease(candidate);
            }
            WinDDRelease(adapter);
        }
        WinDDRelease(factory); return outcome;
    }
    HRESULT Acquire(DXGI_OUTDUPL_FRAME_INFO& info)
    {
        if (held) return DXGI_ERROR_INVALID_CALL;
        HRESULT hr = duplication->AcquireNextFrame(0, &info, &frame);
        if (SUCCEEDED(hr)) { held = true; frameInfo = info; unmapResult = S_OK; }
        return hr;
    }
    HRESULT Damage(std::vector<RECT>& dirty, std::vector<DXGI_OUTDUPL_MOVE_RECT>& moves)
    {
        const UINT maximum = 1024 * 1024;
        UINT bytes = frameInfo.TotalMetadataBufferSize, used = 0;
        if (!bytes || bytes > maximum) return S_FALSE; // Full hashing is safer than trusting missing/oversized damage.
        dirty.resize(bytes / sizeof(RECT) + 1);
        HRESULT hr = duplication->GetFrameDirtyRects((UINT)(dirty.size() * sizeof(RECT)), dirty.data(), &used);
        if (FAILED(hr)) return hr;
        if (used > dirty.size() * sizeof(RECT) || used % sizeof(RECT)) return S_FALSE;
        dirty.resize(used / sizeof(RECT)); moves.resize(bytes / sizeof(DXGI_OUTDUPL_MOVE_RECT) + 1);
        hr = duplication->GetFrameMoveRects((UINT)(moves.size() * sizeof(DXGI_OUTDUPL_MOVE_RECT)), moves.data(), &used);
        if (FAILED(hr)) return hr;
        if (used > moves.size() * sizeof(DXGI_OUTDUPL_MOVE_RECT) || used % sizeof(DXGI_OUTDUPL_MOVE_RECT)) return S_FALSE;
        moves.resize(used / sizeof(DXGI_OUTDUPL_MOVE_RECT)); return S_OK;
    }
    HRESULT Readback(bool newFrame, bool allowDirect, const BYTE*& pixels, UINT& pitch)
    {
        if (!newFrame && allowDirect && directSnapshot) return S_FALSE;
        if (newFrame && allowDirect && systemMemory)
        {
            // Keep the per-frame texture validation used by the staging path.
            ID3D11Texture2D* texture = NULL;
            HRESULT hr = frame->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&texture);
            if (FAILED(hr)) return hr;
            D3D11_TEXTURE2D_DESC desc = {}; texture->GetDesc(&desc); texture->Release();
            if (desc.Width != (UINT)(bounds.right - bounds.left) || desc.Height != (UINT)(bounds.bottom - bounds.top) ||
                desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || desc.SampleDesc.Count != 1 || desc.ArraySize != 1 || desc.MipLevels != 1)
                return DXGI_ERROR_UNSUPPORTED;
            DXGI_MAPPED_RECT map = {};
            hr = duplication->MapDesktopSurface(&map);
            if (SUCCEEDED(hr))
            {
                directMapped = true;
                if (!map.pBits || map.Pitch <= 0) return E_INVALIDARG;
                pixels = map.pBits; pitch = (UINT)map.Pitch;
                // Encode only the copied private DIB, never this borrowed mapping.
                WinDDRelease(staging); staged = false; directSnapshot = true;
                return S_OK;
            }
            if (hr != DXGI_ERROR_UNSUPPORTED) return hr;
            systemMemory = false; // A driver declining direct access retains the staging path.
        }
        if (newFrame)
        {
            ID3D11Texture2D* texture = NULL;
            HRESULT hr = frame->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&texture);
            if (FAILED(hr)) return hr;
            D3D11_TEXTURE2D_DESC desc = {}; texture->GetDesc(&desc);
            if (desc.Width != (UINT)(bounds.right - bounds.left) || desc.Height != (UINT)(bounds.bottom - bounds.top) ||
                desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || desc.SampleDesc.Count != 1 || desc.ArraySize != 1 || desc.MipLevels != 1)
            { texture->Release(); return DXGI_ERROR_UNSUPPORTED; }
            if (!staging)
            {
                desc.Usage = D3D11_USAGE_STAGING; desc.BindFlags = desc.MiscFlags = 0; desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                hr = device->CreateTexture2D(&desc, NULL, &staging);
                if (FAILED(hr)) { texture->Release(); return hr; }
            }
            context->CopyResource(staging, texture); texture->Release(); staged = true; directSnapshot = false;
        }
        if (!staged) return DXGI_ERROR_INVALID_CALL;
        D3D11_MAPPED_SUBRESOURCE map = {};
        HRESULT hr = context->Map(staging, 0, D3D11_MAP_READ, 0, &map);
        if (FAILED(hr)) return hr;
        mapped = true; pixels = (const BYTE*)map.pData; pitch = map.RowPitch; return S_OK;
    }
    void Unmap()
    {
        if (directMapped) { unmapResult = duplication->UnMapDesktopSurface(); directMapped = false; }
        if (mapped) { context->Unmap(staging, 0); mapped = false; }
    }
    HRESULT ReleaseFrame()
    {
        WinDDRelease(frame);
        if (!held) return S_OK;
        held = false; HRESULT hr = duplication->ReleaseFrame();
        return FAILED(unmapResult) ? unmapResult : hr;
    }
    HRESULT Health()
    {
        HRESULT hr = device->GetDeviceRemovedReason(); if (FAILED(hr)) return hr;
        DXGI_OUTPUT_DESC desc = {}; hr = output->GetDesc(&desc);
        if (FAILED(hr)) return hr;
        return desc.AttachedToDesktop && desc.Rotation == DXGI_MODE_ROTATION_IDENTITY && EqualRect(&bounds, &desc.DesktopCoordinates) ? S_OK : DXGI_ERROR_ACCESS_LOST;
    }
};

/** Optional capture-worker adapter with a private, caller-owned DIB snapshot.
 * DXGI mapped pointers never escape the synchronous Read/Acquire operation.
 * Frame leases always unmap/release, including early failure and timeout paths.
 * Damage is an optimization hint: uncertainty forces complete private copying
 * or secure GDI fallback. Cursor overlays invalidate sparse-copy assumptions.
 */
class WinDesktopDuplication
{
public:
    // Waiting has no valid first image; Unchanged may reuse only a valid snapshot.
    enum Result { Fallback, Frame, Unchanged, Waiting };
    typedef HRESULT(*Factory)(const RECT&, WinDDSource**);
    unsigned long long frames, unchanged, attempts, failures;
    HRESULT lastError;
    WinDDDamage damage;
private:
    std::unique_ptr<WinDDSource> source;
    Factory factory;
    DWORD lastAttempt;
    bool attempted, valid, pointerVisible, snapshotCursorDrawn;
    BYTE* snapshot;
    int snapshotStride, snapshotHeight;
    RECT snapshotBounds;
    HRESULT releaseError;
    struct Lease
    {
        WinDDSource* source; bool acquired; HRESULT& releaseError;
        Lease(WinDDSource* s, bool a, HRESULT& e) : source(s), acquired(a), releaseError(e) {}
        ~Lease() { source->Unmap(); if (acquired) releaseError = source->ReleaseFrame(); }
    };
    Result Read(BYTE* destination, size_t capacity, int stride, int paddedHeight, const RECT& selected,
        int tw, int th, bool force, bool cursorChanged, bool cursorWanted, bool& drawCursor)
    {
        int width = selected.right - selected.left, height = selected.bottom - selected.top;
        HRESULT hr = source->Health(); if (FAILED(hr)) { lastError = hr; return Fallback; }
        DXGI_OUTDUPL_FRAME_INFO info = {};
        hr = source->Acquire(info);
        bool acquired = SUCCEEDED(hr);
        if (!acquired && hr != DXGI_ERROR_WAIT_TIMEOUT) { lastError = hr; return Fallback; }
        Lease lease(source.get(), acquired, releaseError);
        if (!acquired && !valid) return Waiting;
        if (acquired && (!valid || info.LastMouseUpdateTime.QuadPart)) pointerVisible = info.PointerPosition.Visible != FALSE;
        // DXGI reports false when the pointer is already baked into the desktop image.
        drawCursor = cursorWanted && pointerVisible;
        if (!acquired && !force && !cursorChanged) { ++unchanged; return Unchanged; }
        // In-band cursor drawing modifies the DIB. Restore the complete clean
        // image before redrawing it, including the transition back to OS-baked
        // cursors; sparse metadata need not cover the old overlay's pixels.
        bool fullCopy = force || !valid || cursorChanged || drawCursor || snapshotCursorDrawn;
        damage.Begin(stride / 4, paddedHeight, tw, th, fullCopy);
        if (acquired && !fullCopy)
        {
            std::vector<RECT> dirty; std::vector<DXGI_OUTDUPL_MOVE_RECT> moves;
            hr = source->Damage(dirty, moves);
            if (FAILED(hr)) { lastError = hr; return Fallback; }
            if (hr != S_OK) damage.Full();
            else
            {
                for (size_t i = 0; i < moves.size(); ++i)
                {
                    damage.Mark(moves[i].DestinationRect, width, height);
                    long long right = (long long)moves[i].SourcePoint.x + moves[i].DestinationRect.right - moves[i].DestinationRect.left;
                    long long bottom = (long long)moves[i].SourcePoint.y + moves[i].DestinationRect.bottom - moves[i].DestinationRect.top;
                    if (right > width || bottom > height || right < 0 || bottom < 0) damage.Full();
                    else { RECT from = { moves[i].SourcePoint.x, moves[i].SourcePoint.y, (LONG)right, (LONG)bottom }; damage.Mark(from, width, height); }
                }
                for (size_t i = 0; i < dirty.size(); ++i) damage.Mark(dirty[i], width, height);
                if (dirty.empty() && moves.empty() && info.LastPresentTime.QuadPart) damage.Full();
            }
        }
        const BYTE* pixels = NULL; UINT pitch = 0;
        hr = source->Readback(acquired, !drawCursor, pixels, pitch);
        if (FAILED(hr)) { lastError = hr; return Fallback; }
        if (hr == S_FALSE && (acquired || !valid || drawCursor)) { lastError = E_INVALIDARG; return Fallback; }
        if (hr != S_FALSE && !WinDDCopyRows(destination, capacity, stride, paddedHeight, pixels, pitch, width, height, &damage))
        { lastError = E_INVALIDARG; return Fallback; }
        hr = source->Health(); if (FAILED(hr)) { lastError = hr; return Fallback; }
        snapshot = destination; snapshotStride = stride; snapshotHeight = paddedHeight; snapshotBounds = selected;
        snapshotCursorDrawn = drawCursor; valid = true; ++frames; return Frame;
    }
public:
    explicit WinDesktopDuplication(Factory create = WinDXGISource::Create) : frames(0), unchanged(0), attempts(0), failures(0), lastError(S_OK),
        factory(create), lastAttempt(0), attempted(false), valid(false), pointerVisible(false), snapshotCursorDrawn(false), snapshot(NULL),
        snapshotStride(0), snapshotHeight(0), snapshotBounds(), releaseError(S_OK) {}
    void Reset() { source.reset(); damage.Clear(); valid = pointerVisible = snapshotCursorDrawn = false; snapshot = NULL; attempted = false; lastError = S_OK; }
    Result Capture(BYTE* destination, size_t capacity, int stride, int paddedHeight, const RECT& selected,
        int tw, int th, bool force, bool cursorChanged, bool cursorWanted, bool& drawCursor)
    {
        drawCursor = false;
        long long width = (long long)selected.right - selected.left, height = (long long)selected.bottom - selected.top;
        if (!destination || width <= 0 || height <= 0 || width > INT_MAX / 4 || stride < width * 4 || paddedHeight < height ||
            tw <= 0 || th <= 0 || stride % 4 || (stride / 4) % tw || paddedHeight % th ||
            (size_t)stride > SIZE_MAX / (size_t)paddedHeight || capacity < (size_t)stride * paddedHeight)
        { Reset(); lastError = E_INVALIDARG; return Fallback; }
        try
        {
            // A timeout must never authorize reusing a different destination or layout.
            if (valid && (snapshot != destination || snapshotStride != stride || snapshotHeight != paddedHeight ||
                !EqualRect(&snapshotBounds, &selected))) Reset();
            if (!source)
            {
                DWORD now = GetTickCount();
                if (attempted && (DWORD)(now - lastAttempt) < 5000) return Fallback;
                attempted = true; lastAttempt = now; ++attempts;
                WinDDSource* created = NULL; lastError = factory(selected, &created); source.reset(created);
                if (FAILED(lastError) || !source) { source.reset(); ++failures; return Fallback; }
            }
            releaseError = S_OK;
            Result result = Read(destination, capacity, stride, paddedHeight, selected, tw, th, force, cursorChanged, cursorWanted, drawCursor);
            if (FAILED(releaseError)) { lastError = releaseError; result = Fallback; }
            if (result == Waiting) return Fallback; // Keep the new duplication alive for its first notification.
            if (result == Fallback)
            {
                // Read's lease has already unmapped/released before destroying the source.
                source.reset(); damage.Clear(); valid = pointerVisible = false; ++failures;
                lastAttempt = GetTickCount(); attempted = true;
            }
            return result;
        }
        catch (const std::bad_alloc&)
        {
            source.reset(); damage.Clear(); valid = pointerVisible = false;
            lastAttempt = GetTickCount(); attempted = true; lastError = E_OUTOFMEMORY; ++failures; return Fallback;
        }
    }
};

#endif
