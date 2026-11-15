/*
Copyright 2010 - 2011 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "meshcore/KVM/Linux/linux_kvm_capture.h"
#include "meshcore/KVM/Linux/linux_kvm_dmabuf_sync.h"
#include "meshcore/KVM/Linux/linux_kvm_input_state.h"
#include "meshcore/KVM/Linux/linux_kvm_recovery.h"
#include "meshcore/KVM/Linux/linux_kvm_wayland.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

static int g_passed = 0;
static int g_failed = 0;
static int g_skipped = 0;

typedef struct released_codes
{
	unsigned int codes[8];
	int count;
} released_codes;

typedef struct dmabuf_fixture
{
	int wait_result;
	int sync_result;
	int wait_calls;
	int sync_calls;
	int last_start;
	unsigned int timeout_ms;
} dmabuf_fixture;

#define CHECK(name, condition) do { \
	if (condition) { ++g_passed; } \
	else { ++g_failed; fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); } \
} while (0)

#if !defined(KVM_TEST_NO_SESSION)
static int write_text(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (f == NULL) { return 0; }
	if (fwrite(text, 1, strlen(text), f) != strlen(text)) { fclose(f); return 0; }
	return fclose(f) == 0;
}
#endif

static void test_recovery_policy(void)
{
	uint32_t failures = 0;
	uint32_t delay = 0;
	int i;

	for (i = 1; i <= 12; ++i)
	{
		delay = kvm_recovery_next_delay_ms(&failures, 1000, 1100, 30000);
		if (i <= 5) { CHECK("first five retries are fast", delay == 1500); }
		else if (i <= 10) { CHECK("middle retries open the circuit", delay == 10000); }
		else { CHECK("later retries remain enabled and bounded", delay == 30000); }
	}
	CHECK("more than old burst limit remains recoverable", failures == 12 && delay == 30000);
	delay = kvm_recovery_next_delay_ms(&failures, 1000, 31000, 30000);
	CHECK("healthy worker resets failure burst", failures == 1 && delay == 1500);
	failures = UINT32_MAX;
	delay = kvm_recovery_next_delay_ms(&failures, 0, 0, 30000);
	CHECK("retry counter saturates without disabling probes", failures == UINT32_MAX && delay == 30000);
}

static void test_display_wake_policy(void)
{
    uint64_t last = 0;
    CHECK("brief scanout transition does not wake", !kvm_capture_wake_due(1000, 1499, &last, 1, 1, 1) && last == 0);
    CHECK("stable inactive console wakes after grace", kvm_capture_wake_due(1000, 1500, &last, 1, 1, 1) && last == 1500);
    CHECK("wake attempts are rate limited", !kvm_capture_wake_due(1000, 2499, &last, 1, 1, 1) && last == 1500);
    CHECK("wake can retry once per second", kvm_capture_wake_due(1000, 2500, &last, 1, 1, 1) && last == 2500);
    CHECK("wake retry window is bounded", !kvm_capture_wake_due(1000, 11000, &last, 1, 1, 1));
    CHECK("partial inactive layout does not inject", !kvm_capture_wake_due(1000, 4000, &last, 0, 1, 1));
    CHECK("unavailable input does not wake", !kvm_capture_wake_due(1000, 4000, &last, 1, 0, 1));
    CHECK("session handover does not wake", !kvm_capture_wake_due(1000, 4000, &last, 1, 1, 0));
    CHECK("clock reversal does not bypass rate limit", !kvm_capture_wake_due(1000, 2000, &last, 1, 1, 1));
}

static void test_capture_failure_budget(void)
{
    uint64_t hardSince = 0;
    CHECK("display suspension does not start hard retry", !kvm_capture_failure_due(&hardSince, 1000, 0, 5000) && hardSince == 0);
    CHECK("long display suspension does not consume hard retry", !kvm_capture_failure_due(&hardSince, 7000, 0, 5000) && hardSince == 0);
    CHECK("wake fresh-frame wait starts with full retry budget", !kvm_capture_failure_due(&hardSince, 7000, 1, 5000) && hardSince == 7000);
    CHECK("repeated incomplete frames do not renew retry", !kvm_capture_failure_due(&hardSince, 11999, 1, 5000) && hardSince == 7000);
    CHECK("continuous hard failure expires at original five seconds", kvm_capture_failure_due(&hardSince, 12000, 1, 5000) && hardSince == 7000);
    CHECK("continued hard failure remains expired", kvm_capture_failure_due(&hardSince, 13000, 1, 5000));
    CHECK("complete frame clears prior hard failure", !kvm_capture_failure_due(&hardSince, 14000, 0, 5000) && hardSince == 0);
    CHECK("new outage gets a new retry budget", !kvm_capture_failure_due(&hardSince, 15000, 1, 5000) && hardSince == 15000);
    CHECK("only suspended outputs clear hard failure phase", !kvm_capture_failure_due(&hardSince, 16000, 0, 5000) && hardSince == 0);
    CHECK("hard failure on another output still starts retry", !kvm_capture_failure_due(&hardSince, 17000, 1, 5000) && hardSince == 17000);
    CHECK("other suspended outputs cannot reset aggregate hard failure", kvm_capture_failure_due(&hardSince, 22000, 1, 5000) && hardSince == 17000);
    CHECK("clock reversal fails closed", kvm_capture_failure_due(&hardSince, 16999, 1, 5000));
    CHECK("unavailable clock fails closed", kvm_capture_failure_due(&hardSince, 0, 1, 5000));
    hardSince = 0;
    CHECK("zero retry budget expires immediately", kvm_capture_failure_due(&hardSince, 23000, 1, 0));
}

static void test_capture_limits(void)
{
	size_t bytes = 0;
	uint32_t width = 0;
	uint32_t height = 0;

	CHECK("1080p RGB allocation accepted", kvm_capture_checked_rgb_size(1920, 1080, &bytes) && bytes == 6220800);
	CHECK("zero-sized frame rejected", !kvm_capture_checked_rgb_size(0, 1080, &bytes));
	CHECK("oversized frame rejected", !kvm_capture_checked_rgb_size(32768, 32768, &bytes));
	CHECK("RGBA temporary buffer budget enforced", !kvm_capture_checked_pixel_size(16384, 16384, 4, &bytes));
	CHECK("normal mapping accepted", kvm_capture_checked_map_size(4096, 7680, 1080, &bytes) && bytes == 8298496);
	CHECK("mapping budget enforced", !kvm_capture_checked_map_size(UINT32_MAX, UINT32_MAX, UINT32_MAX, &bytes));
	CHECK("negative-origin layout accepted", kvm_capture_checked_layout_size(-1920, -1080, 3840, 2160, &width, &height) && width == 5760 && height == 3240);
	CHECK("unbounded layout rejected", !kvm_capture_checked_layout_size(INT64_MIN, 0, INT64_MAX, 1080, &width, &height));
	CHECK("single primary plane accepted", kvm_capture_plane_topology_supported(1, 0));
	CHECK("primary plus overlay rejected", !kvm_capture_plane_topology_supported(2, 0));
	CHECK("ambiguous active planes rejected", !kvm_capture_plane_topology_supported(1, 1));
}

static void test_capture_states(void)
{
	CHECK("detached state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_DETACHED), "detached") == 0);
	CHECK("discovering state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_DISCOVERING), "discovering") == 0);
	CHECK("capturing state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_CAPTURING), "capturing") == 0);
	CHECK("suspended state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_SUSPENDED), "temporarily-suspended") == 0);
	CHECK("recovering state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_RECOVERING), "recovering") == 0);
	CHECK("failed state named", strcmp(kvm_capture_state_name(KVM_CAPTURE_STATE_FAILED), "failed") == 0);
}

static int dmabuf_wait(void *context, unsigned int timeout_ms)
{
	dmabuf_fixture *fixture = (dmabuf_fixture *)context;
	++fixture->wait_calls;
	fixture->timeout_ms = timeout_ms;
	return fixture->wait_result;
}

static int dmabuf_sync(void *context, int start)
{
	dmabuf_fixture *fixture = (dmabuf_fixture *)context;
	++fixture->sync_calls;
	fixture->last_start = start;
	return fixture->sync_result;
}

static void test_dmabuf_sync(void)
{
	dmabuf_fixture fixture;
	kvm_dmabuf_access_ops ops;
	char error[128];

	memset(&fixture, 0, sizeof(fixture));
	memset(&ops, 0, sizeof(ops));
	ops.context = &fixture;
	ops.wait_readable = dmabuf_wait;
	ops.sync = dmabuf_sync;
	fixture.wait_result = 1;
	CHECK("DMA-BUF start waits then synchronizes", kvm_dmabuf_cpu_access(&ops, 1, error, sizeof(error)) &&
		fixture.wait_calls == 1 && fixture.sync_calls == 1 && fixture.last_start == 1 && fixture.timeout_ms == 100);

	memset(&fixture, 0, sizeof(fixture));
	fixture.wait_result = 0;
	CHECK("DMA-BUF timeout blocks CPU access", !kvm_dmabuf_cpu_access(&ops, 1, error, sizeof(error)) &&
		fixture.wait_calls == 1 && fixture.sync_calls == 0 && strstr(error, "Timed out") != NULL);

	memset(&fixture, 0, sizeof(fixture));
	fixture.wait_result = -5;
	CHECK("DMA-BUF producer wait failure is actionable", !kvm_dmabuf_cpu_access(&ops, 1, error, sizeof(error)) &&
		fixture.sync_calls == 0 && strstr(error, "Failed waiting") != NULL && strstr(error, "errno=5") != NULL);

	memset(&fixture, 0, sizeof(fixture));
	fixture.wait_result = 1;
	fixture.sync_result = -5;
	CHECK("DMA-BUF start failure is actionable", !kvm_dmabuf_cpu_access(&ops, 1, error, sizeof(error)) &&
		fixture.sync_calls == 1 && strstr(error, "start failed") != NULL && strstr(error, "errno=5") != NULL);

	memset(&fixture, 0, sizeof(fixture));
	fixture.sync_result = -22;
	CHECK("DMA-BUF end failure skips producer wait", !kvm_dmabuf_cpu_access(&ops, 0, error, sizeof(error)) &&
		fixture.wait_calls == 0 && fixture.sync_calls == 1 && fixture.last_start == 0 && strstr(error, "end failed") != NULL);
}

static int remember_release(void *context, unsigned int code)
{
	released_codes *released = (released_codes *)context;
	if (released->count < (int)(sizeof(released->codes) / sizeof(released->codes[0])))
	{
		released->codes[released->count++] = code;
	}
	return code == 42 ? -1 : 0;
}

static void test_unicode_input(void)
{
    kvm_input_state state = {0};
    uint32_t cp = 0;
    CHECK("BMP Unicode remains unchanged", kvm_input_state_unicode(&state, 0x4e2d, 0, 10, &cp) && cp == 0x4e2d);
    CHECK("high surrogate waits", !kvm_input_state_unicode(&state, 0xd83d, 0, 20, &cp));
    CHECK("browser high key-up preserves pair", !kvm_input_state_unicode(&state, 0xd83d, 1, 21, &cp));
    CHECK("emoji pair becomes one scalar", kvm_input_state_unicode(&state, 0xde00, 0, 22, &cp) && cp == 0x1f600);
    CHECK("low key-up does not repeat text", !kvm_input_state_unicode(&state, 0xde00, 1, 23, &cp));
    CHECK("orphan low surrogate discarded", !kvm_input_state_unicode(&state, 0xde00, 0, 24, &cp));
    kvm_input_state_unicode(&state, 0xd800, 0, 30, &cp);
    CHECK("minimum supplementary scalar", kvm_input_state_unicode(&state, 0xdc00, 0, 31, &cp) && cp == 0x10000);
    kvm_input_state_unicode(&state, 0xdbff, 0, 40, &cp);
    CHECK("maximum Unicode scalar", kvm_input_state_unicode(&state, 0xdfff, 0, 41, &cp) && cp == 0x10ffff);
    kvm_input_state_unicode(&state, 0xd83d, 0, 50, &cp);
    kvm_input_state_unicode(&state, 0xd800, 0, 51, &cp);
    CHECK("new high replaces incomplete pair", kvm_input_state_unicode(&state, 0xdc00, 0, 52, &cp) && cp == 0x10000);
    kvm_input_state_unicode(&state, 0xd83d, 0, 60, &cp);
    CHECK("BMP cancels high without losing text", kvm_input_state_unicode(&state, 'A', 0, 61, &cp) && cp == 'A');
    CHECK("low cannot span intervening text", !kvm_input_state_unicode(&state, 0xde00, 0, 62, &cp));
    kvm_input_state_unicode(&state, 0xd83d, 0, 70, &cp);
    kvm_input_state_cancel_unicode(&state);
    CHECK("non-text input cancels pair", !kvm_input_state_unicode(&state, 0xde00, 0, 71, &cp));
    kvm_input_state_unicode(&state, 0xd83d, 0, 80, &cp);
    kvm_input_state_release_all(&state, NULL, NULL);
    CHECK("cleanup cannot leak pair into new session", !kvm_input_state_unicode(&state, 0xde00, 0, 81, &cp));
    kvm_input_state_unicode(&state, 0xd83d, 0, 100, &cp);
    CHECK("pair timeout boundary accepted", kvm_input_state_unicode(&state, 0xde00, 0, 1100, &cp) && cp == 0x1f600);
    kvm_input_state_unicode(&state, 0xd83d, 0, 2000, &cp);
    CHECK("expired pair discarded", !kvm_input_state_unicode(&state, 0xde00, 0, 3001, &cp));
    kvm_input_state_unicode(&state, 0xd83d, 0, 4000, &cp);
    CHECK("backwards clock cannot retain pair", !kvm_input_state_unicode(&state, 0xde00, 0, 3999, &cp));
    CHECK("next valid text recovers", kvm_input_state_unicode(&state, 'B', 0, 5000, &cp) && cp == 'B');
}

static void test_input_cleanup(void)
{
	kvm_input_state state;
	released_codes released;
	memset(&state, 0, sizeof(state));
	memset(&released, 0, sizeof(released));
	kvm_input_state_set(&state, 42, 1);
	kvm_input_state_set(&state, 30, 1);
	kvm_input_state_set(&state, 30, 1);
	kvm_input_state_set(&state, 30, 0);
	kvm_input_state_set(&state, 272, 1);
	CHECK("held keys and buttons released once", kvm_input_state_release_all(&state, remember_release, &released) == 2);
	CHECK("release continues after injection failure", released.count == 2 && released.codes[0] == 42 && released.codes[1] == 272);
	CHECK("released state cannot cross generation", kvm_input_state_release_all(&state, remember_release, &released) == 0 && released.count == 2);
	kvm_input_state_set(&state, KVM_INPUT_STATE_MAX_CODE + 1, 1);
	CHECK("out-of-range input state ignored", kvm_input_state_release_all(&state, remember_release, &released) == 0);
}

#if !defined(KVM_TEST_NO_SESSION)
static void test_session_identity(void)
{
	char root[] = "/tmp/meshagent-wayland-test-XXXXXX";
	char path[512];
	kvm_wayland_console_session first;
	kvm_wayland_console_session second;
	kvm_wayland_console_session changedState;
	int fixtureReady = 1;

	if (mkdtemp(root) == NULL) { perror("mkdtemp"); ++g_failed; return; }
	snprintf(path, sizeof(path), "%s/systemd", root); fixtureReady &= mkdir(path, 0700) == 0;
	snprintf(path, sizeof(path), "%s/systemd/seats", root); fixtureReady &= mkdir(path, 0700) == 0;
	snprintf(path, sizeof(path), "%s/systemd/sessions", root); fixtureReady &= mkdir(path, 0700) == 0;
	snprintf(path, sizeof(path), "%s/systemd/seats/seat0", root); fixtureReady &= write_text(path, "ACTIVE=c1\n");
	snprintf(path, sizeof(path), "%s/systemd/sessions/c1", root); fixtureReady &= write_text(path, "UID=120\nTYPE=wayland\nSTATE=active\n");
	CHECK("session fixture created", fixtureReady);
	CHECK("greeter session parsed", fixtureReady && kvm_wayland_read_console_session_files(root, &first));
	CHECK("greeter fields preserved", first.uid == 120 && strcmp(first.id, "c1") == 0 && strcmp(first.type, "wayland") == 0);

	changedState = first;
	snprintf(changedState.state, sizeof(changedState.state), "closing");
	CHECK("state-only notification preserves generation", kvm_wayland_console_session_equal(&first, &changedState));

	snprintf(path, sizeof(path), "%s/systemd/seats/seat0", root); fixtureReady &= write_text(path, "ACTIVE=c2\n");
	CHECK("stale new endpoint rejected", !kvm_wayland_read_console_session_files(root, &second));
	snprintf(path, sizeof(path), "%s/systemd/sessions/c2", root); fixtureReady &= write_text(path, "UID=120\nTYPE=wayland\nSTATE=active\n");
	CHECK("same-uid replacement parsed", kvm_wayland_read_console_session_files(root, &second));
	CHECK("same uid new session changes generation", !kvm_wayland_console_session_equal(&first, &second));

	snprintf(path, sizeof(path), "%s/systemd/seats/seat0", root); fixtureReady &= write_text(path, "ACTIVE=../escape\n");
	CHECK("path traversal session id rejected", !kvm_wayland_read_console_session_files(root, &second));
	snprintf(path, sizeof(path), "%s/systemd/seats/seat0", root); fixtureReady &= write_text(path, "ACTIVE=c2\n");
	snprintf(path, sizeof(path), "%s/systemd/sessions/c2", root); fixtureReady &= write_text(path, "UID=120junk\nTYPE=wayland\nSTATE=active\n");
	CHECK("invalid uid rejected", !kvm_wayland_read_console_session_files(root, &second));

	snprintf(path, sizeof(path), "%s/systemd/sessions/c1", root); unlink(path);
	snprintf(path, sizeof(path), "%s/systemd/sessions/c2", root); unlink(path);
	snprintf(path, sizeof(path), "%s/systemd/seats/seat0", root); unlink(path);
	snprintf(path, sizeof(path), "%s/systemd/sessions", root); rmdir(path);
	snprintf(path, sizeof(path), "%s/systemd/seats", root); rmdir(path);
	snprintf(path, sizeof(path), "%s/systemd", root); rmdir(path);
	rmdir(root);
}
#endif

static void test_scaling(void)
{
    CHECK("scaled pointer right edge", kvm_capture_source_coordinate(1919,3840,1920)==3839);
    CHECK("scaled pointer clamps outside", kvm_capture_source_coordinate(1920,3840,1920)==3839);
    CHECK("single pixel pointer", kvm_capture_source_coordinate(0,17,1)==0);
    CHECK("enlarged pointer edge", kvm_capture_source_coordinate(67,17,68)==16);
    uint32_t w,h;
    CHECK("half size quarter pixels", kvm_capture_scaled_size(3840,2160,512,&w,&h) && w==1920 && h==1080);
    CHECK("minimum scale", kvm_capture_scaled_size(17,9,64,&w,&h) && w==1 && h==1);
    CHECK("enlargement", kvm_capture_scaled_size(17,9,4096,&w,&h) && w==68 && h==36);
    CHECK("scaled allocation cap", !kvm_capture_scaled_size(16384,16384,4096,&w,&h));
    unsigned char src[12]={0,0,0,100,100,100,100,100,100,200,200,200},dst[27];
    kvm_capture_scale_rgb(src,2,2,dst,3,3);
    CHECK("bilinear endpoints and center", dst[0]==0 && dst[12]==100 && dst[26]==200);
    kvm_capture_scale_rgb(src,2,2,dst,2,2);
    CHECK("identity pixels", memcmp(src,dst,12)==0);
}

static void test_linear_copy(void)
{
    unsigned char source[320], target[320];
    for(size_t i=0;i<sizeof(source);++i)source[i]=(unsigned char)(i*71u);
    int equal=1,guards=1;
    for(size_t s=0;s<32;++s)for(size_t d=0;d<32;++d)for(size_t n=0;n<=257;++n)
    {
        memset(target,0xa5,sizeof(target));
        kvm_capture_copy_linear(target+d,source+s,n);
        if(memcmp(target+d,source+s,n))equal=0;
        for(size_t i=0;i<d;++i)if(target[i]!=0xa5)guards=0;
        for(size_t i=d+n;i<sizeof(target);++i)if(target[i]!=0xa5)guards=0;
    }
    CHECK("linear copy all alignments and tails",equal);
    CHECK("linear copy preserves destination guards",guards);
    kvm_capture_copy_linear(NULL,NULL,0);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *s=mmap(NULL,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    unsigned char *d=mmap(NULL,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK("linear copy guard maps",s!=MAP_FAILED&&d!=MAP_FAILED);
    if(s!=MAP_FAILED&&d!=MAP_FAILED)
    {
        CHECK("linear copy guard permissions",mprotect(s+page,page,PROT_READ|PROT_WRITE)==0&&mprotect(d+page,page,PROT_READ|PROT_WRITE)==0);
        memset(s+page,0x73,page);
        for(size_t n=0;n<=130;++n)
        {
            kvm_capture_copy_linear(d+page*2-n,s+page*2-n,n);
            CHECK("linear copy never crosses a guard page",memcmp(d+page*2-n,s+page*2-n,n)==0);
        }
        kvm_capture_copy_linear(d+page,s+page,page);
        CHECK("linear copy full page",memcmp(d+page,s+page,page)==0);
    }
    if(s!=MAP_FAILED)munmap(s,page*3);
    if(d!=MAP_FAILED)munmap(d,page*3);
}

static void test_rgb32_rows(void)
{
    const unsigned channels[4][3] = {{2,1,0},{0,1,2},{3,2,1},{1,2,3}};
    const size_t widths[] = {0,1,2,3,4,5,15,16,17,31,32,33,65,3840};
    for (unsigned order=0;order<4;++order) for (unsigned align=0;align<16;++align)
    for (unsigned wi=0;wi<sizeof(widths)/sizeof(widths[0]);++wi)
    {
        size_t width=widths[wi],srcSize=width*4+32,dstSize=width*3+32;
        unsigned char *src=malloc(srcSize),*dst=malloc(dstSize),*expected=malloc(dstSize);
        memset(dst,0xA7,dstSize);memset(expected,0xA7,dstSize);
        for(size_t i=0;i<srcSize;++i)src[i]=(unsigned char)(i*37+i/13);
        for(size_t i=0;i<width;++i)for(unsigned c=0;c<3;++c)
            expected[15-align+i*3+c]=src[align+i*4+channels[order][c]];
        kvm_capture_rgb32_row(dst+15-align,src+align,width,channels[order][0],channels[order][1],channels[order][2]);
        CHECK("RGB32 conversion and exact write bounds",memcmp(dst,expected,dstSize)==0);
        free(src);free(dst);free(expected);
    }
}

int main(void)
{
    test_rgb32_rows();
    test_linear_copy();
    test_scaling();
	test_recovery_policy();
	test_capture_limits();
	test_display_wake_policy();
	test_capture_failure_budget();
	test_capture_states();
	test_dmabuf_sync();
	test_input_cleanup();
	test_unicode_input();
#if !defined(KVM_TEST_NO_SESSION)
	test_session_identity();
#else
	g_skipped += 9;
#endif
	printf("linux-kvm-wayland-tests: %d passed, %d failed, %d skipped\n", g_passed, g_failed, g_skipped);
	return g_failed == 0 ? 0 : 1;
}
