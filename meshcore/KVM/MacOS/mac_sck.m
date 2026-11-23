/*
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

// ScreenCaptureKit delivers a frame only when the screen changed, at most one per minimumFrameInterval, so the frame loop no longer captures and checks unchanged screens.
// The frame is converted into the same padded RGB24 layout as getScreenBuffer(), so the tile code is unchanged.
// Only the areas the frame marks as changed are converted, with vImage.

#import <ScreenCaptureKit/ScreenCaptureKit.h>
#include <Accelerate/Accelerate.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "mac_sck.h"

// The makefile builds for macOS 10.12 and 11, and ScreenCaptureKit is weak-linked: its classes are there from macOS 12.3.
// On an older macOS they are nil, which kvm_sck_available() reports, so the availability warnings are silenced.
#pragma clang diagnostic ignored "-Wunguarded-availability-new"

extern int adjust_screen_size(int pixles);

static pthread_mutex_t g_sckLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sckReady = PTHREAD_COND_INITIALIZER;
static unsigned char *g_sckPending = NULL;	// Written by the stream, swapped with the frame loop's buffer
static long long g_sckPendingSize = 0;
static int g_sckNewFrame = 0;
static int g_sckFailed = 0;
static int g_sckWidth = 0;
static int g_sckHeight = 0;
static SCStream *g_sckStream = nil;
static id g_sckOutput = nil;
static SCStreamConfiguration *g_sckConfig = nil; // Kept because a new frame interval is set by updating the whole configuration

// The two buffers take turns, so each one misses the changes of the frames that went into the other while it was away.
// The areas a buffer misses are kept here and converted along with the next frame that goes into it.
#define SCK_MAX_AREAS 64
typedef struct { int all; int count; CGRect areas[SCK_MAX_AREAS]; } SckMissing;
static SckMissing g_sckPendingMissing;	// What g_sckPending lacks
static SckMissing g_sckLoopMissing;		// What the frame loop's buffer lacks, handed to g_sckPending when the buffers are swapped

static void sck_missing_all(SckMissing *m) { m->all = 1; m->count = 0; }
static void sck_missing_none(SckMissing *m) { m->all = 0; m->count = 0; }
static void sck_missing_add(SckMissing *m, CGRect area)
{
	if (m->all) { return; }
	if (m->count == SCK_MAX_AREAS) { sck_missing_all(m); return; }
	m->areas[m->count++] = area;
}

#ifdef KVM_SCK_STATS
// Test builds only: per frame, the changed area and the converted area as a share of the frame, and the time to lock the pixel buffer and to convert
static double g_statConverted = 0;
static void sck_stats(double dirtyPixels, double framePixels, uint64_t lockNs, uint64_t convertNs, int whole)
{
	static unsigned long frames = 0, wholeFrames = 0;
	static double dirtySum = 0, convertedSum = 0, lockSum = 0, convertSum = 0;

	frames++; wholeFrames += whole;
	dirtySum += dirtyPixels / framePixels; convertedSum += g_statConverted / framePixels; g_statConverted = 0;
	lockSum += lockNs / 1e6; convertSum += convertNs / 1e6;
	if (frames % 100 == 0)
	{
		FILE *f = fopen("/tmp/kvm-sck-stats.log", "a");
		if (f != NULL)
		{
			fprintf(f, "frames %lu whole %lu changed %.1f%% converted %.1f%% lock %.2f ms convert %.2f ms\n", frames, wholeFrames, 100 * dirtySum / frames, 100 * convertedSum / frames, lockSum / frames, convertSum / frames);
			fclose(f);
		}
	}
}
#endif

// Converts one area from BGRA to RGB24, clipped to the frame
static void sck_convert(const unsigned char *src, size_t srcStride, unsigned char *dst, size_t dstStride, int w, int h, CGRect area)
{
	int x0 = (int)floor(CGRectGetMinX(area)), y0 = (int)floor(CGRectGetMinY(area));
	int x1 = (int)ceil(CGRectGetMaxX(area)), y1 = (int)ceil(CGRectGetMaxY(area));
	vImage_Buffer s, d;

	if (x0 < 0) { x0 = 0; }
	if (y0 < 0) { y0 = 0; }
	if (x1 > w) { x1 = w; }
	if (y1 > h) { y1 = h; }
	if (x1 <= x0 || y1 <= y0) { return; }

	s.data = (void *)(src + (size_t)y0 * srcStride + (size_t)x0 * 4); s.height = (vImagePixelCount)(y1 - y0); s.width = (vImagePixelCount)(x1 - x0); s.rowBytes = srcStride;
	d.data = dst + (size_t)y0 * dstStride + (size_t)x0 * 3; d.height = s.height; d.width = s.width; d.rowBytes = dstStride;
#ifdef KVM_SCK_STATS
	g_statConverted += (double)s.width * s.height;
#endif
	// One thread, because vImage's own threads cost 15 to 28% more CPU for the same frames (mmac and macboom)
	vImageConvert_BGRA8888toRGB888(&s, &d, kvImageDoNotTile);
}

// Converts the areas one by one, or their bounding box once when that is not larger than the areas together
// ScreenCaptureKit marked 99% of the frame as changed even for a small animation, so the missed and the new areas were mostly the same screen twice.
static void sck_convert_areas(const unsigned char *src, size_t srcStride, unsigned char *dst, size_t dstStride, int w, int h, const CGRect *areas, int count)
{
	CGRect frame = CGRectMake(0, 0, w, h), box = CGRectNull;
	double sum = 0;
	int i;

	for (i = 0; i < count; i++)
	{
		CGRect c = CGRectIntersection(areas[i], frame);
		if (CGRectIsNull(c)) { continue; }
		sum += c.size.width * c.size.height;
		box = CGRectUnion(box, c);
	}
	if (CGRectIsNull(box)) { return; }
	if (box.size.width * box.size.height <= sum) { sck_convert(src, srcStride, dst, dstStride, w, h, box); return; }
	for (i = 0; i < count; i++) { sck_convert(src, srcStride, dst, dstStride, w, h, areas[i]); }
}

#ifdef KVM_SCK_VERIFY
// Test builds only: converts every frame in full as well and logs how many frames the area conversion got wrong
static void sck_verify(const unsigned char *src, size_t srcStride, size_t dstStride, int w, int h, int areas)
{
	static unsigned char *full = NULL;
	static size_t fullSize = 0;
	static unsigned long frames = 0, wrong = 0, areaSum = 0;
	int y, bad = 0;

	if (fullSize != dstStride * (size_t)h) { free(full); fullSize = dstStride * (size_t)h; full = (unsigned char *)malloc(fullSize); }
	if (full == NULL) { return; }
	sck_convert(src, srcStride, full, dstStride, w, h, CGRectMake(0, 0, w, h));
	for (y = 0; y < h && !bad; y++) { bad = memcmp(full + (size_t)y * dstStride, g_sckPending + (size_t)y * dstStride, (size_t)w * 3) != 0; }
	frames++; wrong += bad; areaSum += (unsigned long)areas;
	if (frames % 50 == 0)
	{
		FILE *f = fopen("/tmp/kvm-sck-verify.log", "a");
		if (f != NULL) { fprintf(f, "frames %lu wrong %lu areas per frame %.1f\n", frames, wrong, (double)areaSum / frames); fclose(f); }
	}
}
#endif

@interface KvmStreamOutput : NSObject <SCStreamOutput, SCStreamDelegate>
@end

@implementation KvmStreamOutput

- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type
{
	CFArrayRef infos;
	NSDictionary *info;
	CVPixelBufferRef px;
	const unsigned char *src;
	size_t srcStride, dstStride;
	int w, h, i, n, whole;
	NSArray *dirty;
	CGRect todo[2 * SCK_MAX_AREAS];

	if (type != SCStreamOutputTypeScreen) { return; }

	// Only a complete frame holds a new picture, idle ones mean nothing changed
	infos = CMSampleBufferGetSampleAttachmentsArray(sample, false);
	if (infos == NULL || CFArrayGetCount(infos) == 0) { return; }
	info = (__bridge NSDictionary *)CFArrayGetValueAtIndex(infos, 0);
	if ([info[SCStreamFrameInfoStatus] integerValue] != SCFrameStatusComplete) { return; }
	dirty = info[SCStreamFrameInfoDirtyRects]; // In pixels, nil means the whole frame

	if ((px = CMSampleBufferGetImageBuffer(sample)) == NULL) { return; }
#ifdef KVM_SCK_STATS
	uint64_t t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW), t1, t2;
	double dirtyPixels = 0;
#endif
	CVPixelBufferLockBaseAddress(px, kCVPixelBufferLock_ReadOnly);
	src = (const unsigned char *)CVPixelBufferGetBaseAddress(px);
	srcStride = CVPixelBufferGetBytesPerRow(px);
	w = (int)CVPixelBufferGetWidth(px);
	h = (int)CVPixelBufferGetHeight(px);

	pthread_mutex_lock(&g_sckLock);
	dstStride = (size_t)adjust_screen_size(g_sckWidth) * 3;
	if (src != NULL && g_sckPending != NULL && w <= g_sckWidth && h <= g_sckHeight)
	{
#ifdef KVM_SCK_STATS
		t1 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif
		// The areas this buffer missed, then the frame's own changed areas
		whole = g_sckPendingMissing.all || dirty == nil || dirty.count > SCK_MAX_AREAS;
		n = 0;
		if (!whole) { for (i = 0; i < g_sckPendingMissing.count; i++) { todo[n++] = g_sckPendingMissing.areas[i]; } }
		sck_missing_none(&g_sckPendingMissing);

		if (dirty == nil) { sck_missing_all(&g_sckLoopMissing); }
		for (id v in dirty)
		{
			CGRect area;
			// The header says NSValue, but macOS 26.7 hands a CGRect dictionary, and getValue: on it aborted the KVM
			if ([v isKindOfClass:[NSDictionary class]]) { if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)v, &area)) { area = CGRectMake(0, 0, w, h); } }
			else if ([v isKindOfClass:[NSValue class]]) { [(NSValue *)v getValue:&area size:sizeof(area)]; }
			else { area = CGRectMake(0, 0, w, h); }
			if (!whole) { todo[n++] = area; }
			sck_missing_add(&g_sckLoopMissing, area);
#ifdef KVM_SCK_STATS
			{ CGRect c = CGRectIntersection(area, CGRectMake(0, 0, w, h)); if (!CGRectIsNull(c)) { dirtyPixels += c.size.width * c.size.height; } }
#endif
		}

		// The padding stays zero from calloc()
		if (whole) { sck_convert(src, srcStride, g_sckPending, dstStride, w, h, CGRectMake(0, 0, w, h)); }
		else { sck_convert_areas(src, srcStride, g_sckPending, dstStride, w, h, todo, n); }
#ifdef KVM_SCK_STATS
		t2 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
		sck_stats(dirty == nil ? (double)w * h : dirtyPixels, (double)w * h, t1 - t0, t2 - t1, whole);
#endif
#ifdef KVM_SCK_VERIFY
		sck_verify(src, srcStride, dstStride, w, h, (int)dirty.count);
#endif
		g_sckNewFrame = 1;
		pthread_cond_signal(&g_sckReady);
	}
	pthread_mutex_unlock(&g_sckLock);
	CVPixelBufferUnlockBaseAddress(px, kCVPixelBufferLock_ReadOnly);
}

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error
{
	pthread_mutex_lock(&g_sckLock);
	g_sckFailed = 1;
	pthread_cond_signal(&g_sckReady);
	pthread_mutex_unlock(&g_sckLock);
}

@end

int kvm_sck_available(void)
{
	return(NSClassFromString(@"SCStream") != nil && NSClassFromString(@"SCShareableContent") != nil);
}

int kvm_sck_start(CGDirectDisplayID display, int width, int height, int intervalMs)
{
	__block SCDisplay *target = nil;
	__block int started = -1;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	SCContentFilter *filter;

	kvm_sck_stop();

	[SCShareableContent getShareableContentWithCompletionHandler:^(SCShareableContent *content, NSError *error) {
		for (SCDisplay *d in content.displays) { if (d.displayID == display) { target = d; } }
		dispatch_semaphore_signal(done);
	}];
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0 || target == nil) { return(-1); }

	pthread_mutex_lock(&g_sckLock);
	g_sckWidth = width;
	g_sckHeight = height;
	g_sckNewFrame = 0;
	g_sckFailed = 0;
	sck_missing_all(&g_sckPendingMissing);
	sck_missing_all(&g_sckLoopMissing);
	g_sckPendingSize = (long long)adjust_screen_size(width) * adjust_screen_size(height) * 3;
	g_sckPending = (unsigned char *)calloc(1, (size_t)g_sckPendingSize);
	pthread_mutex_unlock(&g_sckLock);
	if (g_sckPending == NULL) { return(-1); }

	g_sckConfig = [[SCStreamConfiguration alloc] init];
	g_sckConfig.width = (size_t)width;
	g_sckConfig.height = (size_t)height;
	g_sckConfig.pixelFormat = kCVPixelFormatType_32BGRA;
	g_sckConfig.colorSpaceName = kCGColorSpaceSRGB; // The JPEG carries no profile, so a viewer reads it as sRGB
	g_sckConfig.showsCursor = NO; // The viewer draws the pointer from the shape mac_cursor.c sends
	g_sckConfig.minimumFrameInterval = CMTimeMake(intervalMs, 1000);
	g_sckConfig.queueDepth = 3;

	filter = [[SCContentFilter alloc] initWithDisplay:target excludingWindows:@[]];
	g_sckOutput = [[KvmStreamOutput alloc] init];
	g_sckStream = [[SCStream alloc] initWithFilter:filter configuration:g_sckConfig delegate:g_sckOutput];
	if (![g_sckStream addStreamOutput:g_sckOutput type:SCStreamOutputTypeScreen sampleHandlerQueue:dispatch_queue_create("meshagent.kvm.sck", DISPATCH_QUEUE_SERIAL) error:nil])
	{
		kvm_sck_stop();
		return(-1);
	}

	[g_sckStream startCaptureWithCompletionHandler:^(NSError *error) {
		started = (error == nil) ? 0 : -1;
		dispatch_semaphore_signal(done);
	}];
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0) { started = -1; }
	if (started != 0) { kvm_sck_stop(); }
	return(started);
}

int kvm_sck_set_interval(int intervalMs)
{
	__block int updated = -1;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);

	if (g_sckStream == nil || g_sckConfig == nil) { return(-1); }
	g_sckConfig.minimumFrameInterval = CMTimeMake(intervalMs, 1000);
	[g_sckStream updateConfiguration:g_sckConfig completionHandler:^(NSError *error) {
		updated = (error == nil) ? 0 : -1;
		dispatch_semaphore_signal(done);
	}];
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0) { return(-1); }
	return(updated);
}

int kvm_sck_take_frame(unsigned char **desktop, long long *desktopsize, int timeoutMs)
{
	// A relative wait, because a deadline on the wall clock moves when the clock is set
	struct timespec wait = { timeoutMs / 1000, (long)(timeoutMs % 1000) * 1000000L };
	unsigned char *swap;
	int ret;

	pthread_mutex_lock(&g_sckLock);
	if (!g_sckNewFrame && !g_sckFailed && g_sckPending != NULL) { pthread_cond_timedwait_relative_np(&g_sckReady, &g_sckLock, &wait); }
	if (g_sckFailed || g_sckPending == NULL) { ret = -1; }
	else if (!g_sckNewFrame) { ret = 0; }
	else
	{
		// The stream gets the buffer the frame loop is done with, so a frame is converted once and never copied again
		if (*desktopsize != g_sckPendingSize)
		{
			free(*desktop);
			*desktop = (unsigned char *)calloc(1, (size_t)g_sckPendingSize);
			*desktopsize = (*desktop != NULL) ? g_sckPendingSize : 0;
			sck_missing_all(&g_sckLoopMissing);
		}
		swap = *desktop;
		*desktop = g_sckPending;
		g_sckPending = swap;
		g_sckPendingMissing = g_sckLoopMissing;
		sck_missing_none(&g_sckLoopMissing);
		g_sckNewFrame = 0;
		ret = (g_sckPending != NULL) ? 1 : -1;
	}
	pthread_mutex_unlock(&g_sckLock);
	return(ret);
}

void kvm_sck_stop(void)
{
	SCStream *stream = g_sckStream;

	if (stream != nil)
	{
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[stream stopCaptureWithCompletionHandler:^(NSError *error) { dispatch_semaphore_signal(done); }];
		dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
	}
	g_sckStream = nil;
	g_sckOutput = nil;
	g_sckConfig = nil;

	pthread_mutex_lock(&g_sckLock);
	free(g_sckPending);
	g_sckPending = NULL;
	g_sckPendingSize = 0;
	g_sckNewFrame = 0;
	pthread_mutex_unlock(&g_sckLock);
}
