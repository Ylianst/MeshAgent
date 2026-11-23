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
// The frame loop compares and encodes the stream's own BGRA pixel buffer in place, so a frame is neither converted nor copied.

#import <ScreenCaptureKit/ScreenCaptureKit.h>
#include <pthread.h>
#include "mac_tile.h"
#include "mac_sck.h"

// The makefile builds for macOS 10.12 and 11, and ScreenCaptureKit is weak-linked: its classes are there from macOS 12.3.
// On an older macOS they are nil, which kvm_sck_available() reports, so the availability warnings are silenced.
#pragma clang diagnostic ignored "-Wunguarded-availability-new"

static pthread_mutex_t g_sckLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sckReady = PTHREAD_COND_INITIALIZER;
static CVPixelBufferRef g_sckPending = NULL;	// The newest frame the loop has not taken yet
static CVPixelBufferRef g_sckHeld = NULL;		// The frame the loop took last, locked for reading, touched by the loop's thread only
static int g_sckRunning = 0;
static int g_sckFailed = 0;
static SCStream *g_sckStream = nil;
static id g_sckOutput = nil;
static SCStreamConfiguration *g_sckConfig = nil; // Kept because a new frame interval is set by updating the whole configuration

@interface KvmStreamOutput : NSObject <SCStreamOutput, SCStreamDelegate>
@end

@implementation KvmStreamOutput

- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type
{
	CFArrayRef infos;
	NSDictionary *info;
	CVPixelBufferRef px;

	if (type != SCStreamOutputTypeScreen) { return; }

	// Only a complete frame holds a new picture, idle ones mean nothing changed
	infos = CMSampleBufferGetSampleAttachmentsArray(sample, false);
	if (infos == NULL || CFArrayGetCount(infos) == 0) { return; }
	info = (__bridge NSDictionary *)CFArrayGetValueAtIndex(infos, 0);
	if ([info[SCStreamFrameInfoStatus] integerValue] != SCFrameStatusComplete) { return; }
	if ((px = CMSampleBufferGetImageBuffer(sample)) == NULL) { return; }

	// A frame the loop has not taken yet is replaced, so the stream never waits on the loop and the loop gets the newest picture
	pthread_mutex_lock(&g_sckLock);
	if (g_sckRunning)
	{
		if (g_sckPending != NULL) { CVPixelBufferRelease(g_sckPending); }
		g_sckPending = CVPixelBufferRetain(px);
		pthread_cond_signal(&g_sckReady);
	}
	pthread_mutex_unlock(&g_sckLock);
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
	g_sckFailed = 0;
	g_sckRunning = 1;
	pthread_mutex_unlock(&g_sckLock);

	g_sckConfig = [[SCStreamConfiguration alloc] init];
	g_sckConfig.width = (size_t)width;
	g_sckConfig.height = (size_t)height;
	g_sckConfig.pixelFormat = kCVPixelFormatType_32BGRA;
	g_sckConfig.colorSpaceName = kCGColorSpaceSRGB; // The JPEG carries no profile, so a viewer reads it as sRGB
	g_sckConfig.showsCursor = NO; // The viewer draws the pointer from the shape mac_cursor.c sends
	g_sckConfig.minimumFrameInterval = CMTimeMake(intervalMs, 1000);
	g_sckConfig.queueDepth = 3; // The loop holds at most two of them, the one it works on and the newest

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

static void sck_release_held(void)
{
	if (g_sckHeld == NULL) { return; }
	CVPixelBufferUnlockBaseAddress(g_sckHeld, kCVPixelBufferLock_ReadOnly);
	CVPixelBufferRelease(g_sckHeld);
	g_sckHeld = NULL;
}

int kvm_sck_take_frame(struct tileFrame_t *frame, int timeoutMs)
{
	// A relative wait, because a deadline on the wall clock moves when the clock is set
	struct timespec wait = { timeoutMs / 1000, (long)(timeoutMs % 1000) * 1000000L };
	CVPixelBufferRef px;
	int stopped;

	pthread_mutex_lock(&g_sckLock);
	if (g_sckPending == NULL && !g_sckFailed && g_sckRunning) { pthread_cond_timedwait_relative_np(&g_sckReady, &g_sckLock, &wait); }
	stopped = g_sckFailed || !g_sckRunning;
	px = stopped ? NULL : g_sckPending;
	if (px != NULL) { g_sckPending = NULL; }
	pthread_mutex_unlock(&g_sckLock);

	if (stopped) { return(-1); }
	if (px == NULL) { return(0); }

	// The frame taken before stays held until here, so kvm_sck_last_frame() can hand it out while the screen is still
	sck_release_held();
	if (CVPixelBufferLockBaseAddress(px, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) { CVPixelBufferRelease(px); return(0); }
	g_sckHeld = px;
	return(kvm_sck_last_frame(frame));
}

int kvm_sck_last_frame(struct tileFrame_t *frame)
{
	if (g_sckHeld == NULL) { return(0); }

	// 32BGRA lies in memory as blue, green, red and alpha, which libjpeg-turbo reads as BGRX
	frame->pixels = (const unsigned char *)CVPixelBufferGetBaseAddress(g_sckHeld);
	frame->stride = CVPixelBufferGetBytesPerRow(g_sckHeld);
	frame->bytesPerPixel = 4;
	frame->width = (int)CVPixelBufferGetWidth(g_sckHeld);
	frame->height = (int)CVPixelBufferGetHeight(g_sckHeld);
	frame->format = JCS_EXT_BGRX;
	if (frame->pixels == NULL) { sck_release_held(); return(0); }
	return(1);
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
	g_sckRunning = 0;
	if (g_sckPending != NULL) { CVPixelBufferRelease(g_sckPending); g_sckPending = NULL; }
	pthread_mutex_unlock(&g_sckLock);
	sck_release_held();
}
