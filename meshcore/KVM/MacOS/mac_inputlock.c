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

// The macOS counterpart of BlockInput() in the Windows KVM: an active event tap drops every input event this process did not post itself.
// The tap needs the Accessibility grant, which the KVM already has to post the viewer's input. It is only enabled while locked,
// and macOS switches a tap off when its thread stops answering, so a hung agent cannot keep the local user out.
// Two more taps note when the local mouse and keyboard are used, so the viewer's input can back off instead of fighting the local user.

#include "mac_inputlock.h"
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// Gesture, rotate, magnify, swipe and pressure events from the trackpad have no CGEventType names
#define KVM_LOCK_TRACKPAD_TYPES ((1ULL << 18) | (1ULL << 19) | (1ULL << 20) | (1ULL << 29) | (1ULL << 30) | (1ULL << 31) | (1ULL << 32) | (1ULL << 34))
// Media, volume and brightness keys arrive as NX_SYSDEFINED
#define KVM_LOCK_SYSDEFINED_TYPE (1ULL << 14)
// After the local user uses the mouse or keyboard, the viewer's mouse and keyboard are both ignored for this long, so neither side mistypes or misclicks into the other's work
#define KVM_LOCAL_INPUT_BACKOFF_MS 4000

static pthread_mutex_t g_lockMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_lockReady = PTHREAD_COND_INITIALIZER;
static CFMachPortRef g_lockTap = NULL;
static CFMachPortRef g_watchTap = NULL;
static CFMachPortRef g_keyWatchTap = NULL;
static int g_lockThreadState = 0;	// 0 not started, 1 running, -1 no tap could be made
static int g_lockState = 0;
static int g_watchState = 0;
static uint64_t g_localInputMs = 0;
static pid_t g_lockPid = 0;

static uint64_t kvm_inputlock_now(void)
{
	return(clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000);
}

static CGEventRef kvm_inputlock_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *user)
{
	(void)proxy; (void)user;
	if (type == kCGEventTapDisabledByTimeout)
	{
		// The thread was slow but answers again, so the lock goes back on if it is still wanted
		if (__atomic_load_n(&g_lockState, __ATOMIC_RELAXED)) { CGEventTapEnable(g_lockTap, true); }
		return(event);
	}
	if (type == kCGEventTapDisabledByUserInput)
	{
		// macOS switched the tap off for the local user, for example for secure input, and that is respected
		__atomic_store_n(&g_lockState, 0, __ATOMIC_RELAXED);
		return(event);
	}

	// The viewer's input is posted by this process, everything else comes from the local devices
	return(CGEventGetIntegerValueField(event, kCGEventSourceUnixProcessID) == g_lockPid ? event : NULL);
}

static CGEventRef kvm_watch_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *user)
{
	(void)proxy; (void)user;
	if (type == kCGEventTapDisabledByTimeout || type == kCGEventTapDisabledByUserInput)
	{
		if (__atomic_load_n(&g_watchState, __ATOMIC_RELAXED)) { CGEventTapEnable(g_watchTap, true); }
		return(event);
	}
	if (CGEventGetIntegerValueField(event, kCGEventSourceUnixProcessID) != g_lockPid) { __atomic_store_n(&g_localInputMs, kvm_inputlock_now(), __ATOMIC_RELAXED); }
	return(event);
}

// Active, because a listen-only tap gets key events only with the Input Monitoring grant, and it hands every event back unchanged
static CGEventRef kvm_keywatch_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *user)
{
	(void)proxy; (void)user;
	if (type == kCGEventTapDisabledByTimeout || type == kCGEventTapDisabledByUserInput)
	{
		if (__atomic_load_n(&g_watchState, __ATOMIC_RELAXED)) { CGEventTapEnable(g_keyWatchTap, true); }
		return(event);
	}
	if (CGEventGetIntegerValueField(event, kCGEventSourceUnixProcessID) != g_lockPid) { __atomic_store_n(&g_localInputMs, kvm_inputlock_now(), __ATOMIC_RELAXED); }
	return(event);
}

// Makes the tap disabled and adds it to this thread's run loop, returns NULL when it cannot be made
static CFMachPortRef kvm_inputlock_tap(CGEventTapLocation location, CGEventTapPlacement placement, CGEventTapOptions options, CGEventMask mask, CGEventTapCallBack callback)
{
	CFMachPortRef tap;
	CFRunLoopSourceRef source;

	if ((tap = CGEventTapCreate(location, placement, options, mask, callback, NULL)) == NULL) { return(NULL); }
	CGEventTapEnable(tap, false);
	if ((source = CFMachPortCreateRunLoopSource(NULL, tap, 0)) == NULL) { CFRelease(tap); return(NULL); }
	CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
	CFRelease(source);
	return(tap);
}

static void *kvm_inputlock_thread(void *arg)
{
	CGEventMask lockMask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventKeyUp) | CGEventMaskBit(kCGEventFlagsChanged) |
		CGEventMaskBit(kCGEventLeftMouseDown) | CGEventMaskBit(kCGEventLeftMouseUp) | CGEventMaskBit(kCGEventLeftMouseDragged) |
		CGEventMaskBit(kCGEventRightMouseDown) | CGEventMaskBit(kCGEventRightMouseUp) | CGEventMaskBit(kCGEventRightMouseDragged) |
		CGEventMaskBit(kCGEventOtherMouseDown) | CGEventMaskBit(kCGEventOtherMouseUp) | CGEventMaskBit(kCGEventOtherMouseDragged) |
		CGEventMaskBit(kCGEventMouseMoved) | CGEventMaskBit(kCGEventScrollWheel) | CGEventMaskBit(kCGEventTabletPointer) |
		CGEventMaskBit(kCGEventTabletProximity) | KVM_LOCK_TRACKPAD_TYPES | KVM_LOCK_SYSDEFINED_TYPE;
	CGEventMask watchMask = CGEventMaskBit(kCGEventMouseMoved) | CGEventMaskBit(kCGEventLeftMouseDown) | CGEventMaskBit(kCGEventRightMouseDown) |
		CGEventMaskBit(kCGEventOtherMouseDown) | CGEventMaskBit(kCGEventLeftMouseDragged) | CGEventMaskBit(kCGEventRightMouseDragged) |
		CGEventMaskBit(kCGEventOtherMouseDragged) | CGEventMaskBit(kCGEventScrollWheel);
	CGEventMask keyMask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventKeyUp) | CGEventMaskBit(kCGEventFlagsChanged) | KVM_LOCK_SYSDEFINED_TYPE;
	CFMachPortRef lockTap, watchTap, keyWatchTap;
	(void)arg;

	lockTap = kvm_inputlock_tap(kCGHIDEventTap, kCGHeadInsertEventTap, kCGEventTapOptionDefault, lockMask, kvm_inputlock_callback);
	// Listen-only, so a slow agent never holds up the local mouse, and behind the lock tap, so locked input does not count as local use
	watchTap = kvm_inputlock_tap(kCGHIDEventTap, kCGTailAppendEventTap, kCGEventTapOptionListenOnly, watchMask, kvm_watch_callback);
	keyWatchTap = kvm_inputlock_tap(kCGHIDEventTap, kCGTailAppendEventTap, kCGEventTapOptionDefault, keyMask, kvm_keywatch_callback);

	pthread_mutex_lock(&g_lockMutex);
	g_lockTap = lockTap;
	g_watchTap = watchTap;
	g_keyWatchTap = keyWatchTap;
	g_lockThreadState = (lockTap != NULL || watchTap != NULL || keyWatchTap != NULL) ? 1 : -1;
	pthread_cond_signal(&g_lockReady);
	pthread_mutex_unlock(&g_lockMutex);

	// Runs until the process ends
	if (g_lockThreadState == 1) { CFRunLoopRun(); }
	return(NULL);
}

// Called with g_lockMutex held, starts the tap thread once and waits until its taps are made
static void kvm_inputlock_start(void)
{
	pthread_t thread;

	if (g_lockThreadState != 0) { return; }
	g_lockPid = getpid();
	if (pthread_create(&thread, NULL, kvm_inputlock_thread, NULL) != 0) { g_lockThreadState = -1; return; }
	pthread_detach(thread);
	while (g_lockThreadState == 0) { pthread_cond_wait(&g_lockReady, &g_lockMutex); }
}

int kvm_inputlock_set(int lock)
{
	pthread_mutex_lock(&g_lockMutex);
	if (lock) { kvm_inputlock_start(); }
	if (g_lockTap != NULL)
	{
		__atomic_store_n(&g_lockState, lock ? 1 : 0, __ATOMIC_RELAXED);
		CGEventTapEnable(g_lockTap, lock ? true : false);
	}
	pthread_mutex_unlock(&g_lockMutex);
	return(kvm_inputlock_get());
}

int kvm_inputlock_get(void)
{
	return(__atomic_load_n(&g_lockState, __ATOMIC_RELAXED));
}

void kvm_inputlock_watch(int on)
{
	pthread_mutex_lock(&g_lockMutex);
	// A new viewer does not inherit the previous session's backoff
	__atomic_store_n(&g_localInputMs, 0, __ATOMIC_RELAXED);
	if (on) { kvm_inputlock_start(); }
	__atomic_store_n(&g_watchState, on ? 1 : 0, __ATOMIC_RELAXED);
	if (g_watchTap != NULL) { CGEventTapEnable(g_watchTap, on ? true : false); }
	if (g_keyWatchTap != NULL) { CGEventTapEnable(g_keyWatchTap, on ? true : false); }
	pthread_mutex_unlock(&g_lockMutex);
}

int kvm_local_input_active(void)
{
	uint64_t last = __atomic_load_n(&g_localInputMs, __ATOMIC_RELAXED);
	return(last != 0 && kvm_inputlock_now() < last + KVM_LOCAL_INPUT_BACKOFF_MS);
}
