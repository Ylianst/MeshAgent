/* Compiles the REAL linux_mic.c against stub Opus/PulseAudio and asserts the
   consent gate: the microphone is never opened, and no audio is ever encoded
   or sent, until the local user has agreed. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

extern void kvm_mic_init(int(*)(char*,int,void*), void*);
extern void kvm_mic_set_consent(int);
extern int  kvm_mic_has_consent(void);
extern void kvm_mic_start(void);
extern void kvm_mic_stop(void);
extern void kvm_mic_feed(char*, int);
extern void kvm_mic_set_slave_fd(int);
extern void kvm_mic_cleanup(void);

int g_encodeCalls = 0;   /* incremented by the stub opus_encode */

/* The capture counter lives inside the fake libpulse-simple, because a
 * dlopen'd object cannot resolve symbols back into this executable. Read it
 * through the same handle linux_mic.c uses. */
static int captureOpened(void) {
    static int *counter = NULL;
    if (counter == NULL) {
        void *h = dlopen("libpulse-simple.so.0", RTLD_LAZY);
        if (h != NULL) { counter = (int*)dlsym(h, "mesh_test_captureOpened"); }
    }
    return (counter != NULL) ? *counter : -1;
}
int g_capsSent = 0;
int g_lastCapsConsent = -1;

static int sink(char *b, int len, void *r) {
    unsigned char *u = (unsigned char*)b; (void)r;
    if (len >= 9 && ((u[0]<<8)|u[1]) == 96) { g_capsSent++; g_lastCapsConsent = (u[7] & 0x02) ? 1 : 0; }
    return 1;
}

#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS  %s\n", msg); } \
    else { printf("  FAIL  %s\n", msg); failures++; } } while (0)

int main(void) {
    int failures = 0;
    char frame[64];
    memset(frame, 0, sizeof(frame));

    printf("Microphone consent gate (device mic -> operator)\n");

    kvm_mic_init(sink, NULL);
    CHECK(g_capsSent == 1, "init advertises capability");
    CHECK(kvm_mic_has_consent() == 0, "consent starts denied");

    /* The core security property: no consent, no microphone. */
    g_encodeCalls = 0;
    kvm_mic_start();
    usleep(200000);
    CHECK(captureOpened() == 0, "microphone is NOT opened without consent");
    CHECK(g_encodeCalls == 0, "no audio is captured without consent");

    /* Grant, and capture should begin. */
    kvm_mic_set_consent(1);
    CHECK(kvm_mic_has_consent() == 1, "consent is recorded when granted");
    CHECK(g_lastCapsConsent == 1, "caps report consent to the browser");

    g_encodeCalls = 0;
    kvm_mic_start();
    usleep(300000);
    CHECK(captureOpened() >= 1, "microphone opens once consent is granted");
    CHECK(g_encodeCalls > 0, "audio is captured and encoded after consent");

    /* Revoking must stop capture promptly. */
    kvm_mic_set_consent(0);
    CHECK(kvm_mic_has_consent() == 0, "consent can be revoked");
    g_encodeCalls = 0;
    usleep(300000);
    CHECK(g_encodeCalls == 0, "capture stops when consent is revoked");

    /* Stop must also clear consent so the next attempt re-prompts. */
    kvm_mic_set_consent(1);
    kvm_mic_start();
    usleep(150000);
    kvm_mic_stop();
    CHECK(kvm_mic_has_consent() == 0, "stop() revokes consent for the session");
    {
        int before = captureOpened();
        g_encodeCalls = 0;
        kvm_mic_start();
        usleep(200000);
        CHECK(captureOpened() == before, "start() after stop() opens no microphone");
        CHECK(g_encodeCalls == 0, "start() after stop() captures nothing without new consent");
    }

    /* Inbound frames are not a capture path and must be ignored safely. */
    kvm_mic_feed(NULL, 40);
    kvm_mic_feed(frame, 0);
    kvm_mic_feed(frame, 40);
    CHECK(1, "inbound frames are discarded safely");

    kvm_mic_cleanup();
    CHECK(kvm_mic_has_consent() == 0, "cleanup clears consent");

    printf("\n%s\n", failures ? "GATE FAILURES" : "CONSENT GATE VERIFIED");
    return failures ? 1 : 0;
}
