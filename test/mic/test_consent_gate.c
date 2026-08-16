/* Compiles the REAL linux_mic.c against stub Opus/PulseAudio and asserts the
   consent gate: no frame may reach the decoder until consent is granted. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern void kvm_mic_init(int(*)(char*,int,void*), void*);
extern void kvm_mic_set_consent(int);
extern int  kvm_mic_has_consent(void);
extern void kvm_mic_start(void);
extern void kvm_mic_stop(void);
extern void kvm_mic_feed(char*, int);
extern void kvm_mic_cleanup(void);

int g_decodeCalls = 0;   /* incremented by the stub opus_decode */
int g_capsSent = 0;
int g_lastCapsConsent = -1;

static int sink(char *b, int len, void *r) {
    unsigned char *u = (unsigned char*)b; (void)r;
    if (len >= 9 && ((u[0]<<8)|u[1]) == 96) { g_capsSent++; g_lastCapsConsent = (u[7] & 0x02) ? 1 : 0; }
    return 1;
}

static char *mkframe(int *len) {
    static char f[64];
    memset(f, 0, sizeof(f));
    f[0]=0; f[1]=99;            /* MNG_MIC_DATA */
    f[2]=0; f[3]=40;
    f[4]=0; f[5]=1;             /* seq */
    f[6]=0;
    *len = 40;
    return f;
}

#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS  %s\n", msg); } \
    else { printf("  FAIL  %s\n", msg); failures++; } } while (0)

int main(void) {
    int failures = 0, len;
    char *frame = mkframe(&len);

    printf("Microphone consent gate\n");

    kvm_mic_init(sink, NULL);
    CHECK(g_capsSent == 1, "init advertises capability");
    CHECK(kvm_mic_has_consent() == 0, "consent starts denied");

    /* The core security property. */
    g_decodeCalls = 0;
    kvm_mic_feed(frame, len);
    CHECK(g_decodeCalls == 0, "audio is DISCARDED before consent");

    /* Starting without consent must not open the device either. */
    kvm_mic_start();
    g_decodeCalls = 0;
    kvm_mic_feed(frame, len);
    CHECK(g_decodeCalls == 0, "start() without consent does not enable playback");

    /* Grant, then it should flow. */
    kvm_mic_set_consent(1);
    CHECK(kvm_mic_has_consent() == 1, "consent is recorded when granted");
    CHECK(g_lastCapsConsent == 1, "caps report consent to the browser");
    kvm_mic_start();
    g_decodeCalls = 0;
    kvm_mic_feed(frame, len);
    CHECK(g_decodeCalls == 1, "audio flows once consent is granted");

    /* Revoking must take effect immediately. */
    kvm_mic_set_consent(0);
    CHECK(kvm_mic_has_consent() == 0, "consent can be revoked");
    g_decodeCalls = 0;
    kvm_mic_feed(frame, len);
    CHECK(g_decodeCalls == 0, "audio stops the moment consent is revoked");

    /* Stop must also clear consent, so the next attempt re-prompts. */
    kvm_mic_set_consent(1);
    kvm_mic_start();
    kvm_mic_stop();
    CHECK(kvm_mic_has_consent() == 0, "stop() revokes consent for the session");
    g_decodeCalls = 0;
    kvm_mic_feed(frame, len);
    CHECK(g_decodeCalls == 0, "no audio after stop");

    /* Malformed input must not crash or leak through. */
    kvm_mic_set_consent(1);
    kvm_mic_start();
    g_decodeCalls = 0;
    kvm_mic_feed(NULL, 40);
    kvm_mic_feed(frame, 0);
    kvm_mic_feed(frame, 7);      /* header only, no payload */
    kvm_mic_feed(frame, -1);
    CHECK(g_decodeCalls == 0, "malformed frames are rejected safely");

    kvm_mic_cleanup();
    CHECK(kvm_mic_has_consent() == 0, "cleanup clears consent");

    printf("\n%s\n", failures ? "GATE FAILURES" : "CONSENT GATE VERIFIED");
    return failures ? 1 : 0;
}
