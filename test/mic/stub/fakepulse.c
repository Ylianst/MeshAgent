/* Stand-in for libpulse-simple, loaded by linux_mic.c via dlopen.
 * The counter lives here rather than in the test executable: a shared object
 * cannot resolve symbols back into the main program under dlopen, which would
 * make the library fail to load and the test misreport the gate. */
#include <stddef.h>
#include <string.h>
#include <unistd.h>

typedef struct pa_simple pa_simple;
static int dummy;

int mesh_test_captureOpened = 0;

pa_simple* pa_simple_new(const char*a,const char*b,int c,const char*d,const char*e,
                         const void*f,const void*g,const void*h,int*i){
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;
    if(i)*i=0;
    mesh_test_captureOpened++;
    return (pa_simple*)&dummy;
}

int pa_simple_read(pa_simple*s,void*data,size_t n,int*e){
    (void)s; if(e)*e=0;
    memset(data,0,n);
    usleep(20000);   /* pace the fake capture like a real 20 ms read */
    return 0;
}

void pa_simple_free(pa_simple*s){ (void)s; }
