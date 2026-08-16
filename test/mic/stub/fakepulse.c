#include <stddef.h>
typedef struct pa_simple pa_simple;
static int dummy;
pa_simple* pa_simple_new(const char*a,const char*b,int c,const char*d,const char*e,const void*f,const void*g,const void*h,int*i){
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; if(i)*i=0; return (pa_simple*)&dummy; }
int  pa_simple_write(pa_simple*s,const void*d,size_t n,int*e){ (void)s;(void)d;(void)n; if(e)*e=0; return 0; }
int  pa_simple_flush(pa_simple*s,int*e){ (void)s; if(e)*e=0; return 0; }
void pa_simple_free(pa_simple*s){ (void)s; }
