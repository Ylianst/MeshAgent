/* Compile the compatibility path against headers without RGB32 extensions. */
#include "../meshcore/KVM/Linux/linux_compression.h"
#undef JCS_EXTENSIONS
#include "../meshcore/KVM/Linux/linux_compression.c"
int main(void)
{
    unsigned char pixel[4]={17,31,47,0};
    for(int f=JPEG_BGRX32;f<=JPEG_XRGB32;++f) {
        if(jpeg_rgb32_supported((jpeg_pixel_format)f) ||
            write_JPEG_buffer_pixels(pixel,1,1,4,50,(jpeg_pixel_format)f)!=-1 || jpeg_buffer) return 1;
    }
    if(write_JPEG_buffer_strided(pixel,1,1,3,50) || !jpeg_buffer || jpeg_buffer_length<=0) return 1;
    jpeg_encoder_cleanup();
    puts("JPEG without RGB32 extensions: RGB fallback passed");return 0;
}
