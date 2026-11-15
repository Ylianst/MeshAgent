// libjpeg-turbo is linked statically. No codec DLL is discovered or loaded.
// Only the capture worker's validated, private BGRX DIB reaches this encoder.
#ifndef MESH_WINDOWS_JPEG_ENCODER_H
#define MESH_WINDOWS_JPEG_ENCODER_H
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include "lib-jpeg-turbo/windows/include/jpeglib.h"
#include "lib-jpeg-turbo/windows/include/jerror.h"

#ifndef MESH_JPEG_MALLOC
#define MESH_JPEG_MALLOC malloc
#define MESH_JPEG_REALLOC realloc
#endif
/** Worker-local, non-reentrant libjpeg context; owns only in-progress output.
 * Completed packet ownership transfers to the sender, so retained codec state
 * must never retain a pointer into a packet still being sent asynchronously.
 */
struct WinJpegEncoder
{
    jpeg_compress_struct codec;
    jpeg_error_mgr errors;
    jpeg_destination_mgr destination;
    jmp_buf failure;
    unsigned char* packet;
    size_t capacity;
    bool configured;
    int configuredQuality;

    WinJpegEncoder() : codec(), errors(), destination(), packet(NULL), capacity(0), configured(false), configuredQuality(0) {}
    ~WinJpegEncoder() { Reset(); }
    /** Destroy codec and unfinished packet on failure or desktop/capture reset. */
    void Reset()
    {
        if (codec.mem) jpeg_destroy_compress(&codec);
        memset(&codec, 0, sizeof(codec));
        configured = false;
        free(packet); packet = NULL; capacity = 0;
    }
    static WinJpegEncoder* Owner(j_common_ptr c) { return (WinJpegEncoder*)c->client_data; }
    static void Error(j_common_ptr c) { longjmp(Owner(c)->failure, 1); }
    static void Quiet(j_common_ptr) {} // Never log pixels or libjpeg's diagnostic contents.
    static void Begin(j_compress_ptr c)
    {
        WinJpegEncoder* self = Owner((j_common_ptr)c);
        self->capacity = 16384;
        self->packet = (unsigned char*)MESH_JPEG_MALLOC(self->capacity);
        if (!self->packet) ERREXIT(c, JERR_OUT_OF_MEMORY);
        self->destination.next_output_byte = self->packet + 16; // Reserve wire headers.
        self->destination.free_in_buffer = self->capacity - 16;
    }
    static boolean Grow(j_compress_ptr c)
    {
        WinJpegEncoder* self = Owner((j_common_ptr)c);
        // Bound the packet and all growth arithmetic to the existing signed packet API.
        if (self->capacity > (size_t)INT_MAX / 2) ERREXIT(c, JERR_OUT_OF_MEMORY);
        size_t next = self->capacity * 2;
        unsigned char* grown = (unsigned char*)MESH_JPEG_REALLOC(self->packet, next);
        if (!grown) ERREXIT(c, JERR_OUT_OF_MEMORY);
        self->packet = grown;
        self->destination.next_output_byte = grown + self->capacity;
        self->destination.free_in_buffer = next - self->capacity;
        self->capacity = next;
        return TRUE;
    }
    static void End(j_compress_ptr) {}
    /** Encode the caller-validated private bottom-up BGRX DIB synchronously.
     * top is the first logical row; subsequent rows are at top - row * stride.
     * The caller validates geometry/quality before entry. On success output is
     * caller-owned malloc storage with 16 bytes reserved before the JPEG payload.
     * On false, publish neither output nor length; the codec has been reset.
     * No C++ RAII object may span the libjpeg setjmp/longjmp error boundary.
     */
    bool Encode(const unsigned char* top, int width, int height, int stride, int quality,
        void** output, unsigned long* length)
    {
        // No objects with nontrivial destructors may cross the codec's error jump.
        if (setjmp(failure)) { Reset(); return false; }
        if (!codec.mem)
        {
            codec.err = jpeg_std_error(&errors);
            errors.error_exit = Error; errors.output_message = Quiet;
            codec.client_data = this;
            jpeg_create_compress(&codec);
            codec.client_data = this;
        }
        destination.init_destination = Begin;
        destination.empty_output_buffer = Grow;
        destination.term_destination = End;
        codec.dest = &destination;
        codec.image_width = width; codec.image_height = height;
        if (!configured)
        {
            codec.input_components = 4; codec.in_color_space = JCS_EXT_BGRX;
            jpeg_set_defaults(&codec);
            // Baseline sequential JPEG, 4:2:0, accurate integer DCT.
            codec.dct_method = JDCT_ISLOW;
        }
        if (!configured || configuredQuality != quality)
        {
            jpeg_set_quality(&codec, quality, TRUE);
            configuredQuality = quality;
        }
        configured = true;
        jpeg_start_compress(&codec, TRUE);
        while (codec.next_scanline < codec.image_height)
        {
            JSAMPROW row = (JSAMPROW)(top - (size_t)codec.next_scanline * stride);
            jpeg_write_scanlines(&codec, &row, 1);
        }
        jpeg_finish_compress(&codec);
        *length = (unsigned long)(capacity - destination.free_in_buffer - 16);
        *output = packet;
        packet = NULL; capacity = 0; // Packet ownership transfers to the caller.
        return true;
    }
};
#endif
