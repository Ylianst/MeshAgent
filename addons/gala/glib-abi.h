/* SPDX-License-Identifier: GPL-3.0-or-later
 * Public GLib/GObject/GIO ABI used by the Gala addition. Keeping these opaque
 * declarations here avoids a GLib SDK dependency in Agent cross builds. The
 * compositor already loads these libraries; no private object fields are read.
 */
#ifndef MESH_GALA_GLIB_ABI_H
#define MESH_GALA_GLIB_ABI_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef int gboolean;
typedef unsigned int guint;
typedef uintptr_t GType;
typedef struct GObject GObject;
typedef struct GError GError;
typedef struct { GType type; const char *type_name; guint class_size, instance_size; } GTypeQuery;
typedef void (*GCallback)(void);
typedef gboolean (*GSourceFunc)(void *);
typedef void (*GAsyncReadyCallback)(void *, void *, void *);
extern GType g_object_get_type(void);
extern GType g_type_from_name(const char *);
extern void g_type_query(GType, GTypeQuery *);
extern GType g_type_register_static_simple(GType, const char *, guint, void (*)(void *,void *), guint, void (*)(void *,void *), guint);
extern void *g_object_new(GType, const char *, ...);
extern void *g_object_ref(void *);
extern void g_object_unref(void *);
extern void g_object_get(void *, const char *, ...);
extern void *g_file_new_for_path(const char *);
extern void *g_file_monitor_file(void *,guint,void *,GError **);
extern gboolean g_file_monitor_cancel(void *);
extern char *g_strdup(const char *);
extern void *g_malloc0(size_t);
extern void g_free(void *);
extern void g_error_free(GError *);
extern unsigned long g_signal_connect_data(void *,const char *,GCallback,void *,void (*)(void *,void *),guint);
extern guint g_timeout_add_full(int,guint,GSourceFunc,void *,void (*)(void *));
extern guint g_idle_add_full(int,GSourceFunc,void *,void (*)(void *));
extern gboolean g_source_remove(guint);
extern void *g_cancellable_new(void);
extern void g_cancellable_cancel(void *);
extern gboolean g_cancellable_is_cancelled(void *);
extern void *g_socket_service_new(void);
extern void g_socket_service_start(void *);
extern void g_socket_service_stop(void *);
extern void g_socket_listener_close(void *);
extern void *g_unix_socket_address_new(const char *);
extern gboolean g_socket_listener_add_address(void *,void *,int,int,void *,void **,GError **);
extern void *g_socket_connection_get_socket(void *);
extern void *g_socket_get_credentials(void *,GError **);
extern uid_t g_credentials_get_unix_user(void *,GError **);
extern void *g_io_stream_get_input_stream(void *);
extern void *g_io_stream_get_output_stream(void *);
extern gboolean g_io_stream_close(void *,void *,GError **);
extern void g_input_stream_read_all_async(void *,void *,size_t,int,void *,GAsyncReadyCallback,void *);
extern gboolean g_input_stream_read_all_finish(void *,void *,size_t *,GError **);
extern void g_output_stream_write_all_async(void *,const void *,size_t,int,void *,GAsyncReadyCallback,void *);
extern gboolean g_output_stream_write_all_finish(void *,void *,size_t *,GError **);
extern int g_unichar_to_utf8(uint32_t,char *);
#endif
