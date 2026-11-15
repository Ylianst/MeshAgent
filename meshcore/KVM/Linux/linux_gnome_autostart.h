/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_GNOME_AUTOSTART_H
#define MESH_GNOME_AUTOSTART_H
#include <stddef.h>
/* Fixed production parent; no-follow traversal, never creates directories. */
int mesh_gnome_autostart_open_parent(void);
/* Fixed GDM Shell user-unit drop-in directory; creates trusted directories only
 * on installation. No vendor unit or other service's drop-in is replaced. */
int mesh_gnome_greeter_startup_open_parent(int create);
int mesh_gnome_greeter_startup_install(int parent,const char *owner,const unsigned char *data,size_t size,int *changed);
int mesh_gnome_greeter_startup_remove(int parent,const char *owner,const unsigned char *data,size_t size,int *changed);
/* Exact service-owned content only. owner is a lowercase 64-char SHA256.
 * install never replaces a differing existing entry; remove requires exact
 * bytes, root ownership, regular type, nlink1 and mode0644. Each operation
 * holds a nonblocking parent flock. Return 1 durable, 0 refusal/error, -1
 * applied but parent fsync failed. changed records actual publication/removal.
 * Caller must not retry blindly on uncertain durability. */
int mesh_gnome_autostart_install(int parent, const char *owner, const unsigned char *data, size_t size, int *changed);
int mesh_gnome_autostart_remove(int parent, const char *owner, const unsigned char *data, size_t size, int *changed);
#endif
