/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_GALA_ASSETS_H
#define MESH_GALA_ASSETS_H
#include <stddef.h>
#define MESH_GALA_FILE "libmeshagent-console.so"
/* Source revision, not a compiler/build fingerprint. Wire AGL1 stays backward
 * compatible: compiler-only Agent updates retain the existing owned image. */
#define MESH_GALA_GENERATION 3u
int mesh_gala_assets_open_parent(void);
int mesh_gala_assets_install(const char *owner,int *changed);
int mesh_gala_assets_release(const char *owner,int *changed);
int mesh_gala_assets_trusted(void);
/* Fixed-file primitives, also used by isolated native ownership tests. */
int mesh_gala_assets_acquire_at(int parent,const unsigned char *data,size_t size,const char *owner,int *changed);
int mesh_gala_assets_release_at(int parent,const char *owner,int *changed);
int mesh_gala_assets_trusted_at(int parent);
#endif
