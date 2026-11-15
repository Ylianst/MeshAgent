/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_GNOME_ASSETS_H
#define MESH_GNOME_ASSETS_H
#include <stddef.h>
typedef struct mesh_gnome_asset { const unsigned char *data; size_t size; } mesh_gnome_asset;
#define MESH_GNOME_ASSET_UUID "meshagent-console@meshcentral.com"
#define MESH_GNOME_ASSET_BACKUP_SIZE 160
/* Internal installer storage primitive. Caller opens the intended extension
 * parent with no-follow traversal first. All operations require effective UID0
 * and a root-owned directory descriptor with no group/other write permission.
 * Files are metadata.json, protocol.js, extension.js in that fixed order.
 * These functions never enable an extension, end a session or start a service.
 * Return values must be compared explicitly: 1=durable success; 0=refusal/
 * error; -1=rename/deletion applied but parent fsync failed (errno retained).
 * On -1, inspect/rollback the applied state; never blindly retry the operation.
 * backup is empty for a first
 * install/no-op, otherwise an opaque sibling name retained for rollback. */
/* Only this opener selects the production target. No directory is created. */
int mesh_gnome_assets_open_parent(void);
/* Installation alone may create the final extensions directory when absent.
 * Existing directories retain the same no-follow/root-owner/mode validation. */
int mesh_gnome_assets_prepare_parent(void);
/* changed is optional; set only after a rename actually applies. */
int mesh_gnome_assets_install(int parent, const mesh_gnome_asset files[3], char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed);
/* Detach unchanged Agent-owned files atomically; caller can roll back until
 * commit removes the detached directory. Unmanaged or changed files survive. */
int mesh_gnome_assets_uninstall(int parent, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed);
/* Restore a detached installation, or exchange the old/new installation.
 * Managed tokens bind rollback to the exact published receipt or absence.
 * ESTALE refuses rollback after another transaction changes the current state.
 * Legacy tokens cannot roll back across newly registered service ownership.
 * For an update, the backup then holds the candidate and still needs commit. */
int mesh_gnome_assets_rollback(int parent, const char *backup);
/* Commit may partially clean a detached backup on an I/O error. It never
 * touches the current installation; preserve any remainder for inspection. */
int mesh_gnome_assets_commit(int parent, const char *backup);
/* Owner is a lowercase SHA-256 service identity, not a path. Generations must
 * increase whenever the payload changes; downgrade/same-generation conflicts
 * are refused. Payload and owner list publish in one atomic directory rename.
 * Pre-registry installations retain a legacy hold and are never auto-removed.
 * The same backup/rollback/commit and durability rules apply. */
int mesh_gnome_assets_acquire(int parent, const mesh_gnome_asset files[3], const char *owner,
    unsigned int generation, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed);
int mesh_gnome_assets_release(int parent, const char *owner, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed);
#endif
