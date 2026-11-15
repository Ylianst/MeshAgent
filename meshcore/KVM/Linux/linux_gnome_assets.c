/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#ifdef __linux__
#include "linux_gnome_assets.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>

static const char *names[4] = {"metadata.json", "protocol.js", "extension.js", "meshagent-owned.txt"};
static const char prefix[] = ".meshagent-console-";
#define ASSET_LIMIT (1024u * 1024u)
#define RECORD_LIMIT 8192
#define OWNER_LIMIT 64

static int trusted_directory(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 0022);
}
static int open_parent(int create)
{
    const char *parts[] = {"usr", "share", "gnome-shell", "extensions"};
    int fd;
    if (geteuid() != 0) { errno = EPERM; return -1; }
    fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { return -1; }
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i)
    {
        int next, saved;
        if (!trusted_directory(fd)) { close(fd); errno = EPERM; return -1; }
        next = openat(fd, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create && i == 3)
        {
            /* Some GNOME packages omit the otherwise empty extensions directory.
             * Only installation may create it, under the already trusted parent. */
            if (mkdirat(fd, parts[i], 0755) == 0 || errno == EEXIST)
            { next = openat(fd, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); }
        }
        saved = errno; close(fd); fd = next;
        if (fd < 0) { errno = saved; return -1; }
    }
    if (!trusted_directory(fd)) { close(fd); errno = EPERM; return -1; }
    return fd;
}
int mesh_gnome_assets_open_parent(void) { return open_parent(0); }
int mesh_gnome_assets_prepare_parent(void) { return open_parent(1); }
static int parent_lock(int parent)
{
    struct stat st;
    if (geteuid() != 0 || fstat(parent, &st) || !S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022))
    { errno = EPERM; return 0; }
    return flock(parent, LOCK_EX | LOCK_NB) == 0;
}
static int unlock_result(int parent, int result)
{ int saved = errno; flock(parent, LOCK_UN); errno = saved; return result; }
static int lower_hex(const char *text, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    { if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) { return 0; } }
    return 1;
}
static int token_valid(const char *token)
{
    size_t base = sizeof(prefix) - 1 + 32, length;
    if (!token) { return 0; } length = strlen(token);
    if (length != base && length != base + 2 && length != base + 66) { return 0; }
    if (strncmp(token, prefix, sizeof(prefix) - 1) || !lower_hex(token + sizeof(prefix) - 1, 32)) { return 0; }
    if (length == base) { return 1; }
    if (token[base] != '-') { return 0; }
    return (length == base + 2 && token[base+1] == 'd') ||
        (length == base + 66 && (token[base+1] == 'u' || token[base+1] == 'l') && lower_hex(token + base + 2, 64));
}
static void manifest_digest(const char *manifest, char hex[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)manifest, strlen(manifest), digest);
    for (size_t i = 0; i < sizeof(digest); ++i) { snprintf(hex + 2*i, 3, "%02x", digest[i]); }
}
static int make_token(char token[MESH_GNOME_ASSET_BACKUP_SIZE])
{
    unsigned char bytes[16]; size_t offset = 0;
    while (offset < sizeof(bytes))
    {
        ssize_t count = syscall(SYS_getrandom, bytes + offset, sizeof(bytes) - offset, 0);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return 0; }
        offset += (size_t)count;
    }
    memcpy(token, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < sizeof(bytes); ++i) { snprintf(token + sizeof(prefix) - 1 + i * 2, 3, "%02x", bytes[i]); }
    return 1;
}
/* A managed backup names the exact state its rollback may replace. */
static int make_bound_token(char token[MESH_GNOME_ASSET_BACKUP_SIZE], const char *manifest)
{
    size_t offset;
    if (!make_token(token)) { return 0; } offset = strlen(token);
    token[offset++] = '-'; token[offset++] = manifest ? 'u' : 'd';
    if (manifest) { manifest_digest(manifest, token + offset); }
    else { token[offset] = 0; }
    return 1;
}
static int make_legacy_token(char token[MESH_GNOME_ASSET_BACKUP_SIZE], const char *manifest)
{
    size_t offset;
    if (!manifest || !make_token(token)) { return 0; }
    offset = strlen(token); token[offset++] = '-'; token[offset++] = 'l';
    manifest_digest(manifest, token + offset);
    return 1;
}
static int rename_flags(int parent, const char *from, const char *to, unsigned flags)
{ return syscall(SYS_renameat2, parent, from, parent, to, flags) == 0; }
static size_t record(const mesh_gnome_asset files[3], char output[RECORD_LIMIT])
{
    size_t offset = (size_t)snprintf(output, RECORD_LIMIT, "MeshAgent GNOME assets 1\n");
    for (size_t i = 0; i < 3; ++i)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH]; char hex[65];
        SHA256(files[i].data, files[i].size, digest);
        for (size_t n = 0; n < sizeof(digest); ++n) { snprintf(hex + n * 2, 3, "%02x", digest[n]); }
        offset += (size_t)snprintf(output + offset, RECORD_LIMIT - offset, "%s %s\n", names[i], hex);
    }
    return offset;
}

typedef struct owner_set {
    int present, legacy;
    uint32_t generation;
    size_t count;
    char ids[OWNER_LIMIT][65];
} owner_set;
static int owner_valid(const char *id)
{
    if (!id || strlen(id) != 64) { return 0; }
    for (size_t i = 0; i < 64; ++i)
    { if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) { return 0; } }
    return 1;
}
static const char *owner_tail(const char *manifest)
{
    for (int i = 0; i < 4; ++i) {
        manifest = strchr(manifest, '\n');
        if (!manifest) { return NULL; }
        ++manifest;
    }
    return manifest;
}
static int parse_owners(const char *tail, size_t size, owner_set *owners)
{
    memset(owners, 0, sizeof(*owners));
    if (!size) { return 1; }
    if (size < 20 || memcmp(tail, "Owners 1 ", 9) || tail[17] != ' ' ||
        (tail[18] != '0' && tail[18] != '1') || tail[19] != '\n' || (size - 20) % 65) { return 0; }
    owners->present = 1; owners->legacy = tail[18] == '1';
    for (size_t i = 9; i < 17; ++i) {
        unsigned char c = (unsigned char)tail[i]; unsigned int value;
        if (c >= '0' && c <= '9') { value = c - '0'; }
        else if (c >= 'a' && c <= 'f') { value = c - 'a' + 10; }
        else { return 0; }
        owners->generation = (owners->generation << 4) | value;
    }
    owners->count = (size - 20) / 65;
    if (!owners->generation || owners->count > OWNER_LIMIT || (!owners->count && !owners->legacy)) { return 0; }
    for (size_t i = 0; i < owners->count; ++i) {
        const char *id = tail + 20 + 65 * i;
        if (id[64] != '\n') { return 0; }
        memcpy(owners->ids[i], id, 64); owners->ids[i][64] = 0;
        if (!owner_valid(owners->ids[i]) || (i && strcmp(owners->ids[i-1], owners->ids[i]) >= 0)) { return 0; }
    }
    return 1;
}
static size_t append_owners(char output[RECORD_LIMIT], size_t offset, const owner_set *owners)
{
    if (!owners->present) { return offset; }
    offset += (size_t)snprintf(output + offset, RECORD_LIMIT - offset, "Owners 1 %08x %d\n", owners->generation, owners->legacy);
    for (size_t i = 0; i < owners->count; ++i)
    { offset += (size_t)snprintf(output + offset, RECORD_LIMIT - offset, "%s\n", owners->ids[i]); }
    return offset;
}
static int manifest_owners(const char *manifest, owner_set *owners)
{
    const char *tail = owner_tail(manifest);
    return tail && parse_owners(tail, strlen(tail), owners);
}

static int read_regular(int directory, const char *name, unsigned char **data, size_t *size)
{
    struct stat st; int fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC); size_t offset = 0;
    *data = NULL;
    if (fd < 0) { return 0; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1 ||
        (st.st_mode & 07777) != 0644 || st.st_size <= 0 || st.st_size > ASSET_LIMIT)
    { close(fd); errno = EPERM; return 0; }
    *size = (size_t)st.st_size; *data = malloc(*size);
    if (!*data) { close(fd); return 0; }
    while (offset < *size)
    {
        ssize_t count = read(fd, *data + offset, *size - offset);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { free(*data); *data = NULL; close(fd); return 0; }
        offset += (size_t)count;
    }
    close(fd); return 1;
}
/* Only exact, unmodified files with our ownership receipt may be replaced or
 * removed. This proves provenance against non-root changes, not against root. */
static int owned_directory(int parent, const char *name, char manifest[RECORD_LIMIT])
{
    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int good = 0; struct stat st; mesh_gnome_asset assets[3] = {{0}}; unsigned char *receipt = NULL; size_t size;
    DIR *entries = NULL; struct dirent *entry; unsigned count = 0;
    if (directory < 0) { return -1; }
    if (fstat(directory, &st) || st.st_uid != 0 || (st.st_mode & 07777) != 0755) { goto done; }
    entries = fdopendir(dup(directory)); if (!entries) { goto done; }
    while ((entry = readdir(entries)) != NULL)
    {
        int known = 0;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) { continue; }
        for (size_t i = 0; i < 4; ++i) { if (!strcmp(entry->d_name, names[i])) { known = 1; } }
        if (!known || ++count > 4) { goto done; }
    }
    if (count != 4) { goto done; }
    for (size_t i = 0; i < 3; ++i)
    {
        unsigned char *data = NULL;
        if (!read_regular(directory, names[i], &data, &assets[i].size)) { goto done; }
        assets[i].data = data;
    }
    size = record(assets, manifest);
    size_t receipt_size;
    owner_set owners;
    if (!read_regular(directory, names[3], &receipt, &receipt_size) || receipt_size < size ||
        receipt_size >= RECORD_LIMIT || memcmp(receipt, manifest, size) || memchr(receipt, 0, receipt_size) ||
        !parse_owners((const char *)receipt + size, receipt_size - size, &owners)) { goto done; }
    memcpy(manifest, receipt, receipt_size); manifest[receipt_size] = 0;
    good = 1;
done:
    if (entries) { closedir(entries); }
    for (size_t i = 0; i < 3; ++i) { free((void *)assets[i].data); }
    free(receipt);
    if (!good) { close(directory); errno = EPERM; return -1; }
    return directory;
}
/* A pre-registry companion can be adopted only when its complete payload is
 * root-owned, immutable by non-root users, has no extra entries, and exactly
 * matches the embedded payload. A legacy hold keeps it on final uninstall. */
static int legacy_directory(int parent, const char *name, const mesh_gnome_asset expected[3])
{
    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st; DIR *entries = NULL; struct dirent *entry; unsigned count = 0; int good = 0;
    mesh_gnome_asset observed[3] = {{0}}; unsigned char *observedData[3] = {NULL, NULL, NULL};
    if (directory < 0) { return -1; }
    if (fstat(directory, &st) || st.st_uid != 0 || (st.st_mode & 07777) != 0755) { goto done; }
    entries = fdopendir(dup(directory)); if (!entries) { goto done; }
    while ((entry = readdir(entries)) != NULL)
    {
        int known = 0;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) { continue; }
        for (size_t i = 0; i < 3; ++i) { if (!strcmp(entry->d_name, names[i])) { known = 1; } }
        if (!known || ++count > 3) { goto done; }
    }
    if (count != 3) { goto done; }
    for (size_t i = 0; i < 3; ++i)
    {
        if (!read_regular(directory, names[i], &observedData[i], &observed[i].size)) { goto done; }
        observed[i].data = observedData[i];
        if (expected && (observed[i].size != expected[i].size ||
            memcmp(observed[i].data, expected[i].data, observed[i].size))) { goto done; }
    }
    good = 1;
done:
    if (entries) { closedir(entries); }
    for (size_t i = 0; i < 3; ++i) { free(observedData[i]); }
    if (!good) { close(directory); errno = EPERM; return -1; }
    return directory;
}
static int same_payload(int first, int second)
{
    int same = 1;
    for (size_t i = 0; i < 3; ++i)
    {
        unsigned char *a = NULL, *b = NULL; size_t aSize = 0, bSize = 0;
        if (!read_regular(first, names[i], &a, &aSize) || !read_regular(second, names[i], &b, &bSize) ||
            aSize != bSize || memcmp(a, b, aSize)) { same = 0; }
        free(a); free(b); if (!same) { break; }
    }
    return same;
}
static int write_file(int directory, const char *name, const unsigned char *data, size_t size)
{
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    size_t offset = 0; int good = 0;
    if (fd < 0) { return 0; }
    while (offset < size)
    {
        ssize_t count = write(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { goto done; }
        offset += (size_t)count;
    }
    good = !fchmod(fd, 0644) && !fsync(fd);
done:
    if (close(fd)) { good = 0; } return good;
}
static void discard_stage(int parent, const char *token, int directory)
{
    /* Only a newly created, still-private stage reaches this cleanup. */
    for (size_t i = 0; i < 4; ++i) { unlinkat(directory, names[i], 0); }
    close(directory); unlinkat(parent, token, AT_REMOVEDIR);
}

/* Caller holds the parent lock for payload and ownership publication together. */
static int publish(int parent, const mesh_gnome_asset files[3], const char *desired,
    int exists, int bound, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed)
{
    char stage[MESH_GNOME_ASSET_BACKUP_SIZE]; int directory = -1, result = 0;
    if (!(bound == 2 ? make_legacy_token(stage, desired) : (bound ? make_bound_token(stage, desired) : make_token(stage))) ||
        mkdirat(parent, stage, 0700)) { return 0; }
    directory = openat(parent, stage, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { unlinkat(parent, stage, AT_REMOVEDIR); return 0; }
    for (size_t i = 0; i < 3; ++i)
    { if (!write_file(directory, names[i], files[i].data, files[i].size)) { goto done; } }
    if (!write_file(directory, names[3], (const unsigned char *)desired, strlen(desired)) ||
        fchmod(directory, 0755) || fsync(directory)) { goto done; }
    if (!rename_flags(parent, stage, MESH_GNOME_ASSET_UUID, exists ? RENAME_EXCHANGE : RENAME_NOREPLACE)) { goto done; }
    if (changed) { *changed = 1; }
    close(directory); directory = -1;
    if (exists) { strcpy(backup, stage); }
    result = fsync(parent) == 0 ? 1 : -1;
done:
    if (directory >= 0) { int saved = errno; discard_stage(parent, stage, directory); errno = saved; }
    return result;
}
static int payload_valid(const mesh_gnome_asset files[3])
{
    if (!files) { return 0; }
    for (size_t i = 0; i < 3; ++i)
    { if (!files[i].data || !files[i].size || files[i].size > ASSET_LIMIT) { return 0; } }
    return 1;
}
int mesh_gnome_assets_install(int parent, const mesh_gnome_asset files[3], char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed)
{
    char current[RECORD_LIMIT], desired[RECORD_LIMIT]; int old = -1, result = 0; struct stat st;
    if (changed) { *changed = 0; }
    if (!backup || !payload_valid(files)) { errno = EINVAL; return 0; } backup[0] = 0;
    record(files, desired);
    if (!parent_lock(parent)) { return 0; }
    if (!fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW)) {
        old = owned_directory(parent, MESH_GNOME_ASSET_UUID, current);
        if (old < 0) { goto done; }
        owner_set owners;
        if (!manifest_owners(current, &owners)) { errno = EPERM; goto done; }
        /* Old installer calls cannot rewrite or discard service ownership. */
        if (owners.present) {
            size_t base = strlen(desired);
            if (memcmp(current, desired, base)) { errno = EBUSY; goto done; }
            result = 1; goto done;
        }
        if (!strcmp(current, desired)) { result = 1; goto done; }
    } else if (errno != ENOENT) { goto done; }
    result = publish(parent, files, desired, old >= 0, 0, backup, changed);
done:
    if (old >= 0) { close(old); } return unlock_result(parent, result);
}
int mesh_gnome_assets_acquire(int parent, const mesh_gnome_asset files[3], const char *owner,
    unsigned int generation, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed)
{
    char current[RECORD_LIMIT], desired[RECORD_LIMIT]; owner_set owners = {0};
    int old = -1, result = 0, unmanifested = 0; struct stat st; size_t base, position = 0;
    if (changed) { *changed = 0; }
    if (!backup || !payload_valid(files) || !owner_valid(owner) || !generation) { errno = EINVAL; return 0; }
    backup[0] = 0; base = record(files, desired);
    if (!parent_lock(parent)) { return 0; }
    if (!fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW)) {
        old = owned_directory(parent, MESH_GNOME_ASSET_UUID, current);
        if (old < 0) {
            old = legacy_directory(parent, MESH_GNOME_ASSET_UUID, files);
            if (old < 0) { goto done; }
            owners.legacy = 1; unmanifested = 1;
        } else if (!manifest_owners(current, &owners)) { goto done; }
        if (owners.present && (generation < owners.generation ||
            (generation == owners.generation && memcmp(current, desired, base)))) { errno = EBUSY; goto done; }
        /* Pre-registry installations may have dependents we cannot identify. */
        if (!owners.present) { owners.legacy = 1; }
    } else if (errno != ENOENT) { goto done; }
    owners.present = 1; owners.generation = generation;
    while (position < owners.count && strcmp(owners.ids[position], owner) < 0) { ++position; }
    if (position == owners.count || strcmp(owners.ids[position], owner)) {
        if (owners.count == OWNER_LIMIT) { errno = ENOSPC; goto done; }
        memmove(owners.ids + position + 1, owners.ids + position, (owners.count-position) * sizeof(owners.ids[0]));
        strcpy(owners.ids[position], owner); ++owners.count;
    }
    append_owners(desired, base, &owners);
    if (old >= 0 && !unmanifested && !strcmp(current, desired)) { result = 1; goto done; }
    result = publish(parent, files, desired, old >= 0, unmanifested ? 2 : 1, backup, changed);
done:
    if (old >= 0) { close(old); } return unlock_result(parent, result);
}
int mesh_gnome_assets_release(int parent, const char *owner, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed)
{
    char current[RECORD_LIMIT], desired[RECORD_LIMIT], token[MESH_GNOME_ASSET_BACKUP_SIZE];
    owner_set owners; mesh_gnome_asset files[3] = {{0}}; int old = -1, result = 0; struct stat st; size_t position = 0;
    if (changed) { *changed = 0; }
    if (!backup || !owner_valid(owner)) { errno = EINVAL; return 0; } backup[0] = 0;
    if (!parent_lock(parent)) { return 0; }
    if (fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) { result = 1; goto done; }
    old = owned_directory(parent, MESH_GNOME_ASSET_UUID, current);
    if (old < 0 || !manifest_owners(current, &owners)) { goto done; }
    if (!owners.present) { result = 1; goto done; }
    while (position < owners.count && strcmp(owners.ids[position], owner)) { ++position; }
    if (position == owners.count) { result = 1; goto done; }
    memmove(owners.ids + position, owners.ids + position + 1, (owners.count-position-1) * sizeof(owners.ids[0])); --owners.count;
    if (!owners.count && !owners.legacy) {
        if (make_bound_token(token, NULL) && rename_flags(parent, MESH_GNOME_ASSET_UUID, token, RENAME_NOREPLACE)) {
            if (changed) { *changed = 1; } strcpy(backup, token); result = fsync(parent) == 0 ? 1 : -1;
        }
        goto done;
    }
    for (size_t i = 0; i < 3; ++i) {
        unsigned char *data = NULL;
        if (!read_regular(old, names[i], &data, &files[i].size)) { goto done; }
        files[i].data = data;
    }
    append_owners(desired, record(files, desired), &owners);
    result = publish(parent, files, desired, 1, 1, backup, changed);
done:
    for (size_t i = 0; i < 3; ++i) { free((void *)files[i].data); }
    if (old >= 0) { close(old); } return unlock_result(parent, result);
}
int mesh_gnome_assets_uninstall(int parent, char backup[MESH_GNOME_ASSET_BACKUP_SIZE], int *changed)
{
    char manifest[RECORD_LIMIT], token[MESH_GNOME_ASSET_BACKUP_SIZE]; int directory, result = 0; struct stat st;
    if (changed) { *changed = 0; }
    if (!backup) { errno = EINVAL; return 0; } backup[0] = 0;
    if (!parent_lock(parent)) { return 0; }
    if (fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) { return unlock_result(parent, 1); }
    directory = owned_directory(parent, MESH_GNOME_ASSET_UUID, manifest);
    if (directory < 0) { return unlock_result(parent, 0); } close(directory);
    owner_set owners;
    if (!manifest_owners(manifest, &owners) || owners.present) { errno = EBUSY; return unlock_result(parent, 0); }
    if (make_token(token) && rename_flags(parent, MESH_GNOME_ASSET_UUID, token, RENAME_NOREPLACE))
    { if (changed) { *changed = 1; } strcpy(backup, token); result = fsync(parent) == 0 ? 1 : -1; }
    return unlock_result(parent, result);
}
int mesh_gnome_assets_rollback(int parent, const char *backup)
{
    char previous[RECORD_LIMIT], currentManifest[RECORD_LIMIT], digest[65];
    int old, current, result = 0, kind; struct stat st; owner_set owners;
    size_t base = sizeof(prefix) - 1 + 32;
    if (!token_valid(backup)) { errno = EINVAL; return 0; }
    kind = strlen(backup) == base ? 0 : (backup[base+1] == 'd' ? 2 : (backup[base+1] == 'l' ? 3 : 1));
    if (!parent_lock(parent)) { return 0; }
    if (kind == 3) {
        old = legacy_directory(parent, backup, NULL);
        if (old >= 0) {
            if (fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW)) {
                if (errno == ENOENT) { result = rename_flags(parent, backup, MESH_GNOME_ASSET_UUID, RENAME_NOREPLACE); }
            } else {
                current = owned_directory(parent, MESH_GNOME_ASSET_UUID, currentManifest);
                if (current >= 0) {
                    manifest_digest(currentManifest, digest);
                    if (!strcmp(digest, backup + base + 2) && manifest_owners(currentManifest, &owners) &&
                        owners.legacy && same_payload(old, current))
                        result = rename_flags(parent, backup, MESH_GNOME_ASSET_UUID, RENAME_EXCHANGE);
                    close(current);
                }
            }
            close(old);
            if (result) { result = fsync(parent) == 0 ? 1 : -1; }
            return unlock_result(parent, result);
        }
        old = owned_directory(parent, backup, previous);
        if (old >= 0) {
            manifest_digest(previous, digest);
            if (!strcmp(digest, backup + base + 2) && manifest_owners(previous, &owners) && owners.legacy) {
                current = legacy_directory(parent, MESH_GNOME_ASSET_UUID, NULL);
                if (current >= 0) { result = same_payload(old, current); close(current); }
            }
            close(old);
        }
        return unlock_result(parent, result);
    }
    old = owned_directory(parent, backup, previous);
    if (old < 0) { return unlock_result(parent, 0); } close(old);
    if (!manifest_owners(previous, &owners) || (!kind && owners.present))
    { errno = ESTALE; return unlock_result(parent, 0); }
    if (fstatat(parent, MESH_GNOME_ASSET_UUID, &st, AT_SYMLINK_NOFOLLOW)) {
        if (errno != ENOENT) { return unlock_result(parent, 0); }
        if (kind == 1) { errno = ESTALE; return unlock_result(parent, 0); }
        result = rename_flags(parent, backup, MESH_GNOME_ASSET_UUID, RENAME_NOREPLACE);
    } else {
        if (kind == 2) { errno = ESTALE; return unlock_result(parent, 0); }
        current = owned_directory(parent, MESH_GNOME_ASSET_UUID, currentManifest);
        if (current < 0) { return unlock_result(parent, 0); } close(current);
        if (kind == 1) {
            manifest_digest(currentManifest, digest);
            if (strcmp(digest, backup + base + 2)) { errno = ESTALE; return unlock_result(parent, 0); }
        } else if (!manifest_owners(currentManifest, &owners) || owners.present) {
            errno = ESTALE; return unlock_result(parent, 0);
        }
        result = rename_flags(parent, backup, MESH_GNOME_ASSET_UUID, RENAME_EXCHANGE);
    }
    if (result) { result = fsync(parent) == 0 ? 1 : -1; } return unlock_result(parent, result);
}
int mesh_gnome_assets_commit(int parent, const char *backup)
{
    char manifest[RECORD_LIMIT], currentManifest[RECORD_LIMIT], digest[65];
    int directory = -1, current = -1, result = 1, kind; owner_set owners;
    size_t base = sizeof(prefix) - 1 + 32;
    if (!token_valid(backup)) { errno = EINVAL; return 0; }
    kind = strlen(backup) == base ? 0 : (backup[base+1] == 'd' ? 2 : (backup[base+1] == 'l' ? 3 : 1));
    if (!parent_lock(parent)) { return 0; }
    if (kind == 3) {
        directory = legacy_directory(parent, backup, NULL);
        if (directory >= 0) {
            current = owned_directory(parent, MESH_GNOME_ASSET_UUID, currentManifest);
            if (current < 0) { result = 0; goto legacy_done; }
            manifest_digest(currentManifest, digest);
            if (strcmp(digest, backup + base + 2) || !manifest_owners(currentManifest, &owners) ||
                !owners.legacy || !same_payload(directory, current)) { result = 0; goto legacy_done; }
            for (size_t i = 0; i < 3; ++i) { if (unlinkat(directory, names[i], 0)) { result = 0; break; } }
        } else {
            current = legacy_directory(parent, MESH_GNOME_ASSET_UUID, NULL);
            if (current < 0) { result = 0; goto legacy_done; }
            directory = owned_directory(parent, backup, manifest);
            if (directory < 0) { result = 0; goto legacy_done; }
            manifest_digest(manifest, digest);
            if (strcmp(digest, backup + base + 2) || !manifest_owners(manifest, &owners) ||
                !owners.legacy || !same_payload(current, directory)) { result = 0; goto legacy_done; }
            for (size_t i = 0; i < 4; ++i) { if (unlinkat(directory, names[i], 0)) { result = 0; break; } }
        }
        close(directory); directory = -1;
        if (result) { result = unlinkat(parent, backup, AT_REMOVEDIR) == 0 ? (fsync(parent) == 0 ? 1 : -1) : 0; }
legacy_done:
        if (directory >= 0) { close(directory); }
        if (current >= 0) { close(current); }
        return unlock_result(parent, result);
    }
    directory = owned_directory(parent, backup, manifest);
    if (directory < 0) { return unlock_result(parent, 0); }
    for (size_t i = 0; i < 4; ++i) { if (unlinkat(directory, names[i], 0)) { result = 0; break; } }
    close(directory);
    if (result) { result = unlinkat(parent, backup, AT_REMOVEDIR) == 0 ? (fsync(parent) == 0 ? 1 : -1) : 0; }
    return unlock_result(parent, result);
}

#endif /* __linux__ */
