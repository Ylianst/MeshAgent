/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#if defined(__linux__) && defined(_LINKVM)
#include "ILibDuktape_GnomeCompanion.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "../meshcore/KVM/Linux/linux_gnome_assets.h"
#include "../meshcore/KVM/Linux/linux_gnome_autostart.h"
#include "../meshcore/KVM/Linux/linux_gala_assets.h"
#include "../meshcore/KVM/Linux/linux_kvm_gala.h"
#include "../meshcore/KVM/Linux/linux_gala_consent.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

static duk_ret_t companion_result(duk_context *ctx, int result, int error, int changed, const char *backup)
{
    duk_push_object(ctx);
    duk_push_int(ctx, result); duk_put_prop_string(ctx, -2, "status");
    duk_push_int(ctx, result == 1 ? 0 : error); duk_put_prop_string(ctx, -2, "errno");
    if (changed < 0) { duk_push_null(ctx); } else { duk_push_boolean(ctx, changed); }
    duk_put_prop_string(ctx, -2, "changed");
    duk_push_string(ctx, backup ? backup : ""); duk_put_prop_string(ctx, -2, "backup");
    return 1;
}
static duk_ret_t companion_install(duk_context *ctx)
{
    mesh_gnome_asset files[3]; char backup[MESH_GNOME_ASSET_BACKUP_SIZE] = {0};
    int parent, result, error, changed = 0, owned = duk_get_current_magic(ctx);
    const char *owner = NULL; unsigned int generation = 0;
    if (duk_get_top(ctx) != (owned ? 5 : 3)) { return duk_error(ctx, DUK_ERR_TYPE_ERROR, "Invalid companion install arguments"); }
    if (owned) {
        duk_size_t size; owner = duk_require_lstring(ctx, 0, &size);
        double number = duk_require_number(ctx, 1);
        if (size != 64 || memchr(owner, 0, size)) { return duk_error(ctx, DUK_ERR_TYPE_ERROR, "Invalid companion owner"); }
        if (!(number >= 1 && number <= 4294967295.0) || number != (unsigned int)number)
        { return duk_error(ctx, DUK_ERR_RANGE_ERROR, "Invalid companion generation"); }
        generation = (unsigned int)number;
    }
    for (duk_idx_t i = 0; i < 3; ++i)
    {
        duk_size_t size;
        duk_idx_t index = i + (owned ? 2 : 0);
        if (!duk_is_buffer_data(ctx, index)) { return duk_error(ctx, DUK_ERR_TYPE_ERROR, "Companion asset must be a buffer"); }
        files[i].data = (const unsigned char *)Duktape_GetBuffer(ctx, index, &size); files[i].size = (size_t)size;
        if (!files[i].data || !files[i].size || files[i].size > 1024u * 1024u)
        { return duk_error(ctx, DUK_ERR_RANGE_ERROR, "Invalid companion buffer size"); }
    }
    parent = mesh_gnome_assets_prepare_parent();
    if (parent < 0) { return companion_result(ctx, 0, errno, 0, NULL); }
    result = owned ? mesh_gnome_assets_acquire(parent, files, owner, generation, backup, &changed) :
        mesh_gnome_assets_install(parent, files, backup, &changed); error = errno; close(parent);
    return companion_result(ctx, result, error, changed, backup);
}
static duk_ret_t companion_operation(duk_context *ctx)
{
    int op = duk_get_current_magic(ctx), parent, result, error, changed = 0;
    char backup[MESH_GNOME_ASSET_BACKUP_SIZE] = {0};
    if (op != 0)
    {
        duk_size_t size; const char *token = duk_require_lstring(ctx, 0, &size);
        if (!size || size >= sizeof(backup) || memchr(token, 0, size))
        { return duk_error(ctx, DUK_ERR_TYPE_ERROR, "Invalid companion operation token"); }
        memcpy(backup, token, size);
    }
    parent = mesh_gnome_assets_open_parent();
    if (parent < 0) { return companion_result(ctx, 0, errno, 0, NULL); }
    if (op == 3) {
        char detached[MESH_GNOME_ASSET_BACKUP_SIZE] = {0};
        result = mesh_gnome_assets_release(parent, backup, detached, &changed);
        error = errno; close(parent);
        return companion_result(ctx, result, error, changed, detached);
    }
    if (op == 0) { result = mesh_gnome_assets_uninstall(parent, backup, &changed); }
    else if (op == 1) { result = mesh_gnome_assets_rollback(parent, backup); changed = result != 0; }
    else { result = mesh_gnome_assets_commit(parent, backup); changed = result == 0 ? -1 : 1; }
    error = errno; close(parent);
    return companion_result(ctx, result, error, changed, backup);
}
static duk_ret_t companion_autostart(duk_context *ctx)
{
    duk_size_t ownerSize,size;
    const char *owner=duk_require_lstring(ctx,0,&ownerSize);
    if(duk_get_top(ctx)!=2||ownerSize!=64||memchr(owner,0,ownerSize)||!duk_is_buffer_data(ctx,1))
        return duk_error(ctx,DUK_ERR_TYPE_ERROR,"Invalid GNOME startup entry arguments");
    const unsigned char *data=(const unsigned char*)Duktape_GetBuffer(ctx,1,&size);
    if(!data||!size||size>32768)return duk_error(ctx,DUK_ERR_RANGE_ERROR,"Invalid GNOME startup entry size");
    int op=duk_get_current_magic(ctx),greeter=op>=2,removing=op&1;
    int parent=greeter?mesh_gnome_greeter_startup_open_parent(!removing):mesh_gnome_autostart_open_parent(),changed=0;
    if(parent<0)return companion_result(ctx,removing&&errno==ENOENT?1:0,errno,0,NULL);
    int result=greeter?(removing?mesh_gnome_greeter_startup_remove(parent,owner,data,size,&changed):mesh_gnome_greeter_startup_install(parent,owner,data,size,&changed)):
        (removing?mesh_gnome_autostart_remove(parent,owner,data,size,&changed):mesh_gnome_autostart_install(parent,owner,data,size,&changed));
    int error=errno;close(parent);return companion_result(ctx,result,error,changed,NULL);
}
static void companion_push(duk_context *ctx, void *chain)
{
    (void)chain;
    duk_push_object(ctx);
    duk_push_c_function(ctx,companion_autostart,2);duk_put_prop_string(ctx,-2,"autostartInstall");
    duk_push_c_function(ctx,companion_autostart,2);duk_set_magic(ctx,-1,1);duk_put_prop_string(ctx,-2,"autostartRemove");
    duk_push_c_function(ctx,companion_autostart,2);duk_set_magic(ctx,-1,2);duk_put_prop_string(ctx,-2,"greeterStartupInstall");
    duk_push_c_function(ctx,companion_autostart,2);duk_set_magic(ctx,-1,3);duk_put_prop_string(ctx,-2,"greeterStartupRemove");
    duk_push_c_function(ctx, companion_install, DUK_VARARGS); duk_put_prop_string(ctx, -2, "install");
    duk_push_c_function(ctx, companion_install, DUK_VARARGS); duk_set_magic(ctx, -1, 1); duk_put_prop_string(ctx, -2, "acquire");
    const char *names[] = {"uninstall", "rollback", "commit", "release"};
    for (int i = 0; i < 4; ++i)
    {
        duk_push_c_function(ctx, companion_operation, i ? 1 : 0);
        duk_set_magic(ctx, -1, i); duk_put_prop_string(ctx, -2, names[i]);
    }
}
static duk_ret_t gala_operation(duk_context *ctx)
{
    int op=duk_get_current_magic(ctx),changed=0,result=0,error=0;
    if(op<2){
        duk_size_t size;const char *owner=duk_require_lstring(ctx,0,&size);
        if(size!=64||memchr(owner,0,size))return duk_error(ctx,DUK_ERR_TYPE_ERROR,"Invalid Gala owner");
        result=op?mesh_gala_assets_release(owner,&changed):mesh_gala_assets_install(owner,&changed);error=errno;
        return companion_result(ctx,result,error,changed,NULL);
    }
    if(op==2){int fd=mesh_gala_assets_open_parent();duk_push_boolean(ctx,fd>=0);if(fd>=0)close(fd);return 1;}
    if(op==3){duk_push_boolean(ctx,kvm_gala_available());return 1;}
    if(op==4){kvm_gala_target target;duk_push_boolean(ctx,kvm_gala_find_target(&target));return 1;}
    int consent=mesh_gala_offer_signout();duk_push_object(ctx);
    duk_push_string(ctx,consent==0?"sign-out-requested":consent==2?"declined":"deferred");duk_put_prop_string(ctx,-2,"state");
    return 1;
}
static void gala_push(duk_context *ctx,void *chain)
{
    (void)chain;duk_push_object(ctx);const char *names[]={"install","release","detect","active","target","offerSignOut"};
    for(int i=0;i<6;++i){duk_push_c_function(ctx,gala_operation,i<2?1:0);duk_set_magic(ctx,-1,i);duk_put_prop_string(ctx,-2,names[i]);}
}
void ILibDuktape_GnomeCompanion_Init(duk_context *ctx)
{
    /* Called only by fs_init: restricted script contexts must not acquire this
     * file-writing primitive through the general polyfill registry. */
    ILibDuktape_ModSearch_AddHandler(ctx, "_gnome-companion-store", companion_push);
    ILibDuktape_ModSearch_AddHandler(ctx, "_gala-companion-store", gala_push);
}
#endif
