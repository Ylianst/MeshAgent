/* SPDX-License-Identifier: Apache-2.0 */
#include "meshcore/KVM/Linux/linux_kvm_xkb.c"
#include <assert.h>
static unsigned int restore_calls;
static size_t restore_map_size;
static void record_restore(struct wl_proxy *keyboard, uint32_t op, union wl_argument *args)
{
    (void)keyboard;
    assert(op == restore_calls++);
    if (op == 0) { assert(args[0].u == (restore_map_size ? 1u : 0u) && args[1].h == 7 && args[2].u == restore_map_size); }
    if (op == 1) { assert(args[1].u == 194 && args[2].u == 0); }
    if (op == 2) { assert(args[0].u == 1 && args[1].u == 2 && args[2].u == 4 && args[3].u == 3); }
}
static void virtual_map_tests(void)
{
    struct names { const char *rules, *model, *layout, *variant, *options; } names = {NULL, NULL, "us", NULL, NULL};
    struct xkb_keymap *(*from_names)(struct xkb_context *, const struct names *, int);
    char *(*as_string)(struct xkb_keymap *, int);
    struct xkb_context *ctx;
    assert(kvm_xkb_load_xkbcommon());
    from_names = (void *)dlsym(g_xkb_libxkbcommon, "xkb_keymap_new_from_names");
    as_string = (void *)dlsym(g_xkb_libxkbcommon, "xkb_keymap_get_as_string");
    assert(from_names && as_string && (ctx = g_xkbFn.context_new(0)));
    g_xkbLibsUnavailable = 1; /* Never connect to the test host's desktop. */
    const char *layouts[] = {"us", "fr"};
    const uint32_t points[] = {0x00e9, 0x03a9, 0x4e2d, 0x1f600};
    for (size_t i = 0; i < 2; ++i)
    {
        names.layout = layouts[i];
        struct xkb_keymap *map = from_names(ctx, &names, 0); assert(map);
        char *base = as_string(map, 1); assert(base);
        uint32_t off, caps, num, both;
        assert(kvm_vk_lock_mask(base, 0, 0, &off) && off == 0);
        assert(kvm_vk_lock_mask(base, 4, 0, &caps) && caps != 0);
        assert(kvm_vk_lock_mask(base, 1, 0, &num) && num != 0 && !(caps & num));
        assert(kvm_vk_lock_mask(base, 5, 0, &both) && both == (caps | num));
        assert(kvm_vk_lock_mask(base, 0, both, &off) && off == 0);
        kvm_xkb_match before, after, unicode;
        assert(kvm_xkb_build_from_keymap_string(base));
        assert(kvm_xkb_lookup_unicode('A', 0, &before));
        for (size_t j = 0; j < 4; ++j)
        {
            char *custom = kvm_vk_keymap(base, points[j]); assert(custom);
            assert(kvm_xkb_build_from_keymap_string(custom));
            assert(kvm_xkb_lookup_unicode(points[j], 0, &unicode));
            struct xkb_keymap *typed = g_xkbFn.keymap_new_from_string(ctx, custom, 1, 0); assert(typed);
            struct xkb_state *state = g_xkbFn.state_new(typed); assert(state);
            assert(g_xkbFn.state_key_get_utf32(state, 202) == points[j]);
            g_xkbFn.state_unref(state); g_xkbFn.keymap_unref(typed);
            assert(kvm_xkb_lookup_unicode('A', 0, &after));
            assert(before.keycode == after.keycode && before.shift == after.shift && before.altgr == after.altgr);
            int fd = kvm_vk_map_fd(custom); assert(fd >= 0);
            assert((fcntl(fd, F_GET_SEALS) & F_SEAL_WRITE) && write(fd, "x", 1) == -1 && errno == EPERM);
            close(fd); free(custom);
        }
        assert(!kvm_vk_keymap(base, 0) && !kvm_vk_keymap(base, 0xd800) && !kvm_vk_keymap(base, 0x110000));
        free(base); g_xkbFn.keymap_unref(map);
    }
    g_xkbFn.context_unref(ctx);
    g_xkbLibsUnavailable = 0;
    puts("Virtual Unicode maps preserve US/French keys, four Unicode ranges and sealed descriptors: passed");
}
static int closed, dispatched, token;
static int broken_prepare(struct wl_display *d) { (void)d; return -1; }
static int broken_dispatch(struct wl_display *d) { (void)d; dispatched++; return -1; }
static void closed_display(struct wl_display *d) { (void)d; closed++; }
int main(void)
{
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/cosmic-comp"), "/usr/bin/cosmic-comp"));
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/sway"), "/usr/bin/sway"));
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/labwc (deleted)"), "/usr/bin/labwc"));
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/miriway-shell"), "/usr/bin/miriway-shell"));
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/miracle-wm"), "/usr/bin/miracle-wm"));
    assert(!strcmp(kvm_vk_compositor_executable("/usr/bin/kylin-wlcom"), "/usr/bin/kylin-wlcom"));
    assert(!kvm_vk_compositor_executable("/tmp/kylin-wlcom"));
    assert(!kvm_vk_compositor_executable("/usr/bin/miriway-shell-test"));
    assert(!kvm_vk_compositor_executable("/tmp/sway"));
    assert(!kvm_vk_compositor_executable("/usr/bin/sway-nested"));
    assert(!kvm_vk_compositor_executable("/usr/bin/labwc (deleted) extra"));
    assert(!kvm_vk_compositor_executable("/usr/bin/gnome-shell"));
    assert(!kvm_vk_compositor_executable(NULL));
    virtual_map_tests();
    kvm_vk_restore_system_map(NULL, record_restore, 7, 0, 1, 2, 4, 3);
    assert(restore_calls == 3);
    restore_calls = 0; restore_map_size = 123;
    kvm_vk_restore_system_map(NULL, record_restore, 7, restore_map_size, 1, 2, 4, 3);
    assert(restore_calls == 3);
    puts("System map activation precedes exact modifier restoration without a key press: passed");
    g_xkbAuthenticatedDisplay=(struct wl_display *)&token;
    g_xkbPreparedUid=1000;g_xkbPreparedPid=123;
    assert(kvm_vk_prepared_peer_matches(g_xkbAuthenticatedDisplay,1000,123));
    assert(!kvm_vk_prepared_peer_matches(NULL,1000,123));
    assert(!kvm_vk_prepared_peer_matches((struct wl_display *)&closed,1000,123));
    assert(!kvm_vk_prepared_peer_matches(g_xkbAuthenticatedDisplay,1001,123));
    assert(!kvm_vk_prepared_peer_matches(g_xkbAuthenticatedDisplay,1000,124));
    assert(!kvm_vk_prepared_peer_matches(g_xkbAuthenticatedDisplay,0,123));
    g_xkbDisplay=(struct wl_display *)&token;
    x_wl_display_prepare_read=broken_prepare;
    x_wl_display_dispatch_pending=broken_dispatch;
    x_wl_display_disconnect=closed_display;
    kvm_xkb_pump();
    assert(!g_xkbAuthenticatedDisplay && !g_xkbPreparedUid && !g_xkbPreparedPid);
    if (g_xkbDisplay!=NULL || closed!=1 || dispatched!=1) { return 1; }
    kvm_xkb_pump();
    if (closed!=1 || dispatched!=1) { return 1; }
    puts("Broken Wayland connection disconnects once without spinning: passed");
    puts("Preauthenticated peer identity is bound to one connection and cleared on disconnect: passed");
    return 0;
}
