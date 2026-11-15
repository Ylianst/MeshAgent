/* SPDX-License-Identifier: Apache-2.0
 * Optional zwp_virtual_keyboard_v1 client. Protocol ABI:
 * https://github.com/atx/wtype/blob/master/protocol/virtual-keyboard-unstable-v1.xml
 * This is used only for characters absent from the real keyboard map, on an
 * authenticated stock compositor below. Existing input routes stay first.
 *
 * Provider kinds below describe behavior, not release/package versions:
 * 0 = refused, 1 = COSMIC NoKeymap restore, 2 = full XKB-map restore,
 * 3 = Miriway device initialization followed by full-map restore.
 * Keep these differences local to this adapter; they must not alter the
 * physical keyboard layout or the existing mapped-key/uinput path.
 */
static const struct wl_message kvm_vk_requests[] = {
    {"keymap", "uhu", NULL}, {"key", "uuu", NULL},
    {"modifiers", "uuuu", NULL}, {"destroy", "", NULL}
};
static const struct wl_interface kvm_vk_interface = {
    "zwp_virtual_keyboard_v1", 1, 4, kvm_vk_requests, 0, NULL
};
static const struct wl_interface *kvm_vk_create_types[2];
static const struct wl_message kvm_vk_manager_requests[] = {
    {"create_virtual_keyboard", "on", kvm_vk_create_types}
};
static const struct wl_interface kvm_vk_manager_interface = {
    "zwp_virtual_keyboard_manager_v1", 1, 1, kvm_vk_manager_requests, 0, NULL
};

static const char *kvm_vk_compositor_executable(const char *exe)
{
    /* Exact installed images, not process names or arbitrary wlroots/Mir
     * clients. A new provider needs executable authentication and a live
     * map/lock-state restoration check before it belongs in this list. */
    static const char *paths[] = {"/usr/bin/cosmic-comp", "/usr/bin/sway", "/usr/bin/labwc",
        "/usr/bin/miriway-shell", "/usr/bin/miracle-wm", "/usr/bin/kylin-wlcom"};
    if (!exe) { return NULL; }
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
    {
        char deleted[128];
        snprintf(deleted, sizeof(deleted), "%s (deleted)", paths[i]);
        if (!strcmp(exe, paths[i]) || !strcmp(exe, deleted)) { return paths[i]; }
    }
    return NULL;
}

static int kvm_vk_prepared_peer_matches(const struct wl_display *display, uid_t uid, pid_t pid)
{
    return display && g_xkbAuthenticatedDisplay == display && uid > 0 &&
        uid == g_xkbPreparedUid && pid > 1 && pid == g_xkbPreparedPid;
}

static int kvm_vk_supported_peer(void)
{
    struct ucred peer;
    socklen_t length = sizeof(peer);
    struct stat expected, actual;
    char path[64], exe[PATH_MAX];
    ssize_t n;
    if (!g_xkbDisplay || geteuid() == 0 ||
        getsockopt(x_wl_display_get_fd(g_xkbDisplay), SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
        length != sizeof(peer) || peer.uid != geteuid() || peer.pid <= 1) { return 0; }
    /* This exact live connection was authenticated before the full privilege
     * drop. Fedora's capability-bearing Sway denies /proc/PID/exe afterward.
     * Never carry this identity to a new connection or replacement peer. */
    if (kvm_vk_prepared_peer_matches(g_xkbDisplay,peer.uid,peer.pid)) { return 2; }
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)peer.pid);
    n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0 || n >= (ssize_t)sizeof(exe) - 1) { return 0; }
    exe[n] = 0;
    const char *installed = kvm_vk_compositor_executable(exe);
    if (!installed || stat(installed, &expected) || !S_ISREG(expected.st_mode) ||
        expected.st_uid != 0 || (expected.st_mode & 0022)) { return 0; }
    int verified =
        !stat(path, &actual) && S_ISREG(actual.st_mode) && actual.st_uid == 0 && !(actual.st_mode & 0022) &&
        ((actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino) ||
            strstr(exe, " (deleted)") != NULL);
    /* COSMIC supports NoKeymap; wlroots requires a valid XKB-v1 map. */
    return verified ? (!strcmp(installed, "/usr/bin/cosmic-comp") ? 1 :
        (!strcmp(installed, "/usr/bin/miriway-shell") ? 3 : 2)) : 0;
}

void kvm_xkb_prepare_virtual_peer(int sessionUid)
{
    struct wl_display *display;
    struct wl_display *(*connect_fd)(int);
    struct sockaddr_un address;
    int fd = -1;
    struct ucred peer; socklen_t length = sizeof(peer);
    struct stat runtimeInfo, socketInfo, installed, actual;
    char runtime[64], socketPath[108], proc[64], exe[PATH_MAX];
    const char *name = getenv("WAYLAND_DISPLAY"); ssize_t size;
    if (geteuid() != 0 || sessionUid <= 0 || g_xkbDisplay || g_xkbPreparedDisplay ||
        !name || !*name || strchr(name, '/') || strlen(name) > 50) { return; }
    snprintf(runtime,sizeof(runtime),"/run/user/%d",sessionUid);
    snprintf(socketPath,sizeof(socketPath),"%s/%s",runtime,name);
    if (!getenv("XDG_RUNTIME_DIR") || strcmp(getenv("XDG_RUNTIME_DIR"),runtime) ||
        lstat(runtime,&runtimeInfo) || !S_ISDIR(runtimeInfo.st_mode) ||
        runtimeInfo.st_uid != (uid_t)sessionUid || (runtimeInfo.st_mode & 0077) ||
        lstat(socketPath,&socketInfo) || !S_ISSOCK(socketInfo.st_mode) ||
        socketInfo.st_uid != (uid_t)sessionUid) { return; }
    memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
    memcpy(address.sun_path,socketPath,strlen(socketPath)+1);
    fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd < 0) { return; }
    if (connect(fd,(struct sockaddr *)&address,sizeof(address)) ||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) ||
        length != sizeof(peer) || peer.uid != (uid_t)sessionUid || peer.pid <= 1) { goto reject; }
    snprintf(proc,sizeof(proc),"/proc/%d/exe",peer.pid);
    size=readlink(proc,exe,sizeof(exe)-1);
    if (size<=0 || size>=(ssize_t)sizeof(exe)-1) { goto reject; }
    exe[size]=0;
    /* Only Sway needs this path; all other working providers remain lazy. */
    if ((strcmp(exe,"/usr/bin/sway") && strcmp(exe,"/usr/bin/sway (deleted)")) ||
        stat("/usr/bin/sway",&installed) || stat(proc,&actual) ||
        !S_ISREG(installed.st_mode) || !S_ISREG(actual.st_mode) ||
        installed.st_uid || actual.st_uid || (installed.st_mode & 0022) || (actual.st_mode & 0022) ||
        ((installed.st_dev != actual.st_dev || installed.st_ino != actual.st_ino) && !strstr(exe," (deleted)"))) { goto reject; }
    if (!kvm_xkb_load_wayland() ||
        !(connect_fd=(void *)dlsym(g_xkb_libwayland,"wl_display_connect_to_fd"))) { goto reject; }
    /* libwayland owns fd from this point, including on initialization failure.
     * No registry request or reply parsing occurs until after the UID drop. */
    display=connect_fd(fd);fd=-1;
    if (!display) { return; }
    g_xkbPreparedDisplay=display;g_xkbPreparedUid=peer.uid;g_xkbPreparedPid=peer.pid;
    return;
reject:
    if (fd >= 0) { close(fd); }
}

/* Create a device-local map from the actual map. Retain all its other keys,
 * use one existing non-character slot, and remove that slot's modifiers.
 * XKB keycode 202 is evdev 194 + 8. Resolve its real name from the supplied
 * map rather than assuming a key name on every layout or architecture.
 * NoKeymap returns the compositor to its system map after each character.
 */
static char *kvm_vk_keymap(const char *base, uint32_t cp)
{
    const char *(*get_name)(struct xkb_keymap *, uint32_t);
    struct xkb_context *ctx = NULL;
    struct xkb_keymap *map = NULL;
    const char *name, *section, *p, *end = NULL;
    char insertion[192], *result = NULL;
    size_t size, prefix;
    int depth = 0, quoted = 0, escaped = 0, inserted;
    if (!base || cp < 0x20 || cp == 0x7f || cp > 0x10ffff ||
        (cp >= 0xd800 && cp <= 0xdfff) || (size = strlen(base)) > 1048576 ||
        !kvm_xkb_load_xkbcommon()) { return NULL; }
    get_name = (void *)dlsym(g_xkb_libxkbcommon, "xkb_keymap_key_get_name");
    if (!get_name || !(ctx = g_xkbFn.context_new(0)) ||
        !(map = g_xkbFn.keymap_new_from_string(ctx, base, KVM_XKB_KEYMAP_FORMAT_TEXT_V1, 0)) ||
        !(name = get_name(map, 202)) || !*name || strlen(name) > 8 ||
        strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != strlen(name)) { goto done; }
    section = strstr(base, "xkb_symbols");
    if (!section || !(section = strchr(section, '{'))) { goto done; }
    for (p = section; *p; ++p)
    {
        if (quoted)
        {
            if (escaped) { escaped = 0; }
            else if (*p == '\\') { escaped = 1; }
            else if (*p == '"') { quoted = 0; }
            continue;
        }
        if (*p == '"') { quoted = 1; }
        else if (*p == '{') { ++depth; }
        else if (*p == '}' && --depth == 0) { end = p; break; }
    }
    if (!end) { goto done; }
    inserted = snprintf(insertion, sizeof(insertion),
        "\nreplace key <%s> { type[Group1]=\"ONE_LEVEL\", symbols[Group1]=[ U%08X ] };\nmodifier_map None { <%s> };\n", name, cp, name);
    if (inserted < 0 || (size_t)inserted >= sizeof(insertion) ||
        !(result = malloc(size + (size_t)inserted + 1))) { goto done; }
    prefix = (size_t)(end - base);
    memcpy(result, base, prefix);
    memcpy(result + prefix, insertion, (size_t)inserted);
    memcpy(result + prefix + inserted, end, size - prefix + 1);
    {
        struct xkb_keymap *check = g_xkbFn.keymap_new_from_string(ctx, result, KVM_XKB_KEYMAP_FORMAT_TEXT_V1, 0);
        if (!check) { free(result); result = NULL; }
        else { g_xkbFn.keymap_unref(check); }
    }
done:
    if (map) { g_xkbFn.keymap_unref(map); }
    if (ctx) { g_xkbFn.context_unref(ctx); }
    return result;
}

static int kvm_vk_map_fd(const char *text)
{
    size_t size = strlen(text) + 1, offset = 0;
    int fd = -1;
#ifdef SYS_memfd_create
    fd = (int)syscall(SYS_memfd_create, "meshagent-virtual-keymap", MFD_CLOEXEC | MFD_ALLOW_SEALING);
#endif
    if (fd < 0) { return -1; }
    while (offset < size)
    {
        ssize_t n = write(fd, text + offset, size - offset);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { close(fd); return -1; }
        offset += (size_t)n;
    }
    if (lseek(fd, 0, SEEK_SET) < 0 ||
        fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
    { close(fd); return -1; }
    return fd;
}

/* Map LED state through the actual keymap rather than assuming Mod2/Mod3.
 * A virtual-keyboard keymap replacement resets compositor lock state. Restore
 * the pre-request state after returning the original map. */
static int kvm_vk_lock_mask(const char *base, unsigned int leds, uint32_t observed, uint32_t *locked)
{
    int (*update_key)(struct xkb_state *, uint32_t, int);
    uint32_t (*serialize_mods)(struct xkb_state *, int);
    struct xkb_context *ctx = NULL;
    struct xkb_keymap *map = NULL;
    const uint32_t keys[] = {77, 78, 66}; /* XKB Num, Scroll, Caps */
    int ok = 0;
    update_key = (void *)dlsym(g_xkb_libxkbcommon, "xkb_state_update_key");
    serialize_mods = (void *)dlsym(g_xkb_libxkbcommon, "xkb_state_serialize_mods");
    if (!update_key || !serialize_mods || !(ctx = g_xkbFn.context_new(0)) ||
        !(map = g_xkbFn.keymap_new_from_string(ctx, base, 1, 0))) { goto done; }
    *locked = observed;
    for (unsigned int i = 0; i < 3; ++i)
    {
        struct xkb_state *state = g_xkbFn.state_new(map);
        uint32_t mask;
        if (!state) { goto done; }
        update_key(state, keys[i], 1); update_key(state, keys[i], 0);
        mask = serialize_mods(state, 1 << 2); /* XKB_STATE_MODS_LOCKED */
        g_xkbFn.state_unref(state);
        *locked = (*locked & ~mask) | ((leds & (1u << i)) ? mask : 0);
    }
    ok = 1;
done:
    if (map) { g_xkbFn.keymap_unref(map); }
    if (ctx) { g_xkbFn.context_unref(ctx); }
    return ok;
}

static void kvm_vk_restore_system_map(struct wl_proxy *keyboard,
    void (*marshal)(struct wl_proxy *, uint32_t, union wl_argument *), int fd, size_t map_size,
    uint32_t depressed, uint32_t latched, uint32_t locked, uint32_t group)
{
    union wl_argument args[4];
    args[0].u = map_size ? 1 : 0; args[1].h = fd; args[2].u = (uint32_t)map_size;
    marshal(keyboard, 0, args);
    args[0].u = (uint32_t)kvm_xkb_now_ms(); args[1].u = 194; args[2].u = 0;
    marshal(keyboard, 1, args);
    args[0].u = depressed; args[1].u = latched; args[2].u = locked; args[3].u = group;
    marshal(keyboard, 2, args);
}

int kvm_xkb_type_unicode_virtual(uint32_t cp, unsigned int leds)
{
    void (*marshal)(struct wl_proxy *, uint32_t, union wl_argument *);
    struct wl_proxy *keyboard = NULL;
    union wl_argument args[4];
    uint32_t depressed, latched, locked, group;
    char *base = NULL, *custom = NULL;
    int base_fd = -1, custom_fd = -1, result = 0, compositor = 0;
    if (!kvm_xkb_ensure_ready() || !g_xkbDisplay || !g_xkbSeat || !g_xkbVirtualManagerName ||
        !g_xkbRawKeymap || !(compositor = kvm_vk_supported_peer()) ||
        !(marshal = (void *)dlsym(g_xkb_libwayland, "wl_proxy_marshal_array")) ||
        !(base = strdup(g_xkbRawKeymap)) || !(custom = kvm_vk_keymap(base, cp)) ||
        (base_fd = kvm_vk_map_fd(base)) < 0 || (custom_fd = kvm_vk_map_fd(custom)) < 0) { goto done; }
    if (!kvm_vk_lock_mask(base, leds, g_xkbLocked, &locked)) { goto done; }
    depressed = g_xkbDepressed; latched = g_xkbLatched; group = g_xkbActiveGroup;
    if (!g_xkbVirtualManager)
    {
        kvm_vk_create_types[0] = x_wl_seat_interface;
        kvm_vk_create_types[1] = &kvm_vk_interface;
        g_xkbVirtualManager = kvm_xkb_wl_registry_bind(g_xkbRegistry, g_xkbVirtualManagerName, &kvm_vk_manager_interface, 1);
    }
    if (!g_xkbVirtualManager) { goto done; }
    args[0].o = (struct wl_object *)g_xkbSeat; args[1].o = NULL;
    if (!g_xkbVirtualKeyboard)
    {
        g_xkbVirtualKeyboard = x_wl_proxy_marshal_array_constructor_versioned(g_xkbVirtualManager, 0, args, &kvm_vk_interface, 1);
        if (g_xkbVirtualKeyboard && compositor == 3)
        {
            /* Let Miriway finish configuring the newly added device before
             * applying a character map; its initial configuration otherwise
             * replaces that first map with the system map. No key is sent. */
            args[0].u=1;args[1].h=base_fd;args[2].u=(uint32_t)strlen(base)+1;
            marshal(g_xkbVirtualKeyboard,0,args);
            if (!kvm_xkb_roundtrip_deadline(kvm_xkb_now_ms()+400)) { result=-1;kvm_xkb_disconnect();goto done; }
        }
    }
    keyboard = g_xkbVirtualKeyboard;
    if (!keyboard) { goto done; }
    result = -1; /* Once requests are queued, never replay through another route. */
    args[0].u = 1; args[1].h = custom_fd; args[2].u = (uint32_t)strlen(custom) + 1;
    marshal(keyboard, 0, args);
    if (!kvm_xkb_roundtrip_deadline(kvm_xkb_now_ms() + 400)) { kvm_xkb_disconnect(); keyboard = NULL; goto done; }
    args[0].u = (uint32_t)kvm_xkb_now_ms(); args[1].u = 194; args[2].u = 1;
    marshal(keyboard, 1, args);
    x_wl_display_flush(g_xkbDisplay); usleep(20000);
    args[2].u = 0; marshal(keyboard, 1, args);
    if (!kvm_xkb_roundtrip_deadline(kvm_xkb_now_ms() + 400)) { kvm_xkb_disconnect(); keyboard = NULL; goto done; }
    /* NoKeymap returns to the compositor's own map. A protocol release of
     * our already released slot activates it without a synthetic key press.
     * Restore modifiers only after that activation; the next physical key
     * then uses the same map and cannot clear the saved locks again. */
    kvm_vk_restore_system_map(keyboard, marshal, base_fd, compositor == 1 ? 0 : strlen(base) + 1,
        depressed, latched, locked, group);
    keyboard = NULL; /* Keep the device alive until its Wayland connection closes. */
    if (kvm_xkb_roundtrip_deadline(kvm_xkb_now_ms() + 400)) { result = 1; }
    else { kvm_xkb_disconnect(); }
done:
    if (keyboard && result < 0) { kvm_xkb_disconnect(); }
    if (base_fd >= 0) { close(base_fd); }
    if (custom_fd >= 0) { close(custom_fd); }
    free(base); free(custom);
    return result;
}
