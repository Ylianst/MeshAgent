/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "linux_kvm_xkb.h"

#if defined(__linux__)

#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <wayland-client.h>

// ---- libwayland-client via dlopen (same pattern as linux_kvm_drm.c: the header's inline request
// wrappers would bake in link-time wl_proxy_* references and keep libwayland in NEEDED) -----------

// The array marshallers instead of wl_proxy_marshal_flags: flags only exists in libwayland >= 1.20
// (2021), which would silently disable this whole path on Debian 11 / Ubuntu 20.04-era systems.
#define KVM_XKB_WAYLAND_SYMBOLS(_) \
	_(wl_display_connect) _(wl_display_disconnect) \
	_(wl_display_flush) _(wl_display_dispatch_pending) _(wl_display_prepare_read) \
	_(wl_display_read_events) _(wl_display_cancel_read) _(wl_display_get_error) _(wl_display_get_fd) \
	_(wl_proxy_marshal_array_constructor) _(wl_proxy_marshal_array_constructor_versioned) \
	_(wl_proxy_add_listener) _(wl_proxy_destroy)

#define KVM_XKB_WL_DECL_PTR(s) static __typeof__(s) *x_##s = NULL;
KVM_XKB_WAYLAND_SYMBOLS(KVM_XKB_WL_DECL_PTR)
#undef KVM_XKB_WL_DECL_PTR

static const struct wl_interface *x_wl_registry_interface = NULL;
static const struct wl_interface *x_wl_seat_interface = NULL;
static const struct wl_interface *x_wl_keyboard_interface = NULL;
static const struct wl_interface *x_wl_callback_interface = NULL;
static void *g_xkb_libwayland = NULL;

static int kvm_xkb_load_wayland(void)
{
	void *h;
	if (g_xkb_libwayland != NULL) { return 1; }
	if ((h = dlopen("libwayland-client.so.0", RTLD_NOW)) == NULL && (h = dlopen("libwayland-client.so", RTLD_NOW)) == NULL)
	{
		return 0;
	}
#define KVM_XKB_WL_LOAD_PTR(s) x_##s = (__typeof__(x_##s))dlsym(h, #s); if (x_##s == NULL) { dlclose(h); return 0; }
	KVM_XKB_WAYLAND_SYMBOLS(KVM_XKB_WL_LOAD_PTR)
#undef KVM_XKB_WL_LOAD_PTR
	x_wl_registry_interface = (const struct wl_interface *)dlsym(h, "wl_registry_interface");
	x_wl_seat_interface = (const struct wl_interface *)dlsym(h, "wl_seat_interface");
	x_wl_keyboard_interface = (const struct wl_interface *)dlsym(h, "wl_keyboard_interface");
	x_wl_callback_interface = (const struct wl_interface *)dlsym(h, "wl_callback_interface");
	if (x_wl_registry_interface == NULL || x_wl_seat_interface == NULL || x_wl_keyboard_interface == NULL || x_wl_callback_interface == NULL)
	{
		dlclose(h);
		return 0;
	}
	g_xkb_libwayland = h;
	return 1;
}

static struct wl_registry *kvm_xkb_wl_display_get_registry(struct wl_display *display)
{
	union wl_argument args[1];
	args[0].o = NULL;
	return (struct wl_registry *)x_wl_proxy_marshal_array_constructor((struct wl_proxy *)display,
		1 /*WL_DISPLAY_GET_REGISTRY*/, args, x_wl_registry_interface);
}
static void *kvm_xkb_wl_registry_bind(struct wl_registry *registry, uint32_t name, const struct wl_interface *interface, uint32_t version)
{
	union wl_argument args[4];
	args[0].u = name;
	args[1].s = interface->name;
	args[2].u = version;
	args[3].o = NULL;
	return (void *)x_wl_proxy_marshal_array_constructor_versioned((struct wl_proxy *)registry,
		0 /*WL_REGISTRY_BIND*/, args, interface, version);
}
static struct wl_keyboard *kvm_xkb_wl_seat_get_keyboard(struct wl_seat *seat)
{
	union wl_argument args[1];
	args[0].o = NULL;
	return (struct wl_keyboard *)x_wl_proxy_marshal_array_constructor((struct wl_proxy *)seat,
		1 /*WL_SEAT_GET_KEYBOARD*/, args, x_wl_keyboard_interface);
}

// ---- libxkbcommon via dlopen (hand-declared API: build hosts need no libxkbcommon-dev) ----------

struct xkb_context;
struct xkb_keymap;
struct xkb_state;
typedef uint32_t kvm_xkb_keycode_t;
typedef uint32_t kvm_xkb_mod_index_t;
typedef uint32_t kvm_xkb_mod_mask_t;
typedef uint32_t kvm_xkb_layout_index_t;
#define KVM_XKB_MOD_INVALID 0xFFFFFFFFu
#define KVM_XKB_KEYMAP_FORMAT_TEXT_V1 1

typedef struct kvm_xkb_exports
{
	struct xkb_context *(*context_new)(int flags);
	void (*context_unref)(struct xkb_context *ctx);
	struct xkb_keymap *(*keymap_new_from_string)(struct xkb_context *ctx, const char *str, int format, int flags);
	void (*keymap_unref)(struct xkb_keymap *keymap);
	kvm_xkb_keycode_t (*keymap_min_keycode)(struct xkb_keymap *keymap);
	kvm_xkb_keycode_t (*keymap_max_keycode)(struct xkb_keymap *keymap);
	kvm_xkb_layout_index_t (*keymap_num_layouts)(struct xkb_keymap *keymap);
	kvm_xkb_mod_index_t (*keymap_mod_get_index)(struct xkb_keymap *keymap, const char *name);
	struct xkb_state *(*state_new)(struct xkb_keymap *keymap);
	void (*state_unref)(struct xkb_state *state);
	int (*state_update_mask)(struct xkb_state *state, kvm_xkb_mod_mask_t depressed, kvm_xkb_mod_mask_t latched, kvm_xkb_mod_mask_t locked,
		kvm_xkb_layout_index_t layoutDepressed, kvm_xkb_layout_index_t layoutLatched, kvm_xkb_layout_index_t layoutLocked);
	uint32_t (*state_key_get_utf32)(struct xkb_state *state, kvm_xkb_keycode_t key);
} kvm_xkb_exports;

static kvm_xkb_exports g_xkbFn;
static void *g_xkb_libxkbcommon = NULL;

static int kvm_xkb_load_xkbcommon(void)
{
	void *h;
	if (g_xkb_libxkbcommon != NULL) { return 1; }
	if ((h = dlopen("libxkbcommon.so.0", RTLD_NOW)) == NULL && (h = dlopen("libxkbcommon.so", RTLD_NOW)) == NULL)
	{
		return 0;
	}
#define KVM_XKB_LOAD(field, sym) g_xkbFn.field = (__typeof__(g_xkbFn.field))dlsym(h, sym); if (g_xkbFn.field == NULL) { dlclose(h); return 0; }
	KVM_XKB_LOAD(context_new, "xkb_context_new")
	KVM_XKB_LOAD(context_unref, "xkb_context_unref")
	KVM_XKB_LOAD(keymap_new_from_string, "xkb_keymap_new_from_string")
	KVM_XKB_LOAD(keymap_unref, "xkb_keymap_unref")
	KVM_XKB_LOAD(keymap_min_keycode, "xkb_keymap_min_keycode")
	KVM_XKB_LOAD(keymap_max_keycode, "xkb_keymap_max_keycode")
	KVM_XKB_LOAD(keymap_num_layouts, "xkb_keymap_num_layouts")
	KVM_XKB_LOAD(keymap_mod_get_index, "xkb_keymap_mod_get_index")
	KVM_XKB_LOAD(state_new, "xkb_state_new")
	KVM_XKB_LOAD(state_unref, "xkb_state_unref")
	KVM_XKB_LOAD(state_update_mask, "xkb_state_update_mask")
	KVM_XKB_LOAD(state_key_get_utf32, "xkb_state_key_get_utf32")
#undef KVM_XKB_LOAD
	g_xkb_libxkbcommon = h;
	return 1;
}

// ---- reverse lookup tables ----------------------------------------------------------------------

typedef struct kvm_xkb_entry
{
	uint32_t codepoint;
	uint16_t keycode;	// evdev
	uint8_t shift;
	uint8_t altgr;
	uint8_t group;		// layout index the mapping belongs to
} kvm_xkb_entry;

typedef struct kvm_xkb_table
{
	kvm_xkb_entry *entries;
	int count;
	int capacity;
} kvm_xkb_table;

static kvm_xkb_table g_xkbCapsOff;
static kvm_xkb_table g_xkbCapsOn;
static int g_xkbTablesReady = 0;

static struct wl_display *g_xkbDisplay = NULL;
static struct wl_registry *g_xkbRegistry = NULL;
static struct wl_seat *g_xkbSeat = NULL;
static struct wl_keyboard *g_xkbKeyboard = NULL;
static uint32_t g_xkbSeatCaps = 0;
static int g_xkbLibsUnavailable = 0;
static uint64_t g_xkbLastAttemptMs = 0;
#define KVM_XKB_RETRY_MS 10000

static int kvm_xkb_debug(void)
{
	static int level = -1;
	if (level < 0)
	{
		const char *env = getenv("MESH_KVM_DRM_DEBUG");
		level = (env != NULL && *env != '\0') ? atoi(env) : 0;
		if (level < 0) { level = 0; }
	}
	return level;
}

static uint64_t kvm_xkb_now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
	return (((uint64_t)ts.tv_sec) * 1000ULL) + (((uint64_t)ts.tv_nsec) / 1000000ULL);
}

static int kvm_xkb_table_find(const kvm_xkb_table *table, uint32_t codepoint)
{
	int lo = 0;
	int hi = table->count - 1;
	while (lo <= hi)
	{
		int mid = lo + ((hi - lo) / 2);
		if (table->entries[mid].codepoint == codepoint) { return mid; }
		if (table->entries[mid].codepoint < codepoint) { lo = mid + 1; }
		else { hi = mid - 1; }
	}
	return -1;
}

// Unsorted linear check during build; tables are sorted once at the end. One entry per
// (codepoint, group) so lookup can prefer the group the user actually has active.
static int kvm_xkb_table_contains(const kvm_xkb_table *table, uint32_t codepoint, uint8_t group)
{
	int i;
	for (i = 0; i < table->count; ++i)
	{
		if (table->entries[i].codepoint == codepoint && table->entries[i].group == group) { return 1; }
	}
	return 0;
}

static int kvm_xkb_table_add(kvm_xkb_table *table, uint32_t codepoint, uint16_t keycode, uint8_t shift, uint8_t altgr, uint8_t group)
{
	if (table->count == table->capacity)
	{
		int newCap = table->capacity == 0 ? 256 : table->capacity * 2;
		kvm_xkb_entry *tmp = (kvm_xkb_entry *)realloc(table->entries, ((size_t)newCap) * sizeof(kvm_xkb_entry));
		if (tmp == NULL) { return 0; }
		table->entries = tmp;
		table->capacity = newCap;
	}
	table->entries[table->count].codepoint = codepoint;
	table->entries[table->count].keycode = keycode;
	table->entries[table->count].shift = shift;
	table->entries[table->count].altgr = altgr;
	table->entries[table->count].group = group;
	table->count++;
	return 1;
}

static void kvm_xkb_table_reset(kvm_xkb_table *table)
{
	free(table->entries);
	table->entries = NULL;
	table->count = 0;
	table->capacity = 0;
}

// Order: codepoint, then modifier cost (plain before Shift before AltGr), then group — so within a
// codepoint's run, the first entry is the overall cheapest and the first entry of any group is that
// group's cheapest.
static int kvm_xkb_entry_compare(const void *a, const void *b)
{
	const kvm_xkb_entry *ea = (const kvm_xkb_entry *)a;
	const kvm_xkb_entry *eb = (const kvm_xkb_entry *)b;
	int costa, costb;
	if (ea->codepoint < eb->codepoint) { return -1; }
	if (ea->codepoint > eb->codepoint) { return 1; }
	costa = (int)ea->shift + 2 * (int)ea->altgr;
	costb = (int)eb->shift + 2 * (int)eb->altgr;
	if (costa != costb) { return costa < costb ? -1 : 1; }
	if (ea->group != eb->group) { return ea->group < eb->group ? -1 : 1; }
	return 0;
}

// Build both tables by asking libxkbcommon what every (group, modifier, caps, keycode) combination
// produces - the same computation the compositor will run against our injected events, so the
// result is exact for any script with no case-mapping heuristics. First hit wins, iterating
// modifiers before groups, so the mapping with the fewest synthesized modifiers is preferred.
// The group carrying the codepoint is assumed active: a user typing that character switched the
// remote layout to it (the codepoint is unreachable otherwise, and was dropped entirely before).
int kvm_xkb_build_from_keymap_string(const char *keymapText)
{
	static struct xkb_context *ctx = NULL;
	struct xkb_keymap *keymap = NULL;
	struct xkb_state *state = NULL;
	kvm_xkb_mod_index_t idx;
	kvm_xkb_mod_mask_t shiftMask = 0, altgrMask = 0, capsMask = 0;
	kvm_xkb_mod_mask_t scenarioMasks[4];
	kvm_xkb_layout_index_t numLayouts, group;
	kvm_xkb_keycode_t minKc, maxKc, kc;
	int scenario, caps;

	if (keymapText == NULL || !kvm_xkb_load_xkbcommon()) { return 0; }
	if (ctx == NULL && (ctx = g_xkbFn.context_new(0)) == NULL) { return 0; }

	keymap = g_xkbFn.keymap_new_from_string(ctx, keymapText, KVM_XKB_KEYMAP_FORMAT_TEXT_V1, 0);
	if (keymap == NULL) { return 0; }
	state = g_xkbFn.state_new(keymap);
	if (state == NULL)
	{
		g_xkbFn.keymap_unref(keymap);
		return 0;
	}

	if ((idx = g_xkbFn.keymap_mod_get_index(keymap, "Shift")) != KVM_XKB_MOD_INVALID) { shiftMask = 1u << idx; }
	if ((idx = g_xkbFn.keymap_mod_get_index(keymap, "Mod5")) != KVM_XKB_MOD_INVALID) { altgrMask = 1u << idx; }	// AltGr = ISO_Level3_Shift = Mod5 on real keymaps
	if ((idx = g_xkbFn.keymap_mod_get_index(keymap, "Lock")) != KVM_XKB_MOD_INVALID) { capsMask = 1u << idx; }
	scenarioMasks[0] = 0;
	scenarioMasks[1] = shiftMask;
	scenarioMasks[2] = altgrMask;
	scenarioMasks[3] = shiftMask | altgrMask;

	kvm_xkb_table_reset(&g_xkbCapsOff);
	kvm_xkb_table_reset(&g_xkbCapsOn);
	g_xkbTablesReady = 0;

	numLayouts = g_xkbFn.keymap_num_layouts(keymap);
	if (numLayouts > 4) { numLayouts = 4; }
	minKc = g_xkbFn.keymap_min_keycode(keymap);
	maxKc = g_xkbFn.keymap_max_keycode(keymap);
	if (maxKc > 255 + 8) { maxKc = 255 + 8; }	// evdev keyboard range; the uinput device enables 1..255

	for (scenario = 0; scenario < 4; ++scenario)
	{
		if (scenario >= 2 && altgrMask == 0) { break; }	// keymap has no AltGr modifier: scenarios 2/3 duplicate 0/1
		for (group = 0; group < numLayouts; ++group)
		{
			for (caps = 0; caps < 2; ++caps)
			{
				kvm_xkb_table *table = caps ? &g_xkbCapsOn : &g_xkbCapsOff;
				g_xkbFn.state_update_mask(state, scenarioMasks[scenario], 0, caps ? capsMask : 0, 0, 0, group);
				for (kc = minKc; kc <= maxKc; ++kc)
				{
					uint32_t cp = g_xkbFn.state_key_get_utf32(state, kc);
					if (cp < 0x20 || cp == 0x7F || kc < 8) { continue; }
					if (kvm_xkb_table_contains(table, cp, (uint8_t)group)) { continue; }
					if (!kvm_xkb_table_add(table, cp, (uint16_t)(kc - 8), (uint8_t)(scenario & 1), (uint8_t)((scenario >> 1) & 1), (uint8_t)group))
					{
						kvm_xkb_table_reset(&g_xkbCapsOff);
						kvm_xkb_table_reset(&g_xkbCapsOn);
						g_xkbFn.state_unref(state);
						g_xkbFn.keymap_unref(keymap);
						return 0;
					}
				}
			}
		}
	}

	g_xkbFn.state_unref(state);
	g_xkbFn.keymap_unref(keymap);
	qsort(g_xkbCapsOff.entries, (size_t)g_xkbCapsOff.count, sizeof(kvm_xkb_entry), kvm_xkb_entry_compare);
	qsort(g_xkbCapsOn.entries, (size_t)g_xkbCapsOn.count, sizeof(kvm_xkb_entry), kvm_xkb_entry_compare);
	g_xkbTablesReady = 1;
	if (kvm_xkb_debug())
	{
		fprintf(stderr, "XKB: keymap tables built: %u layout(s), %d codepoint(s)\n", numLayouts, g_xkbCapsOff.count);
	}
	return 1;
}

// ---- wl_seat / wl_keyboard plumbing -------------------------------------------------------------

static void kvm_xkb_on_keymap(void *data, struct wl_keyboard *keyboard, uint32_t format, int32_t fd, uint32_t size)
{
	void *mapped;
	char *text;
	if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 || size == 0)
	{
		close(fd);
		return;
	}
	mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapped == MAP_FAILED) { return; }
	// wl_keyboard delivers the keymap with a terminating NUL inside size, but don't rely on it.
	text = (char *)malloc((size_t)size + 1);
	if (text != NULL)
	{
		memcpy(text, mapped, size);
		text[size] = 0;
	}
	munmap(mapped, size);
	if (text == NULL) { return; }
	kvm_xkb_build_from_keymap_string(text);
	free(text);
}
static void kvm_xkb_on_kb_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface, struct wl_array *keys) { }
static void kvm_xkb_on_kb_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial, struct wl_surface *surface) { }
static void kvm_xkb_on_kb_key(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) { }
// Compositors that broadcast modifier state to unfocused keyboards keep us informed of the active
// layout group (Alt+Shift switches land here); ones that don't leave the group at 0 and lookup
// falls back to its cheapest-entry order, which is the pre-group-tracking behavior.
static uint32_t g_xkbActiveGroup = 0;
static void kvm_xkb_on_kb_modifiers(void *data, struct wl_keyboard *keyboard, uint32_t serial, uint32_t depressed, uint32_t latched, uint32_t locked, uint32_t group)
{
	(void)data; (void)keyboard; (void)serial; (void)depressed; (void)latched; (void)locked;
	g_xkbActiveGroup = group;
}
static void kvm_xkb_on_kb_repeat_info(void *data, struct wl_keyboard *keyboard, int32_t rate, int32_t delay) { }

static const struct wl_keyboard_listener g_xkbKeyboardListener =
{
	kvm_xkb_on_keymap,
	kvm_xkb_on_kb_enter,
	kvm_xkb_on_kb_leave,
	kvm_xkb_on_kb_key,
	kvm_xkb_on_kb_modifiers,
	kvm_xkb_on_kb_repeat_info
};

static void kvm_xkb_on_seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities)
{
	g_xkbSeatCaps = capabilities;
}
static void kvm_xkb_on_seat_name(void *data, struct wl_seat *seat, const char *name) { }

static const struct wl_seat_listener g_xkbSeatListener =
{
	kvm_xkb_on_seat_capabilities,
	kvm_xkb_on_seat_name
};

static void kvm_xkb_on_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
	if (g_xkbSeat == NULL && interface != NULL && strcmp(interface, "wl_seat") == 0)
	{
		g_xkbSeat = (struct wl_seat *)kvm_xkb_wl_registry_bind(registry, name, x_wl_seat_interface, 1);
		if (g_xkbSeat != NULL)
		{
			x_wl_proxy_add_listener((struct wl_proxy *)g_xkbSeat, (void (**)(void))&g_xkbSeatListener, NULL);
		}
	}
}
static void kvm_xkb_on_global_remove(void *data, struct wl_registry *registry, uint32_t name) { }

static const struct wl_registry_listener g_xkbRegistryListener =
{
	kvm_xkb_on_global,
	kvm_xkb_on_global_remove
};

// Tears down the Wayland connection only; existing lookup tables survive so typing keeps working
// with the last known keymap if the compositor connection drops.
static void kvm_xkb_disconnect(void)
{
	if (g_xkbKeyboard != NULL) { x_wl_proxy_destroy((struct wl_proxy *)g_xkbKeyboard); g_xkbKeyboard = NULL; }
	if (g_xkbSeat != NULL) { x_wl_proxy_destroy((struct wl_proxy *)g_xkbSeat); g_xkbSeat = NULL; }
	if (g_xkbRegistry != NULL) { x_wl_proxy_destroy((struct wl_proxy *)g_xkbRegistry); g_xkbRegistry = NULL; }
	if (g_xkbDisplay != NULL) { x_wl_display_disconnect(g_xkbDisplay); g_xkbDisplay = NULL; }
	g_xkbSeatCaps = 0;
}

// Non-blocking drain of pending events so keymap changes (layout added/removed) are picked up
// between keystrokes without ever stalling input injection on a hung compositor.
static void kvm_xkb_pump(void)
{
	struct pollfd pfd;
	if (g_xkbDisplay == NULL) { return; }
	while (x_wl_display_prepare_read(g_xkbDisplay) != 0)
	{
		x_wl_display_dispatch_pending(g_xkbDisplay);
	}
	x_wl_display_flush(g_xkbDisplay);
	pfd.fd = x_wl_display_get_fd(g_xkbDisplay);
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN) != 0)
	{
		x_wl_display_read_events(g_xkbDisplay);
	}
	else
	{
		x_wl_display_cancel_read(g_xkbDisplay);
	}
	x_wl_display_dispatch_pending(g_xkbDisplay);
	if (x_wl_display_get_error(g_xkbDisplay) != 0)
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: Wayland connection error; keeping last keymap tables\n"); }
		kvm_xkb_disconnect();
	}
}

static void kvm_xkb_on_sync_done(void *data, struct wl_callback *callback, uint32_t serial)
{
	(void)callback; (void)serial;
	*(int *)data = 1;
}
static const struct wl_callback_listener g_xkbSyncListener = { kvm_xkb_on_sync_done };

// Deadline-bounded stand-in for wl_display_roundtrip. This runs on the slave's only thread; an
// unbounded roundtrip against a hung compositor would stop the master2slave drain and re-arm the
// agent-wide pipe stall that kvm_drm_write_all exists to prevent. Returns 1 when the sync
// callback fired, 0 on timeout or connection error (caller disconnects; ASCII fallback remains).
static int kvm_xkb_roundtrip_deadline(uint64_t deadlineMs)
{
	union wl_argument args[1];
	struct wl_callback *cb;
	int done = 0;

	if (g_xkbDisplay == NULL) { return 0; }
	args[0].o = NULL;
	cb = (struct wl_callback *)x_wl_proxy_marshal_array_constructor((struct wl_proxy *)g_xkbDisplay,
		0 /*WL_DISPLAY_SYNC*/, args, x_wl_callback_interface);
	if (cb == NULL) { return 0; }
	x_wl_proxy_add_listener((struct wl_proxy *)cb, (void (**)(void))&g_xkbSyncListener, &done);

	while (!done)
	{
		struct pollfd pfd;
		uint64_t now;
		int pr;

		if (x_wl_display_dispatch_pending(g_xkbDisplay) < 0) { break; }
		if (done) { break; }
		while (x_wl_display_prepare_read(g_xkbDisplay) != 0)
		{
			if (x_wl_display_dispatch_pending(g_xkbDisplay) < 0) { goto out; }
		}
		x_wl_display_flush(g_xkbDisplay);

		now = kvm_xkb_now_ms();
		pfd.fd = x_wl_display_get_fd(g_xkbDisplay);
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = (now >= deadlineMs) ? 0 : poll(&pfd, 1, (int)(deadlineMs - now));
		if (pr <= 0)
		{
			int savedErrno = errno;
			x_wl_display_cancel_read(g_xkbDisplay);
			if (pr < 0 && savedErrno == EINTR && kvm_xkb_now_ms() < deadlineMs) { continue; }
			break;
		}
		if (x_wl_display_read_events(g_xkbDisplay) < 0) { break; }
	}
out:
	// Destroy before returning: the listener writes into this frame's 'done', so a late-arriving
	// event dispatched by a future pump must find the proxy already dead.
	x_wl_proxy_destroy((struct wl_proxy *)cb);
	return done;
}

#define KVM_XKB_CONNECT_TIMEOUT_MS 2000

static int kvm_xkb_try_connect(void)
{
	uint64_t deadline;
	if (!kvm_xkb_load_wayland() || !kvm_xkb_load_xkbcommon())
	{
		g_xkbLibsUnavailable = 1;
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: libwayland-client/libxkbcommon unavailable; unicode limited to ASCII\n"); }
		return 0;
	}

	g_xkbDisplay = x_wl_display_connect(NULL);
	if (g_xkbDisplay == NULL)
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: wl_display_connect failed (WAYLAND_DISPLAY=%s)\n", getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "unset"); }
		return 0;
	}
	g_xkbRegistry = kvm_xkb_wl_display_get_registry(g_xkbDisplay);
	if (g_xkbRegistry == NULL)
	{
		kvm_xkb_disconnect();
		return 0;
	}
	x_wl_proxy_add_listener((struct wl_proxy *)g_xkbRegistry, (void (**)(void))&g_xkbRegistryListener, NULL);
	deadline = kvm_xkb_now_ms() + KVM_XKB_CONNECT_TIMEOUT_MS;
	if (!kvm_xkb_roundtrip_deadline(deadline) ||	// globals: binds the seat
		!kvm_xkb_roundtrip_deadline(deadline))		// seat capabilities
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: Wayland roundtrip timed out/failed during connect\n"); }
		kvm_xkb_disconnect();
		return 0;
	}
	if (g_xkbSeat == NULL || (g_xkbSeatCaps & WL_SEAT_CAPABILITY_KEYBOARD) == 0)
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: no wl_seat with keyboard capability\n"); }
		kvm_xkb_disconnect();
		return 0;
	}
	g_xkbKeyboard = kvm_xkb_wl_seat_get_keyboard(g_xkbSeat);
	if (g_xkbKeyboard == NULL)
	{
		kvm_xkb_disconnect();
		return 0;
	}
	x_wl_proxy_add_listener((struct wl_proxy *)g_xkbKeyboard, (void (**)(void))&g_xkbKeyboardListener, NULL);
	if (!kvm_xkb_roundtrip_deadline(deadline))	// keymap event -> tables
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: Wayland roundtrip timed out/failed waiting for keymap\n"); }
		kvm_xkb_disconnect();
		return 0;
	}
	if (!g_xkbTablesReady)
	{
		if (kvm_xkb_debug()) { fprintf(stderr, "XKB: no usable keymap received\n"); }
		kvm_xkb_disconnect();
		return 0;
	}
	return 1;
}

static int kvm_xkb_ensure_ready(void)
{
	uint64_t now;
	if (g_xkbLibsUnavailable) { return g_xkbTablesReady; }
	if (g_xkbDisplay != NULL)
	{
		kvm_xkb_pump();
		return g_xkbTablesReady;
	}
	now = kvm_xkb_now_ms();
	if (g_xkbLastAttemptMs != 0 && (now - g_xkbLastAttemptMs) < KVM_XKB_RETRY_MS) { return g_xkbTablesReady; }
	g_xkbLastAttemptMs = now;
	kvm_xkb_try_connect();
	return g_xkbTablesReady;
}

int kvm_xkb_lookup_unicode(uint32_t codepoint, int capslockOn, kvm_xkb_match *match)
{
	const kvm_xkb_table *table;
	int i;
	if (match == NULL || !kvm_xkb_ensure_ready()) { return 0; }
	table = capslockOn ? &g_xkbCapsOn : &g_xkbCapsOff;
	i = kvm_xkb_table_find(table, codepoint);
	if (i < 0)
	{
		if (kvm_xkb_debug() >= 2) { fprintf(stderr, "XKB: U+%04X not reachable on the session keymap\n", codepoint); }
		return 0;
	}
	// The search landed somewhere in the codepoint's run; walk to its start (overall cheapest
	// entry), then prefer the active group's cheapest so shared characters (digits, punctuation)
	// inject on the layout the compositor will actually interpret them under.
	while (i > 0 && table->entries[i - 1].codepoint == codepoint) { i--; }
	{
		int best = i;
		int scan;
		for (scan = i; scan < table->count && table->entries[scan].codepoint == codepoint; ++scan)
		{
			if ((uint32_t)table->entries[scan].group == g_xkbActiveGroup) { best = scan; break; }
		}
		i = best;
	}
	match->keycode = table->entries[i].keycode;
	match->shift = table->entries[i].shift;
	match->altgr = table->entries[i].altgr;
	if (kvm_xkb_debug() >= 2)
	{
		fprintf(stderr, "XKB: U+%04X -> keycode %u shift=%d altgr=%d caps=%d group=%u(active=%u)\n",
			codepoint, match->keycode, match->shift, match->altgr, capslockOn ? 1 : 0,
			(unsigned)table->entries[i].group, (unsigned)g_xkbActiveGroup);
	}
	return 1;
}

void kvm_xkb_shutdown(void)
{
	kvm_xkb_disconnect();
	kvm_xkb_table_reset(&g_xkbCapsOff);
	kvm_xkb_table_reset(&g_xkbCapsOn);
	g_xkbTablesReady = 0;
	g_xkbLastAttemptMs = 0;
}

#else

int kvm_xkb_lookup_unicode(uint32_t codepoint, int capslockOn, kvm_xkb_match *match)
{
	(void)codepoint;
	(void)capslockOn;
	(void)match;
	return 0;
}

int kvm_xkb_build_from_keymap_string(const char *keymapText)
{
	(void)keymapText;
	return 0;
}

void kvm_xkb_shutdown(void)
{
}

#endif
