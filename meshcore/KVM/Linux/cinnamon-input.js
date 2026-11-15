/* SPDX-License-Identifier: Apache-2.0 */
// Runs only inside the authenticated active Cinnamon compositor through its
// stock session-local Eval API. No input policy or package files are changed.
// Paired with linux_kvm_cinnamon.c: op 1=key, 2=text, 3=poll, 4=dispose;
// results -1=invalid/uncertain, 0=complete, 1=pending, 2=no injection attempted.
// Keep this versioned entry point compatible while old capture workers exist.
(function(pid, token) {
    const {Clutter, GLib} = imports.gi;
    if (!imports.gi.Meta.is_wayland_compositor()) return -1;
    function incarnation(owner) {
        try {
            // /proc/PID/stat field 22 is the start time. Parse after the final
            // comm delimiter because process names can contain spaces/parentheses.
            const [, bytes] = GLib.file_get_contents('/proc/' + owner + '/stat');
            const text = imports.byteArray.toString(bytes);
            return text.substring(text.lastIndexOf(') ') + 2).trim().split(/\s+/)[19];
        } catch (_) { return null; }
    }
    if (!global._meshAgentCinnamonInputV1) {
        // Shared code lives in Shell; each worker gets its own device and keys.
        // The native peer checks establish trust; these records isolate cleanup.
        const records = Object.create(null);
        function dispose(key) {
            const r = records[key];
            if (!r) return;
            delete records[key];
            if (r.watch) GLib.source_remove(r.watch);
            for (const code of r.keys) r.device.notify_key(0, code, Clutter.KeyState.RELEASED);
            r.keys.clear();
            // Keep the device alive until the queued releases have run.
            GLib.idle_add(GLib.PRIORITY_DEFAULT + 2, () => {
                r.device.run_dispose();
                return GLib.SOURCE_REMOVE;
            });
        }
        global._meshAgentCinnamonInputV1 = function(key, operation, nonce, code, pressed) {
            const r = records[key];
            if (!r) return -1;
            if (operation === 4) { dispose(key); return 0; }
            if (incarnation(r.pid) !== r.start) { dispose(key); return -1; }
            if (operation === 3) return r.ack === nonce ? 0 : (r.pending === nonce ? 1 : -1);
            if (!Number.isInteger(nonce) || nonce <= 0 || nonce > 0xffffffff || r.pending) return -1;
            if (operation === 1) {
                if (!Number.isInteger(code) || code <= 0 || code > 767 || (pressed !== 0 && pressed !== 1)) return -1;
                if (r.keys.has(code) === !!pressed) { r.ack = nonce; return 0; }
                r.device.notify_key(0, code, pressed ? Clutter.KeyState.PRESSED : Clutter.KeyState.RELEASED);
                if (pressed) r.keys.add(code); else r.keys.delete(code);
                if (r.keys.size && !r.watch) {
                    r.watch = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 2, () => {
                        if (incarnation(r.pid) !== r.start) { r.watch = 0; dispose(key); return GLib.SOURCE_REMOVE; }
                        return GLib.SOURCE_CONTINUE;
                    });
                } else if (!r.keys.size && r.watch) { GLib.source_remove(r.watch); r.watch = 0; }
            } else if (operation === 2) {
                if (!Number.isInteger(code) || code < 0x20 || (code >= 0x7f && code < 0xa0) ||
                    code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return -1;
                const text = String.fromCodePoint(code);
                const focus = global.stage.get_key_focus();
                // Shell controls use Clutter.Text directly. Native applications
                // use the existing backend method; do not replace that method or
                // inspect surrounding application text to manufacture a commit.
                if (focus instanceof Clutter.Text && focus.editable) {
                    focus.delete_selection(); focus.insert_text(text, focus.get_cursor_position());
                } else {
                    const method = Clutter.get_default_backend().get_input_method();
                    if (!method) return 2; // No text queued; preserve the existing mapped-key fallback.
                    method.commit(text);
                }
            } else return -1;
            r.pending = nonce;
            // Clutter consumes IM events at DEFAULT and emits text-input done
            // at DEFAULT+1. Do not let the next request overwrite pending text.
            GLib.idle_add(GLib.PRIORITY_DEFAULT + 2, () => {
                if (records[key] === r) { r.ack = nonce; r.pending = 0; }
                return GLib.SOURCE_REMOVE;
            });
            return 1;
        };
        global._meshAgentCinnamonInputV1.records = records;
    }
    const records = global._meshAgentCinnamonInputV1.records;
    // A worker that died with no held keys needed no periodic watch. Reap its
    // device at the next connection instead of exhausting the bounded table.
    for (const key of Object.keys(records)) {
        if (incarnation(records[key].pid) !== records[key].start)
            global._meshAgentCinnamonInputV1(key, 4, 0, 0, 0);
    }
    if (records[token]) return records[token].pid === pid ? 0 : -1;
    // Bound devices even if several simultaneous viewers/workers are present.
    if (Object.keys(records).length >= 8) return -1;
    const start = incarnation(pid);
    if (!start) return -1;
    records[token] = {pid, start, keys: new Set(), pending: 0, ack: 0, watch: 0,
        device: Clutter.get_default_backend().get_default_seat().create_virtual_device(Clutter.InputDeviceType.KEYBOARD_DEVICE)};
    return 0;
})
