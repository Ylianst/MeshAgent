/*
 * Copyright 2026 MeshCentral contributors
 * SPDX-License-Identifier: Apache-2.0
 * Experimental: GNOME 46/48 lab qualification only.
 */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GioUnix from 'gi://GioUnix';
import Clutter from 'gi://Clutter';
import Shell from 'gi://Shell';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as Config from 'resource:///org/gnome/shell/misc/config.js';
import {encodeHeader, MAX_PIXELS} from './protocol.js';

const SOCKET = 'meshagent-gnome-prototype.sock';
const MAX_REQUEST = 8192;
const MAX_PNG = 16 * 1024 * 1024;
// Some stock GNOME distributions ship the legacy GLib entry point without
// the separately packaged GLibUnix typelib. Keep the current API where present.
const fdAdd = (() => {
    try { return imports.gi.GLibUnix.fd_add_full; }
    catch (error) {
        if (typeof GLib.unix_fd_add_full === 'function') return GLib.unix_fd_add_full;
        throw error;
    }
})();

export default class MeshAgentConsole extends Extension {
    enable() {
        try {
            this._enable();
        } catch (error) {
            this.disable();
            throw error;
        }
    }

    _enable() {
        this._generation = (this._generation ?? 0) + 1;
        this._enabled = true;
        this._epoch = GLib.uuid_string_random().replaceAll('-', '');
        this._revision = 1;
        this._cancellable = new Gio.Cancellable();
        this._powerSaveMode = null;
        this._connection = null;
        this._busy = false;
        this._bound = false;
        this._path = GLib.build_filenamev([GLib.get_user_runtime_dir(), SOCKET]);
        this._removeStaleEndpoint();
        this._service = new Gio.SocketService();
        this._service.add_address(Gio.UnixSocketAddress.new(this._path),
            Gio.SocketType.STREAM, Gio.SocketProtocol.DEFAULT, null);
        this._bound = true;
        this._socketInfo = Gio.File.new_for_path(this._path).query_info(
            'unix::inode,unix::device', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
        if (GLib.chmod(this._path, 0o600) !== 0)
            throw new Error('Unable to restrict bridge socket permissions');
        this._incomingId = this._service.connect('incoming', (_service, connection) => {
            try {
                if (connection.get_socket().get_credentials().get_unix_user() !== 0 ||
                    this._connection || !this._enabled) {
                    connection.close(null);
                    return true;
                }
                this._connection = connection;
                this._pending = '';
                this._frameFd = false;
                this._keyInput = false;
                this._inputExpiry = false;
                this._armTimeout(connection);
                this._read(connection);
            } catch (_error) {
                connection.close(null);
            }
            return true;
        });
        this._modeId = Main.sessionMode.connect('updated', () => this._invalidate());
        this._monitorsId = Main.layoutManager.connect('monitors-changed', () => this._invalidate());
        this._shooter = new Shell.Screenshot();
        this._pressedKeys = new Set();
        // Query our own compositor's exported power state asynchronously. A
        // synchronous proxy construction here could deadlock the Shell thread.
        const generation = this._generation;
        Gio.DBusProxy.new(Gio.DBus.session, Gio.DBusProxyFlags.DO_NOT_AUTO_START,
            null, 'org.gnome.Mutter.DisplayConfig', '/org/gnome/Mutter/DisplayConfig',
            'org.gnome.Mutter.DisplayConfig', this._cancellable, (_source, result) => {
                try {
                    const proxy = Gio.DBusProxy.new_finish(result);
                    if (!this._enabled || this._generation !== generation)
                        return;
                    this._displayProxy = proxy;
                    const update = () => {
                        const value = proxy.get_cached_property('PowerSaveMode')?.deep_unpack();
                        this._powerSaveMode = Number.isInteger(value) && value >= -1 && value <= 3 ? value : null;
                    };
                    this._powerId = proxy.connect('g-properties-changed', update);
                    update();
                } catch (_error) {
                    // Unknown power state is reported explicitly; it is never
                    // inferred from black or static pixels.
                }
            });
        this._service.start();
    }

    _removeStaleEndpoint() {
        const file = Gio.File.new_for_path(this._path);
        if (!file.query_exists(null))
            return;
        const attributes = 'unix::inode,unix::device,unix::uid,unix::mode';
        const before = file.query_info(attributes, Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
        const uid = Gio.Credentials.new().get_unix_user();
        const mode = before.get_attribute_uint32('unix::mode');
        if (before.get_attribute_uint32('unix::uid') !== uid ||
            (mode & 0xf000) !== 0xc000 || (mode & 0o077) !== 0)
            throw new Error('Existing bridge endpoint ownership or type invalid');
        const socket = Gio.Socket.new(Gio.SocketFamily.UNIX, Gio.SocketType.STREAM, Gio.SocketProtocol.DEFAULT);
        socket.set_blocking(false);
        let refused = false;
        try {
            socket.connect(Gio.UnixSocketAddress.new(this._path), null);
        } catch (error) {
            if (!error.matches(Gio.IOErrorEnum, Gio.IOErrorEnum.CONNECTION_REFUSED))
                throw error;
            refused = true;
        } finally {
            socket.close();
        }
        if (!refused)
            throw new Error('Bridge endpoint already listening');
        const after = file.query_info(attributes, Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
        if (after.get_attribute_uint64('unix::inode') !== before.get_attribute_uint64('unix::inode') ||
            after.get_attribute_uint32('unix::device') !== before.get_attribute_uint32('unix::device') ||
            after.get_attribute_uint32('unix::uid') !== uid ||
            after.get_attribute_uint32('unix::mode') !== mode)
            throw new Error('Bridge endpoint changed during stale recovery');
        file.delete(null);
    }

    _invalidate() {
        this._releaseKeys();
        this._revision = (this._revision + 1) >>> 0;
        if (this._revision === 0) {
            this._epoch = GLib.uuid_string_random().replaceAll('-', '');
            this._revision = 1;
        }
    }

    _armTimeout(connection) {
        if (this._timeoutId)
            GLib.Source.remove(this._timeoutId);
        this._timeoutId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 10, () => {
            this._timeoutId = 0;
            this._close(connection);
            return GLib.SOURCE_REMOVE;
        });
    }

    _close(connection) {
        if (this._fdWaitConnection === connection)
            this._fdWaitCancel?.();
        if (this._keyFrameConnection === connection)
            this._keyFrameCancel?.();
        if (this._connection === connection) {
            this._releaseKeys();
            if (this._timeoutId)
                GLib.Source.remove(this._timeoutId);
            this._timeoutId = 0;
            this._connection = null;
            this._pending = '';
        }
        try { connection.close(null); } catch (_error) { /* Already closed. */ }
    }

    _read(connection) {
        if (!this._enabled || this._connection !== connection)
            return;
        const generation = this._generation;
        connection.get_input_stream().read_bytes_async(4096, GLib.PRIORITY_DEFAULT,
            this._cancellable, (input, result) => {
                try {
                    const bytes = input.read_bytes_finish(result);
                    if (!this._enabled || generation !== this._generation || this._connection !== connection)
                        return;
                    if (!bytes.get_size()) {
                        this._close(connection);
                        return;
                    }
                    // Requests use ASCII JSON, with Unicode escaped by the Agent.
                    const data = bytes.get_data();
                    if (data.some(value => value > 127))
                        throw new Error('Request must use ASCII JSON');
                    this._pending += new TextDecoder().decode(data);
                    if (this._pending.length > MAX_REQUEST)
                        throw new Error('Request too large');
                    const end = this._pending.indexOf('\n');
                    if (end < 0) {
                        this._read(connection);
                        return;
                    }
                    // One outstanding request only. No queued capture flood.
                    if (end !== this._pending.length - 1)
                        throw new Error('Pipelining unsupported');
                    const request = JSON.parse(this._pending.slice(0, end));
                    this._pending = '';
                    this._armTimeout(connection);
                    this._dispatch(request, connection);
                } catch (_error) {
                    this._close(connection);
                }
            });
    }

    _status() {
        const focus = global.stage.get_key_focus();
        return {
            version: 1,
            frameFd: Boolean(this._frameFd),
            keyInput: Boolean(this._keyInput),
            inputExpiry: Boolean(this._inputExpiry),
            epoch: this._epoch,
            revision: this._revision,
            mode: Main.sessionMode.currentMode,
            locked: Main.sessionMode.isLocked,
            greeter: Main.sessionMode.isGreeter,
            displayAsleep: this._powerSaveMode !== null && this._powerSaveMode > 0,
            displayPowerUnknown: this._powerSaveMode === null,
            width: global.stage.width,
            height: global.stage.height,
            monitors: Main.layoutManager.monitors.map(m => ({
                x: m.x, y: m.y, width: m.width, height: m.height,
            })),
            shellTextFocus: focus instanceof Clutter.Text && focus.editable,
            inputMethodFocus: Boolean(Main.inputMethod?.currentFocus),
        };
    }

    async _text(text) {
        if (typeof text !== 'string' || !text.length || text.length > 1024 ||
            /[\u0000-\u001f\u007f]/u.test(text))
            throw new Error('Invalid text');
        for (const ch of text) {
            const cp = ch.codePointAt(0);
            if (cp >= 0xd800 && cp <= 0xdfff)
                throw new Error('Unpaired surrogate');
        }
        const focus = global.stage.get_key_focus();
        if (focus instanceof Clutter.Text && focus.editable) {
            // Use the focused widget's normal editing machinery. Never find a
            // password actor, read its contents, submit, unlock, or change focus.
            focus.delete_selection();
            focus.insert_text(text, focus.get_cursor_position());
            return {route: 'shell-text'};
        }
        if (!Main.inputMethod?.currentFocus)
            throw new Error('No compositor text focus');
        Main.inputMethod.commit(text);
        // Clutter queues IM_COMMIT, and Mutter sends text-input-v3.done from
        // a lower-priority idle. Acknowledging from the I/O callback can let
        // the next commit overtake that done event and overwrite pending text.
        await this._inputBarrier();
        return {route: 'input-method'};
    }

    _inputBarrier() {
        return new Promise((resolve, reject) => {
            this._textIdleReject = reject;
            // Mutter 46/48 handles IM events at DEFAULT and emits done at
            // DEFAULT+1. Run immediately after that, ahead of redraw/background
            // idles that can otherwise starve an acknowledgement in a busy dialog.
            this._textIdleId = GLib.idle_add(GLib.PRIORITY_DEFAULT + 2, () => {
                this._textIdleId = 0;
                this._textIdleReject = null;
                resolve();
                return GLib.SOURCE_REMOVE;
            });
        });
    }

    _keyFrameBarrier() {
        return new Promise((resolve, reject) => {
            let signal = 0;
            let timeout = 0;
            let finished = false;
            const finish = error => {
                if (finished)
                    return;
                finished = true;
                if (signal)
                    global.stage.disconnect(signal);
                if (timeout)
                    GLib.Source.remove(timeout);
                this._keyFrameCancel = null;
                this._keyFrameConnection = null;
                if (error)
                    reject(error);
                else
                    resolve();
            };
            try {
                // Mutter 46/48 drains queued Clutter events at before-frame.
                // An ordinary high-priority GLib idle can run before that.
                signal = global.stage.connect('after-update', () => finish());
                timeout = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 300, () => {
                    timeout = 0;
                    finish(new Error('Compositor key frame deadline'));
                    return GLib.SOURCE_REMOVE;
                });
                this._keyFrameConnection = this._connection;
                this._keyFrameCancel = error => finish(error ?? new Error('Compositor key cancelled'));
                global.stage.queue_redraw();
            } catch (error) {
                finish(error);
            }
        });
    }

    _releaseKeys() {
        const keys = [...(this._pressedKeys ?? [])];
        this._pressedKeys?.clear();
        for (const code of keys) {
            try { this._keyboard?.notify_key(GLib.get_monotonic_time(), code, Clutter.KeyState.RELEASED); }
            catch (_error) { /* Continue releasing the remaining held keys. */ }
        }
    }

    _checkInputDeadline(request) {
        if (!this._inputExpiry)
            return; // Older Agents retain their existing wire contract.
        const now = Math.floor(GLib.get_monotonic_time() / 1000);
        if (!Number.isSafeInteger(request.deadlineMs) || request.deadlineMs <= now ||
            request.deadlineMs > now + 1500)
            throw new Error('Compositor input deadline expired or invalid');
    }

    async _key(code, value) {
        if (!this._keyInput || !this._keyboard || !Number.isInteger(code) || code < 1 || code > 0x2ff ||
            (value !== 0 && value !== 1))
            throw new Error('Invalid compositor key');
        if (value === 1 && !this._pressedKeys.has(code) && this._pressedKeys.size >= 128)
            throw new Error('Too many held keys');
        const barrier = this._keyFrameBarrier();
        // If signal setup failed, await its rejection without injecting a key.
        if (this._keyFrameCancel) {
            try {
                if (value === 1 && !this._pressedKeys.has(code)) {
                    this._pressedKeys.add(code);
                    this._keyboard.notify_key(GLib.get_monotonic_time(), code, Clutter.KeyState.PRESSED);
                } else if (value === 0 && this._pressedKeys.delete(code)) {
                    this._keyboard.notify_key(GLib.get_monotonic_time(), code, Clutter.KeyState.RELEASED);
                }
            } catch (error) {
                this._keyFrameCancel(error);
            }
        }
        // A timeout never causes replay through a different input device.
        await barrier;
        return {route: 'shell-key'};
    }

    // Only entered after an explicit READY reply. No asynchronous stream read
    // is outstanding here, so ancillary descriptors cannot be consumed as JSON.
    _receiveFrameStream(connection) {
        return new Promise((resolve, reject) => {
            const socket = connection.get_socket();
            socket.set_blocking(false);
            let watch = 0;
            let timeout = 0;
            let finished = false;
            const finish = (error, stream = null) => {
                if (finished)
                    return;
                finished = true;
                if (watch)
                    GLib.Source.remove(watch);
                if (timeout)
                    GLib.Source.remove(timeout);
                this._fdWaitCancel = null;
                this._fdWaitConnection = null;
                if (error)
                    reject(error);
                else
                    resolve(stream);
            };
            this._fdWaitConnection = connection;
            this._fdWaitCancel = () => finish(new Error('Frame descriptor cancelled'));
            timeout = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 1000, () => {
                timeout = 0;
                finish(new Error('Frame descriptor deadline'));
                return GLib.SOURCE_REMOVE;
            });
            watch = fdAdd(GLib.PRIORITY_DEFAULT, socket.get_fd(),
                GLib.IOCondition.IN | GLib.IOCondition.HUP | GLib.IOCondition.ERR, () => {
                    let fd = -1;
                    watch = 0;
                    try {
                        fd = connection.receive_fd(null);
                        const path = '/proc/self/fd/' + fd;
                        const info = Gio.File.new_for_path(path).query_info(
                            'standard::type,standard::size,unix::uid,unix::mode',
                            Gio.FileQueryInfoFlags.NONE, null);
                        if (GLib.file_read_link(path) !== '/memfd:meshagent-gnome-frame (deleted)' ||
                            info.get_file_type() !== Gio.FileType.REGULAR || info.get_size() !== MAX_PNG ||
                            info.get_attribute_uint32('unix::uid') !== Gio.Credentials.new().get_unix_user() ||
                            (info.get_attribute_uint32('unix::mode') & 0o777) !== 0o600)
                            throw new Error('Invalid frame descriptor');
                        const stream = new GioUnix.OutputStream({fd, close_fd: true});
                        fd = -1;
                        finish(null, stream);
                    } catch (error) {
                        finish(error);
                    } finally {
                        if (fd >= 0)
                            GLib.close(fd);
                    }
                    return GLib.SOURCE_REMOVE;
                });
        });
    }

    _writeBytes(connection, bytes) {
        return new Promise((resolve, reject) => {
            connection.get_output_stream().write_all_async(bytes,
                GLib.PRIORITY_DEFAULT, this._cancellable, (output, result) => {
                    try { output.write_all_finish(result); resolve(); }
                    catch (error) { reject(error); }
                });
        });
    }

    async _capture(generation, revision, frameStream = null) {
        const powerSaveMode = this._powerSaveMode;
        const width = global.stage.width;
        const height = global.stage.height;
        const scale = Math.max(...Main.layoutManager.monitors.map((_monitor, i) => global.display.get_monitor_scale(i)));
        if (!Number.isFinite(scale) || scale < 1 || scale > 8 || width <= 0 || height <= 0 ||
            width * height * scale * scale > MAX_PIXELS)
            throw new Error('Capture dimensions too large');
        // This native API clears its Cairo surface and pixel buffer when the
        // asynchronous write finishes. Do not create per-frame Clutter/Cogl
        // content or returned GdkPixbuf wrappers whose native memory awaits JS GC.
        const shooter = this._shooter;
        const stream = frameStream ?? Gio.MemoryOutputStream.new_resizable();
        try {
            const [success] = await shooter.screenshot(false, stream);
            if (!success)
                throw new Error('Compositor capture failed');
            if (!this._enabled || this._generation !== generation || this._revision !== revision ||
                global.stage.width !== width || global.stage.height !== height ||
                this._powerSaveMode !== powerSaveMode)
                throw new Error('Capture generation changed');
            stream.close(null);
            if (frameStream)
                return {width, height, scale};
            const bytes = stream.steal_as_bytes();
            if (bytes.get_size() > MAX_PNG)
                throw new Error('Capture too large');
            return {width, height, scale, pngBytes: bytes.get_data()};
        } finally {
            if (!stream.is_closed())
                stream.close(null);
        }
    }

    async _dispatch(request, connection) {
        if (this._busy) {
            this._close(connection);
            return;
        }
        this._busy = true;
        const generation = this._generation;
        const revision = this._revision;
        let response;
        let payload = null;
        let resultCode = 1;
        try {
            if (!this._enabled || this._connection !== connection)
                throw new Error('Bridge unavailable');
            if (request?.op === 'status') {
                // Per-connection opt-in: old Agents must never see new flags.
                if (request.wire === 1 && Number.isInteger(request.features) &&
                    request.features > 0 && (request.features & ~7) === 0) {
                    if (request.features & 1)
                        this._frameFd = true;
                    // Keep the qualified 46/48 compositor-key route. When the
                    // legacy backend API is absent, native capture/text still
                    // work and the Agent retains its existing uinput keys.
                    // Some newer vendor Shell builds still expose the legacy
                    // entry point, although Mutter's threaded key backend is
                    // incompatible with that route. Keep it on qualified major
                    // APIs only; other Shell versions use the Agent's uinput.
                    const legacyKeys = ['46', '48'].includes(Config.PACKAGE_VERSION.split('.')[0]);
                    if ((request.features & 2) && legacyKeys && typeof Clutter.get_default_backend === 'function') {
                        this._keyboard ??= Clutter.get_default_backend().get_default_seat()
                            .create_virtual_device(Clutter.InputDeviceType.KEYBOARD_DEVICE);
                        this._keyInput = true;
                    }
                }
                if (request.wire === 1 && Number.isInteger(request.features) &&
                    request.features > 0 && (request.features & ~7) === 0 && (request.features & 4))
                    this._inputExpiry = true;
                response = this._status();
            }
            else if (request?.op === 'text') {
                if (request.wire === 1 &&
                    (request.epoch !== this._epoch || request.revision !== this._revision))
                    throw new Error('Input generation changed');
                // The Agent and Shell share the same kernel monotonic clock.
                // Reject queued input before injection if Shell was stalled past
                // the sender's receive deadline; never replay it after recovery.
                this._checkInputDeadline(request);
                response = await this._text(request.text);
            }
            else if (request?.op === 'key') {
                if (request.wire !== 1 || request.epoch !== this._epoch || request.revision !== revision)
                    throw new Error('Key generation changed');
                this._checkInputDeadline(request);
                response = await this._key(request.code, request.value);
            }
            else if (request?.op === 'capture' || request?.op === 'captureFd') {
                if (this._powerSaveMode === null || this._powerSaveMode > 0) {
                    resultCode = 2;
                    throw new Error('Display inactive or power state unavailable');
                }
                if (request.op === 'captureFd') {
                    if (!this._frameFd || request.wire !== 1 || request.epoch !== this._epoch ||
                        request.revision !== revision)
                        throw new Error('Frame descriptor capability or generation missing');
                    // The peer waits for this header before sending SCM_RIGHTS.
                    await this._writeBytes(connection, encodeHeader(this._status(), 'captureFd', 3));
                    let stream;
                    try {
                        if (!this._enabled || this._generation !== generation || this._connection !== connection)
                            throw new Error('Bridge unavailable');
                        stream = await this._receiveFrameStream(connection);
                        if (!this._enabled || this._generation !== generation ||
                            this._revision !== revision || this._connection !== connection)
                            throw new Error('Capture generation changed');
                    } catch (error) {
                        // Descriptor protocol failure is terminal, never replayed.
                        if (stream && !stream.is_closed())
                            stream.close(null);
                        this._close(connection);
                        throw error;
                    }
                    try {
                        response = await this._capture(generation, revision, stream);
                    } finally {
                        if (stream && !stream.is_closed())
                            stream.close(null);
                    }
                } else {
                    response = await this._capture(generation, revision);
                }
            }
            else
                throw new Error('Unsupported operation');
            response = {ok: true, ...response};
            if (response.pngBytes) {
                payload = response.pngBytes;
                delete response.pngBytes;
                if (request.wire !== 1)
                    response.png = GLib.base64_encode(payload);
            }
        } catch (error) {
            // Display power may change after capture started. Treat an
            // authoritative off/unknown state as suspension, just as for the
            // pre-capture check, so an ordinary idle blank does not retire the
            // authenticated worker. Awake capture errors remain hard failures.
            if ((request?.op === 'capture' || request?.op === 'captureFd') &&
                (this._powerSaveMode === null || this._powerSaveMode > 0))
                resultCode = 2;
            if (request?.op === 'key')
                this._releaseKeys();
            // Do not echo request text or capture content into diagnostics.
            response = {ok: false, error: error.message};
        }
        if (!this._enabled || generation !== this._generation || this._connection !== connection) {
            if (generation === this._generation)
                this._busy = false;
            return;
        }
        let bytes;
        try {
            if (request.wire === 1) {
                const header = encodeHeader(this._status(), request.op,
                    response.ok ? 0 : resultCode, response.ok && payload ? payload.length : 0);
                bytes = new Uint8Array(header.length + (response.ok && payload ? payload.length : 0));
                bytes.set(header);
                if (response.ok && payload)
                    bytes.set(payload, header.length);
            } else {
                bytes = new TextEncoder().encode(JSON.stringify(response) + '\n');
            }
        } catch (_error) {
            this._busy = false;
            this._close(connection);
            return;
        }
        connection.get_output_stream().write_all_async(bytes,
            GLib.PRIORITY_DEFAULT, this._cancellable, (output, result) => {
                if (generation === this._generation)
                    this._busy = false;
                try {
                    output.write_all_finish(result);
                    this._read(connection);
                } catch (_error) {
                    this._close(connection);
                }
            });
    }

    disable() {
        this._enabled = false;
        this._generation = (this._generation ?? 0) + 1;
        this._keyFrameCancel?.(new Error('Bridge disabled'));
        this._cancellable?.cancel();
        this._cancellable = null;
        if (this._textIdleId)
            GLib.Source.remove(this._textIdleId);
        this._textIdleId = 0;
        this._textIdleReject?.(new Error('Bridge disabled'));
        this._textIdleReject = null;
        if (this._powerId && this._displayProxy)
            this._displayProxy.disconnect(this._powerId);
        this._powerId = 0;
        this._displayProxy = null;
        this._shooter = null;
        this._releaseKeys();
        this._keyboard?.run_dispose();
        this._keyboard = null;
        this._keyInput = false;
        this._inputExpiry = false;
        if (this._modeId)
            Main.sessionMode.disconnect(this._modeId);
        if (this._monitorsId)
            Main.layoutManager.disconnect(this._monitorsId);
        this._modeId = 0;
        this._monitorsId = 0;
        this._service?.stop();
        this._service?.close();
        if (this._incomingId)
            this._service.disconnect(this._incomingId);
        this._incomingId = 0;
        if (this._connection)
            this._close(this._connection);
        this._service = null;
        if (this._path && this._bound) {
            try {
                const file = Gio.File.new_for_path(this._path);
                const info = file.query_info('unix::inode,unix::device',
                    Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
                if (this._socketInfo &&
                    info.get_attribute_uint64('unix::inode') === this._socketInfo.get_attribute_uint64('unix::inode') &&
                    info.get_attribute_uint32('unix::device') === this._socketInfo.get_attribute_uint32('unix::device'))
                    file.delete(null);
            } catch (_error) { /* Absent or replaced; do not delete somebody else's path. */ }
            this._path = null;
        }
        this._bound = false;
        this._socketInfo = null;
    }
}
