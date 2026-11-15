/* SPDX-License-Identifier: Apache-2.0 */
// Fixed binary replies avoid base64 expansion and a general JSON parser in the
// native capture worker. All integers use network byte order.
export const HEADER_SIZE = 60;
export const MAX_MONITORS = 16;
export const MAX_PIXELS = 16777216;
export const MAX_PAYLOAD = 16 * 1024 * 1024;
export const OPS = Object.freeze({status: 1, text: 2, capture: 3, captureFd: 4, key: 5});

export function encodeHeader(status, op, result, payloadLength = 0) {
    if (!OPS[op] || !Number.isInteger(result) || result < 0 || result > 3 || (result === 3 && op !== 'captureFd') ||
        (op === 'captureFd' && payloadLength !== 0) ||
        !Number.isInteger(payloadLength) || payloadLength < 0 || payloadLength > MAX_PAYLOAD ||
        !/^[a-f0-9]{32}$/.test(status.epoch) ||
        !Number.isInteger(status.revision) || status.revision < 1 || status.revision > 0xffffffff ||
        !Number.isInteger(status.width) || !Number.isInteger(status.height) ||
        status.width < 1 || status.height < 1 || status.width * status.height > MAX_PIXELS ||
        !Array.isArray(status.monitors) || status.monitors.length < 1 || status.monitors.length > MAX_MONITORS)
        throw new Error('Invalid bridge header');
    const bytes = new Uint8Array(HEADER_SIZE + 16 * status.monitors.length);
    bytes.set([0x41, 0x47, 0x4e, 0x31]); // AGN1
    const view = new DataView(bytes.buffer);
    view.setUint32(4, OPS[op]);
    view.setUint32(8, result);
    for (let i = 0; i < 16; i++)
        bytes[12 + i] = parseInt(status.epoch.slice(i * 2, i * 2 + 2), 16);
    view.setUint32(28, status.revision);
    view.setUint32(32, (status.locked ? 1 : 0) | (status.greeter ? 2 : 0) |
        (status.displayAsleep ? 4 : 0) | (status.displayPowerUnknown ? 8 : 0) | (status.frameFd ? 16 : 0) | (status.keyInput ? 32 : 0) | (status.inputExpiry ? 64 : 0));
    view.setUint32(36, status.width);
    view.setUint32(40, status.height);
    view.setUint32(44, status.monitors.length);
    view.setUint32(48, payloadLength);
    for (let i = 0; i < status.monitors.length; i++) {
        const m = status.monitors[i];
        if (![m.x, m.y, m.width, m.height].every(Number.isInteger) ||
            Math.abs(m.x) > 32768 || Math.abs(m.y) > 32768 ||
            m.width < 1 || m.height < 1 || m.width > 16384 || m.height > 16384)
            throw new Error('Invalid monitor geometry');
        const offset = HEADER_SIZE + i * 16;
        view.setInt32(offset, m.x);
        view.setInt32(offset + 4, m.y);
        view.setUint32(offset + 8, m.width);
        view.setUint32(offset + 12, m.height);
    }
    return bytes;
}
