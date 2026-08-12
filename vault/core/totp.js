/**
 * TOTP (RFC 6238) code generation — pure, DOM-free, WebCrypto only.
 *
 * The vault already STORES `totp` records (issuer + base32 secret); this turns
 * one into the live 6-digit code, so the UI can finally surface them. Kept out
 * of app.js and the derivation module so it can be audited and unit-tested on
 * its own (see test/core.test.mjs, checked against the RFC 6238 vectors).
 *
 * Only SHA-1/256/512 + 6–8 digits are supported — the union of what every
 * authenticator emits. HOTP counters are 64-bit; JS numbers are exact to 2^53,
 * far past any real Unix time, so the split-word encoding below is safe.
 */
(function (root) {
    'use strict';

    const subtle = (root.crypto || crypto).subtle;
    const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Decode an RFC 4648 base32 secret (case/space/padding insensitive). */
    function base32Decode(input) {
        const clean = String(input).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
        let bits = 0;
        let value = 0;
        const out = [];
        for (const ch of clean) {
            const idx = B32.indexOf(ch);
            if (idx === -1) throw new Error('invalid base32 character: ' + ch);
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.push((value >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return new Uint8Array(out);
    }

    function hashName(algorithm) {
        const a = String(algorithm || 'SHA1').toUpperCase().replace(/-/g, '');
        if (a === 'SHA1') return 'SHA-1';
        if (a === 'SHA256') return 'SHA-256';
        if (a === 'SHA512') return 'SHA-512';
        throw new Error('unsupported TOTP algorithm: ' + algorithm);
    }

    async function hotp(keyBytes, counter, digits, algorithm) {
        const key = await subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: { name: hashName(algorithm) } },
            false,
            ['sign']
        );
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        view.setUint32(0, Math.floor(counter / 0x100000000)); // high word
        view.setUint32(4, counter >>> 0); // low word
        const mac = new Uint8Array(await subtle.sign('HMAC', key, buf));
        // Dynamic truncation (RFC 4226 §5.3).
        const offset = mac[mac.length - 1] & 0x0f;
        const bin =
            ((mac[offset] & 0x7f) << 24) |
            (mac[offset + 1] << 16) |
            (mac[offset + 2] << 8) |
            mac[offset + 3];
        return String(bin % 10 ** digits).padStart(digits, '0');
    }

    /**
     * Current TOTP code for a base32 secret.
     * @param {string} secret - base32.
     * @param {{period?:number, digits?:number, algorithm?:string, timestamp?:number}} [opts]
     *   timestamp is Unix seconds, injectable for tests.
     * @returns {Promise<{code:string, period:number, secondsRemaining:number}>}
     */
    async function generate(secret, opts) {
        const o = opts || {};
        const period = o.period || 30;
        const digits = o.digits || 6;
        const now = typeof o.timestamp === 'number' ? o.timestamp : Math.floor(Date.now() / 1000);
        const code = await hotp(base32Decode(secret), Math.floor(now / period), digits, o.algorithm);
        return { code, period, secondsRemaining: period - (Math.floor(now) % period) };
    }

    /**
     * Parse an `otpauth://totp/...` URI (what QR codes encode) into fields.
     * Returns null if it is not a usable otpauth URI.
     */
    function parseOtpauth(uri) {
        const m = /^otpauth:\/\/(?:totp|hotp)\/([^?]*)\?(.*)$/i.exec(String(uri).trim());
        if (!m) return null;
        // Hostile input: a malformed percent-escape throws in
        // decodeURIComponent. That must not propagate to the caller as a raw
        // URIError — a non-usable URI reads as null, like any other bad input.
        const safeDecode = (s) => {
            try {
                return decodeURIComponent(s);
            } catch (e) {
                return null;
            }
        };
        const label = safeDecode(m[1] || '') || '';
        const params = new Map();
        for (const kv of m[2].split('&')) {
            const eq = kv.indexOf('=');
            if (eq === -1) continue;
            const value = safeDecode(kv.slice(eq + 1));
            if (value === null) continue;
            params.set(kv.slice(0, eq).toLowerCase(), value);
        }
        const secret = params.get('secret');
        if (!secret) return null;
        const colon = label.indexOf(':');
        return {
            issuer: (params.get('issuer') || (colon > -1 ? label.slice(0, colon) : '')).trim(),
            account: (colon > -1 ? label.slice(colon + 1) : label).trim(),
            secret: secret.replace(/\s+/g, ''),
            digits: parseInt(params.get('digits') || '6', 10) || 6,
            period: parseInt(params.get('period') || '30', 10) || 30,
            algorithm: (params.get('algorithm') || 'SHA1').toUpperCase()
        };
    }

    root.VaultTotp = { base32Decode, generate, parseOtpauth };
})(typeof window !== 'undefined' ? window : globalThis);
