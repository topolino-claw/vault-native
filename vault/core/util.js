/**
 * Small shared helpers for the vault core.
 *
 * Every file under vault/core/ is deliberately dependency-free and
 * environment-free: no DOM, no Tauri, no Node APIs, no bundler. They run
 * unchanged in a browser <script> tag, in a Node test via `await import()`,
 * and (once ported) inside the Obsidian plugin. The only ambient requirement
 * is WebCrypto, which all three provide.
 */
(function (root) {
    'use strict';

    const webcrypto = root.crypto || crypto;

    /** @returns {string} `bytes * 2` lowercase hex characters from the CSPRNG. */
    function randomHex(bytes) {
        const buf = new Uint8Array(bytes);
        webcrypto.getRandomValues(buf);
        let out = '';
        for (let i = 0; i < buf.length; i++) out += buf[i].toString(16).padStart(2, '0');
        return out;
    }

    function bytesToB64(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    /**
     * URL-safe base64 of a UTF-8 string. Used to build record ids out of
     * user-supplied text, so ids stay opaque, delimiter-safe and stable.
     */
    function textToB64Url(str) {
        return bytesToB64(new TextEncoder().encode(str))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    function b64UrlToText(b64url) {
        const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
        return new TextDecoder().decode(b64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4)));
    }

    /** Deep-ish clone adequate for the plain-JSON values the vault stores. */
    function clone(value) {
        return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
    }

    root.VaultUtil = {
        randomHex,
        bytesToB64,
        b64ToBytes,
        textToB64Url,
        b64UrlToText,
        clone
    };
})(typeof window !== 'undefined' ? window : globalThis);
