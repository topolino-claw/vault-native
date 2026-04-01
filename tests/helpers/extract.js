/**
 * Extract functions from vault/app.js for isolated testing.
 *
 * Strategy: read the source, build an execution context with minimal globals,
 * eval the source (or individual functions) so we test the real production code.
 */

const fs = require('fs');
const path = require('path');

const APP_PATH = path.join(__dirname, '..', '..', 'vault', 'app.js');
const WORDLIST_PATH = path.join(__dirname, '..', '..', 'vault', 'bip39WordList.js');

const appSrc = fs.readFileSync(APP_PATH, 'utf-8');
const wordlistSrc = fs.readFileSync(WORDLIST_PATH, 'utf-8');

// ── Load BIP39 word list ────────────────────────────────────────────────────
let words;
{
    const fn = new Function(`${wordlistSrc}; return words;`);
    words = fn();
}

// ── Extract a named top-level function by regex ─────────────────────────────
function extractFunction(name) {
    // Matches: function name(...) { ... } (handles async too)
    const re = new RegExp(`^(?:async\\s+)?function\\s+${name}\\s*\\([^)]*\\)\\s*\\{`, 'm');
    const match = re.exec(appSrc);
    if (!match) throw new Error(`Cannot extract function "${name}" from app.js`);

    // Walk braces to find the matching close
    let depth = 0;
    let start = match.index;
    let i = appSrc.indexOf('{', start);
    for (; i < appSrc.length; i++) {
        if (appSrc[i] === '{') depth++;
        else if (appSrc[i] === '}') { depth--; if (depth === 0) break; }
    }
    return appSrc.slice(start, i + 1);
}

// ── Extract a const/let/var assignment (single line or block) ───────────────
function extractConst(name) {
    const re = new RegExp(`^(?:const|let|var)\\s+${name}\\s*=`, 'm');
    const match = re.exec(appSrc);
    if (!match) throw new Error(`Cannot extract const "${name}" from app.js`);

    let i = match.index;
    // Find the end of the statement (semicolon at depth 0)
    let depth = 0;
    for (; i < appSrc.length; i++) {
        if (appSrc[i] === '{' || appSrc[i] === '[' || appSrc[i] === '(') depth++;
        else if (appSrc[i] === '}' || appSrc[i] === ']' || appSrc[i] === ')') depth--;
        else if (appSrc[i] === ';' && depth <= 0) break;
    }
    return appSrc.slice(match.index, i + 1);
}

// ── Build an execution context for pure functions ───────────────────────────
// These functions don't need DOM or Tauri — just crypto and the word list.

function buildPureContext(extraGlobals = {}) {
    const ctx = {
        words,
        crypto: globalThis.crypto,
        BigInt: globalThis.BigInt,
        TextEncoder: globalThis.TextEncoder,
        TextDecoder: globalThis.TextDecoder,
        Uint8Array: globalThis.Uint8Array,
        Array: globalThis.Array,
        JSON: globalThis.JSON,
        Math: globalThis.Math,
        String: globalThis.String,
        Number: globalThis.Number,
        parseInt: globalThis.parseInt,
        atob: globalThis.atob,
        btoa: globalThis.btoa,
        console: globalThis.console,
        setTimeout: globalThis.setTimeout,
        clearTimeout: globalThis.clearTimeout,
        Error: globalThis.Error,
        Map: globalThis.Map,
        Object: globalThis.Object,
        Promise: globalThis.Promise,
        ...extraGlobals,
    };
    return ctx;
}

/**
 * Create a sandboxed module with extracted functions.
 * @param {string[]} functionNames - Function names to extract.
 * @param {string[]} constNames - Constant names to extract.
 * @param {object} extraGlobals - Additional globals to inject.
 * @returns {object} - Object with all named functions available.
 */
function createModule(functionNames, constNames = [], extraGlobals = {}) {
    const ctx = buildPureContext(extraGlobals);

    const parts = [];

    // Add constants
    for (const name of constNames) {
        parts.push(extractConst(name));
    }

    // Add functions
    for (const name of functionNames) {
        parts.push(extractFunction(name));
    }

    // Return object with all exports
    const exports = [...functionNames, ...constNames.map(n => n)].join(', ');
    const returnObj = functionNames.map(n => `${n}`).join(', ');

    const code = parts.join('\n\n') + `\n\nreturn { ${returnObj} };`;

    // Build argument list from context
    const argNames = Object.keys(ctx);
    const argValues = Object.values(ctx);

    try {
        const factory = new Function(...argNames, code);
        return factory(...argValues);
    } catch (e) {
        throw new Error(`Failed to create module: ${e.message}\n\nCode snippet:\n${code.slice(0, 500)}`);
    }
}

/**
 * Build a vault-state context for functions that need vault, nostrKeys, etc.
 */
function createVaultContext(overrides = {}) {
    const vault = {
        privateKey: '',
        seedPhrase: '',
        passphrase: '',
        users: {},
        settings: { hashLength: 16, debugMode: false },
        ...overrides.vault,
    };
    const nostrKeys = { nsec: '', npub: '', hex: '', ...overrides.nostrKeys };
    const _masterPassword = overrides._masterPassword || null;
    const _vaultInitialized = overrides._vaultInitialized || false;
    const invoke = overrides.invoke || null;
    const debugMode = overrides.debugMode || false;

    return { vault, nostrKeys, _masterPassword, _vaultInitialized, invoke, debugMode };
}

/**
 * Create a minimal localStorage mock.
 */
function createLocalStorageMock() {
    const store = {};
    return {
        getItem(key) { return store[key] !== undefined ? store[key] : null; },
        setItem(key, value) { store[key] = String(value); },
        removeItem(key) { delete store[key]; },
        clear() { Object.keys(store).forEach(k => delete store[k]); },
        get _store() { return store; },
    };
}

/**
 * Create a minimal DOM mock for UI-dependent tests.
 */
function createDOMMock() {
    const elements = {};
    const allElements = [];

    function createElement(tag) {
        let _textContent = '';
        let _innerHTML = '';
        const el = {
            tagName: tag.toUpperCase(),
            className: '',
            classList: {
                _classes: new Set(),
                add(c) { this._classes.add(c); },
                remove(c) { this._classes.delete(c); },
                contains(c) { return this._classes.has(c); },
                toggle(c, force) {
                    if (force === undefined) {
                        if (this._classes.has(c)) this._classes.delete(c);
                        else this._classes.add(c);
                    } else if (force) {
                        this._classes.add(c);
                    } else {
                        this._classes.delete(c);
                    }
                },
            },
            dataset: {},
            // Simulate textContent → innerHTML linkage for escapeHtml
            get textContent() { return _textContent; },
            set textContent(v) {
                _textContent = String(v);
                // When textContent is set, innerHTML becomes the HTML-escaped version
                _innerHTML = _textContent
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;');
            },
            get innerHTML() { return _innerHTML; },
            set innerHTML(v) { _innerHTML = String(v); _textContent = v.replace(/<[^>]*>/g, ''); },
            value: '',
            style: {},
            title: '',
            children: [],
            _listeners: {},
            addEventListener(evt, fn) {
                if (!this._listeners[evt]) this._listeners[evt] = [];
                this._listeners[evt].push(fn);
            },
            removeEventListener(evt, fn) {
                if (this._listeners[evt]) {
                    this._listeners[evt] = this._listeners[evt].filter(f => f !== fn);
                }
            },
            dispatchEvent(evt) {
                (this._listeners[evt.type] || []).forEach(fn => fn(evt));
            },
            querySelector(sel) { return null; },
            querySelectorAll(sel) { return []; },
            appendChild(child) { this.children.push(child); return child; },
            removeChild(child) { this.children = this.children.filter(c => c !== child); return child; },
            closest(sel) { return null; },
            focus() {},
            click() {},
        };
        allElements.push(el);
        return el;
    }

    function getElementById(id) {
        if (!elements[id]) {
            elements[id] = createElement('div');
            elements[id].id = id;
        }
        return elements[id];
    }

    const document = {
        getElementById,
        createElement,
        querySelectorAll(sel) {
            if (sel === '.screen') {
                return Object.values(elements).filter(e => e.className && e.className.includes('screen'));
            }
            if (sel === 'input, textarea') {
                return Object.values(elements).filter(e =>
                    e.tagName === 'INPUT' || e.tagName === 'TEXTAREA'
                );
            }
            return [];
        },
        querySelector(sel) { return null; },
        addEventListener(evt, fn, opts) {},
        hidden: false,
        body: { appendChild() {}, removeChild() {}, innerHTML: '' },
    };

    const history = {
        _stack: [],
        pushState(state, title, url) { this._stack.push(state); },
        replaceState(state, title) { this._stack = [state]; },
    };

    return { document, history, elements, createElement };
}

module.exports = {
    appSrc,
    words,
    extractFunction,
    extractConst,
    buildPureContext,
    createModule,
    createVaultContext,
    createLocalStorageMock,
    createDOMMock,
};
