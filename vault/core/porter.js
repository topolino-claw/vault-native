/**
 * Import/export bridge to other password managers — pure CSV, DOM-free.
 *
 * A DELIBERATE MISMATCH TO KEEP IN MIND: this app does not *store* passwords,
 * it *derives* them from the seed. So an import cannot bring passwords across —
 * they would not match what this app generates. What import brings is the list
 * of accounts (site + username) plus, when present, the old password/notes,
 * which the caller preserves as a note record so nothing is lost while the user
 * rotates each site onto a freshly derived password. Export is the reverse: the
 * account list with the passwords THIS app derives (a plaintext-secret file, so
 * the UI must warn before writing it).
 *
 * The CSV parser is RFC 4180 (quotes, escaped quotes, CRLF). Column detection
 * covers the common Bitwarden / 1Password / Chrome / KeePass export headers.
 */
(function (root) {
    'use strict';

    /** RFC 4180 CSV → array of string rows. */
    function parseCsv(text) {
        const s = String(text);
        const rows = [];
        let row = [];
        let field = '';
        let inQuotes = false;
        for (let i = 0; i < s.length; i++) {
            const c = s[i];
            if (inQuotes) {
                if (c === '"') {
                    if (s[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
                } else {
                    field += c;
                }
                continue;
            }
            if (c === '"') inQuotes = true;
            else if (c === ',') { row.push(field); field = ''; }
            else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
            else if (c !== '\r') field += c;
        }
        if (field.length || row.length) { row.push(field); rows.push(row); }
        // Drop blank lines.
        return rows.filter((r) => !(r.length === 1 && r[0] === ''));
    }

    // Header aliases used by the mainstream exporters.
    const COLUMNS = {
        site: ['url', 'uri', 'login_uri', 'website', 'site', 'domain', 'name', 'title'],
        user: ['username', 'user', 'login_username', 'login', 'email', 'account', 'account_username'],
        password: ['password', 'login_password', 'pass', 'pwd'],
        note: ['notes', 'note', 'extra', 'comments']
    };

    function headerIndices(header) {
        const norm = header.map((h) => String(h).trim().toLowerCase());
        const idx = {};
        for (const key of Object.keys(COLUMNS)) {
            idx[key] = COLUMNS[key].map((a) => norm.indexOf(a)).filter((i) => i !== -1);
        }
        return idx;
    }

    /** A URL → bare host ("https://www.github.com/login" → "github.com"). */
    function siteFromValue(value) {
        const s = String(value || '').trim();
        if (!s) return '';
        return s.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./i, '');
    }

    /** First non-empty cell among the given column indices, in priority order. */
    function firstNonEmpty(row, indices) {
        for (const i of indices) {
            if (row[i] != null && String(row[i]).trim() !== '') return String(row[i]);
        }
        return '';
    }

    /**
     * Parse an exported CSV into normalized entries. Prefers a URL column for
     * the site (so "https://www.github.com/login" → "github.com"), falling back
     * to the display name; picks the first non-empty candidate either way.
     * @returns {Array<{site:string, user:string, password:string, note:string}>}
     *   empty if the file has no recognizable columns.
     */
    function importCsv(text) {
        const rows = parseCsv(text);
        if (rows.length < 2) return [];
        const idx = headerIndices(rows[0]);
        if (!idx.site.length && !idx.user.length) return [];
        const out = [];
        for (let r = 1; r < rows.length; r++) {
            const row = rows[r];
            const site = siteFromValue(firstNonEmpty(row, idx.site));
            const user = firstNonEmpty(row, idx.user).trim();
            if (!site && !user) continue;
            out.push({
                site: site || 'unknown',
                user: user,
                password: firstNonEmpty(row, idx.password),
                note: firstNonEmpty(row, idx.note).trim()
            });
        }
        return out;
    }

    /**
     * Encode one CSV cell, defending against spreadsheet formula injection.
     *
     * A cell whose raw value starts with `= + - @` (or a tab/CR) is interpreted
     * as a FORMULA by Excel, Sheets and Calc when the file is opened. Site
     * names and usernames are attacker-influenced (they arrive via CSV import),
     * so a crafted `=HYPERLINK(...)` or `+cmd|...` cell would otherwise execute
     * on open. Prefixing a single quote neutralises it in every mainstream
     * spreadsheet while staying harmless to parsers. Quoting alone does NOT
     * help: CSV quotes are framing, stripped before Excel evaluates the cell,
     * so a quoted `"=1+1"` still runs as a formula.
     */
    function csvField(v) {
        const s = v == null ? '' : String(v);
        const neutralised = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
        return /[",\r\n]/.test(neutralised)
            ? '"' + neutralised.replace(/"/g, '""') + '"'
            : neutralised;
    }

    /**
     * Serialize credential rows to a generic CSV.
     * @param {Array<{name?:string, url?:string, username?:string, password?:string}>} rows
     */
    function exportCsv(rows) {
        const lines = ['name,url,username,password'];
        for (const r of rows || []) {
            lines.push([r.name, r.url, r.username, r.password].map(csvField).join(','));
        }
        return lines.join('\r\n') + '\r\n';
    }

    root.VaultPorter = { parseCsv, importCsv, exportCsv, siteFromValue };
})(typeof window !== 'undefined' ? window : globalThis);
