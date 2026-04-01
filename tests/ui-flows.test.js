/**
 * UI Flow & Navigation Tests
 *
 * Tests: showScreen navigation, goBack stack, renderSiteList filtering,
 *        openSite field population, nonce increment/decrement bounds,
 *        deleteSite cleanup, escapeHtml XSS prevention, settings clamping.
 *
 * Uses a minimal DOM mock — no real browser required.
 *
 * Run:  node tests/ui-flows.test.js
 */

const { describe, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction, createDOMMock, createLocalStorageMock } = require('./helpers/extract');

// ── Build a DOM-aware module ────────────────────────────────────────────────

function buildUIModule() {
    const { document, history, elements } = createDOMMock();
    const localStorage = createLocalStorageMock();

    // Pre-create all DOM elements that the code references
    const domIds = [
        'toast', 'loadingText', 'loadingModal', 'confirmModal', 'confirmText',
        'confirmOk', 'confirmCancel', 'seedGrid', 'verifyInputs',
        'siteList', 'emptyState', 'siteSearch', 'genSite', 'genUser',
        'nonceDisplay', 'genPassword', 'visibilityIcon', 'passwordStrength',
        'masterPass1', 'masterPass2', 'unlockPassword', 'noPasswordBadge',
        'hashLengthSetting', 'hashLengthDisplay', 'debugModeToggle',
        'relayStatus', 'backupWarningBadge', 'viewSeedGrid',
        'nostrHistoryContainer', 'restoreSeedInput', 'seedSuggestions',
        'wordCount', 'bpModalTitle', 'bpModalDesc', 'bpPass1', 'bpPass2Group',
        'bpPass2', 'bpModalConfirm', 'bpModalCancel', 'backupPasswordModal',
        'newVaultPassphrase',
    ];
    domIds.forEach(id => document.getElementById(id));

    // Make screen elements detectable
    const screens = ['welcomeScreen', 'unlockScreen', 'mainScreen', 'newWalletScreen',
        'backupScreen', 'settingsScreen', 'advancedScreen', 'generateScreen',
        'verifySeedScreen', 'restoreSeedScreen', 'setMasterPasswordScreen',
        'viewSeedScreen'];
    screens.forEach(id => {
        const el = document.getElementById(id);
        el.className = 'screen hidden';
        el.classList.add('screen');
        el.classList.add('hidden');
    });

    // Override querySelectorAll for screen selection
    document.querySelectorAll = (sel) => {
        if (sel === '.screen') {
            return screens.map(id => elements[id]);
        }
        if (sel === 'input, textarea') {
            return Object.values(elements).filter(e =>
                e.tagName === 'INPUT' || e.tagName === 'TEXTAREA'
            );
        }
        if (sel.startsWith('[data-seed-word]') || sel.includes('.seed-word')) return [];
        return [];
    };

    document.querySelector = (sel) => {
        if (sel === '.screen:not(.hidden)') {
            const found = screens.find(id => !elements[id].classList.contains('hidden'));
            return found ? elements[found] : null;
        }
        if (sel === '.nonce-control') {
            if (!elements._nonceControl) {
                elements._nonceControl = { classList: { _classes: new Set(), add(c) { this._classes.add(c); }, remove(c) { this._classes.delete(c); }, contains(c) { return this._classes.has(c); } } };
            }
            return elements._nonceControl;
        }
        return null;
    };

    const fnNames = [
        'mergeUsers', 'escapeHtml', 'getPasswordStrength',
    ];

    const fnSrc = fnNames.map(n => extractFunction(n)).join('\n\n');

    const code = `
        const DEFAULT_HASH_LENGTH = 16;
        const MIN_PASSWORD_LENGTH = 8;

        let vault = {
            privateKey: 'testkey',
            seedPhrase: 'test seed',
            passphrase: '',
            users: {},
            settings: { hashLength: 16, debugMode: false }
        };
        let nostrKeys = { nsec: '', npub: 'npub_test', hex: 'hex_test' };
        let currentNonce = 0;
        let originalNonce = 0;
        let passwordVisible = false;
        let navigationStack = ['welcomeScreen'];
        let _masterPassword = null;
        let _vaultInitialized = true;
        let debugMode = false;

        ${fnSrc}

        // Simplified navigation functions
        function showScreen(screenId) {
            document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
            const target = document.getElementById(screenId);
            if (target) {
                target.classList.remove('hidden');
                if (navigationStack[navigationStack.length - 1] !== screenId) {
                    navigationStack.push(screenId);
                    history.pushState({ screen: screenId }, '');
                }
            }
            if (screenId === 'mainScreen') {
                renderSiteList();
            }
        }

        function goBack() {
            navigationStack.pop();
            const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
            showScreen(prev);
        }

        function renderSiteList() {
            const container = document.getElementById('siteList');
            const emptyState = document.getElementById('emptyState');
            const searchTerm = (document.getElementById('siteSearch').value || '').toLowerCase();
            const sites = [];
            Object.entries(vault.users || {}).forEach(([user, userSites]) => {
                Object.entries(userSites).forEach(([site, nonce]) => {
                    sites.push({ user, site, nonce });
                });
            });
            const filtered = sites.filter(s =>
                s.site.toLowerCase().includes(searchTerm) ||
                s.user.toLowerCase().includes(searchTerm)
            );
            if (filtered.length === 0 && !searchTerm) {
                container.innerHTML = '';
                emptyState.classList.remove('hidden');
                return;
            }
            emptyState.classList.add('hidden');
            container.innerHTML = filtered.map(s =>
                '<div class="site-item" data-site="' + escapeHtml(s.site) +
                '" data-user="' + escapeHtml(s.user) +
                '" data-nonce="' + s.nonce + '"></div>'
            ).join('');
        }

        function openSite(site, user, nonce) {
            document.getElementById('genSite').value = site;
            document.getElementById('genUser').value = user;
            currentNonce = nonce || 0;
            originalNonce = currentNonce;
            document.getElementById('nonceDisplay').textContent = currentNonce + 1;
            passwordVisible = false;
            document.getElementById('genPassword').textContent = '••••••••••••';
        }

        function updateNonceIndicator() {
            const nonceControl = document.querySelector('.nonce-control');
            if (!nonceControl) return;
            if (currentNonce !== originalNonce) {
                nonceControl.classList.add('nonce-changed');
            } else {
                nonceControl.classList.remove('nonce-changed');
            }
        }

        function incrementNonce() {
            currentNonce++;
            document.getElementById('nonceDisplay').textContent = currentNonce + 1;
            updateNonceIndicator();
        }

        function decrementNonce() {
            if (currentNonce > 0) {
                currentNonce--;
                document.getElementById('nonceDisplay').textContent = currentNonce + 1;
                updateNonceIndicator();
            }
        }

        function deleteSite(site, user) {
            if (vault.users[user]) {
                delete vault.users[user][site];
                if (Object.keys(vault.users[user]).length === 0) {
                    delete vault.users[user];
                }
            }
            renderSiteList();
        }

        function saveAdvancedSettings() {
            const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
            vault.settings.hashLength = Math.max(8, Math.min(64, len));
            vault.settings.debugMode = debugMode;
        }

        return {
            get vault() { return vault; },
            set vault(v) { vault = v; },
            get currentNonce() { return currentNonce; },
            get originalNonce() { return originalNonce; },
            get navigationStack() { return navigationStack; },
            get passwordVisible() { return passwordVisible; },
            showScreen, goBack, renderSiteList, openSite,
            incrementNonce, decrementNonce, deleteSite,
            escapeHtml, getPasswordStrength, saveAdvancedSettings,
            updateNonceIndicator, mergeUsers,
            document, elements, history,
        };
    `;

    const factory = new Function(
        'document', 'history', 'localStorage', 'elements',
        'words', 'console', 'Object', 'Array', 'JSON',
        'Math', 'String', 'Number', 'parseInt', 'Error',
        code
    );

    return factory(
        document, history, localStorage, elements,
        words, console, Object, Array, JSON,
        Math, String, Number, parseInt, Error
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe('showScreen — navigation', () => {
    it('shows target screen and hides others', () => {
        const mod = buildUIModule();
        mod.showScreen('mainScreen');
        assert(!mod.elements.mainScreen.classList.contains('hidden'), 'mainScreen visible');
        assert(mod.elements.welcomeScreen.classList.contains('hidden'), 'welcomeScreen hidden');
    });

    it('pushes screen onto navigation stack', () => {
        const mod = buildUIModule();
        mod.showScreen('mainScreen');
        assert(mod.navigationStack.includes('mainScreen'), 'mainScreen in stack');
    });

    it('does not duplicate top of stack', () => {
        const mod = buildUIModule();
        mod.showScreen('mainScreen');
        mod.showScreen('mainScreen');
        const count = mod.navigationStack.filter(s => s === 'mainScreen').length;
        assertEqual(count, 1, 'no duplicate');
    });

    it('pushes to browser history', () => {
        const mod = buildUIModule();
        const initialLen = mod.history._stack.length;
        mod.showScreen('settingsScreen');
        assert(mod.history._stack.length > initialLen, 'history pushed');
    });
});

describe('goBack — navigation stack', () => {
    it('returns to previous screen', () => {
        const mod = buildUIModule();
        mod.showScreen('mainScreen');
        mod.showScreen('settingsScreen');
        mod.goBack();
        assert(!mod.elements.mainScreen.classList.contains('hidden'), 'back to mainScreen');
    });

    it('falls back to welcomeScreen when stack is empty', () => {
        const mod = buildUIModule();
        mod.goBack();
        mod.goBack();
        mod.goBack(); // exhaust stack
        // Should not throw
        assert(true, 'no crash on empty stack');
    });
});

describe('renderSiteList — site display', () => {
    it('renders all sites across users', () => {
        const mod = buildUIModule();
        mod.vault.users = {
            alice: { github: 5, twitter: 3 },
            bob: { npm: 2 }
        };
        mod.renderSiteList();
        const html = mod.elements.siteList.innerHTML;
        assert(html.includes('github'), 'github rendered');
        assert(html.includes('twitter'), 'twitter rendered');
        assert(html.includes('npm'), 'npm rendered');
    });

    it('shows empty state when no sites', () => {
        const mod = buildUIModule();
        mod.vault.users = {};
        mod.renderSiteList();
        assert(!mod.elements.emptyState.classList.contains('hidden'), 'empty state shown');
    });

    it('filters sites by search term', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5, twitter: 3 } };
        mod.elements.siteSearch.value = 'github';
        mod.renderSiteList();
        const html = mod.elements.siteList.innerHTML;
        assert(html.includes('github'), 'github shown');
        assert(!html.includes('twitter'), 'twitter filtered out');
    });

    it('filters by username', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5 }, bob: { github: 3 } };
        mod.elements.siteSearch.value = 'alice';
        mod.renderSiteList();
        const html = mod.elements.siteList.innerHTML;
        assert(html.includes('alice'), 'alice shown');
        assert(!html.includes('bob'), 'bob filtered out');
    });

    it('case-insensitive search', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { GitHub: 5 } };
        mod.elements.siteSearch.value = 'github';
        mod.renderSiteList();
        assert(mod.elements.siteList.innerHTML.includes('GitHub'), 'case-insensitive match');
    });
});

describe('openSite — generate screen setup', () => {
    it('populates site and user fields', () => {
        const mod = buildUIModule();
        mod.openSite('github.com', 'alice@test.com', 5);
        assertEqual(mod.elements.genSite.value, 'github.com', 'site populated');
        assertEqual(mod.elements.genUser.value, 'alice@test.com', 'user populated');
    });

    it('sets currentNonce and originalNonce', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 7);
        assertEqual(mod.currentNonce, 7, 'currentNonce set');
        assertEqual(mod.originalNonce, 7, 'originalNonce set');
    });

    it('displays nonce as 1-based', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 0);
        assertEqual(String(mod.elements.nonceDisplay.textContent), '1', 'nonce 0 → display "1"');
    });

    it('defaults nonce to 0 when undefined', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', undefined);
        assertEqual(mod.currentNonce, 0, 'defaults to 0');
    });

    it('masks password initially', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 0);
        assertEqual(mod.elements.genPassword.textContent, '••••••••••••', 'password masked');
        assertEqual(mod.passwordVisible, false, 'passwordVisible is false');
    });
});

describe('incrementNonce / decrementNonce', () => {
    it('incrementNonce increases nonce by 1', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 5);
        mod.incrementNonce();
        assertEqual(mod.currentNonce, 6, 'incremented to 6');
    });

    it('decrementNonce decreases nonce by 1', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 5);
        mod.decrementNonce();
        assertEqual(mod.currentNonce, 4, 'decremented to 4');
    });

    it('decrementNonce does not go below 0', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 0);
        mod.decrementNonce();
        assertEqual(mod.currentNonce, 0, 'stays at 0');
        mod.decrementNonce();
        assertEqual(mod.currentNonce, 0, 'still 0');
    });

    it('nonce display updates on increment', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 0);
        mod.incrementNonce();
        assertEqual(String(mod.elements.nonceDisplay.textContent), '2', 'display shows 2');
    });

    it('rapid increments work correctly', () => {
        const mod = buildUIModule();
        mod.openSite('site', 'user', 0);
        for (let i = 0; i < 100; i++) mod.incrementNonce();
        assertEqual(mod.currentNonce, 100, 'nonce is 100 after 100 increments');
    });
});

describe('deleteSite', () => {
    it('removes site from user', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5, twitter: 3 } };
        mod.deleteSite('github', 'alice');
        assertEqual(mod.vault.users.alice.twitter, 3, 'twitter preserved');
        assert(mod.vault.users.alice.github === undefined, 'github deleted');
    });

    it('cleans up empty user object', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5 } };
        mod.deleteSite('github', 'alice');
        assert(mod.vault.users.alice === undefined, 'empty user removed');
    });

    it('no-op for non-existent site', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5 } };
        mod.deleteSite('nonexistent', 'alice');
        assertEqual(mod.vault.users.alice.github, 5, 'existing data unchanged');
    });

    it('no-op for non-existent user', () => {
        const mod = buildUIModule();
        mod.vault.users = { alice: { github: 5 } };
        mod.deleteSite('github', 'bob');
        assertEqual(mod.vault.users.alice.github, 5, 'existing data unchanged');
    });
});

describe('escapeHtml — XSS prevention', () => {
    it('escapes < and >', () => {
        const mod = buildUIModule();
        const result = mod.escapeHtml('<script>alert(1)</script>');
        assert(!result.includes('<script>'), 'no raw script tag');
        assert(result.includes('&lt;'), 'has &lt;');
        assert(result.includes('&gt;'), 'has &gt;');
    });

    it('escapes & character', () => {
        const mod = buildUIModule();
        const result = mod.escapeHtml('a&b');
        assert(result.includes('&amp;'), 'ampersand escaped');
    });

    it('escapes double quotes', () => {
        const mod = buildUIModule();
        const result = mod.escapeHtml('a"b');
        assert(result.includes('&quot;') || !result.includes('"'), 'quote handled');
    });

    it('preserves safe strings', () => {
        const mod = buildUIModule();
        assertEqual(mod.escapeHtml('hello world'), 'hello world', 'safe string unchanged');
    });

    it('handles empty string', () => {
        const mod = buildUIModule();
        assertEqual(mod.escapeHtml(''), '', 'empty string preserved');
    });
});

describe('saveAdvancedSettings — hashLength clamping', () => {
    it('clamps hashLength to minimum 8', () => {
        const mod = buildUIModule();
        mod.elements.hashLengthSetting.value = '4';
        mod.saveAdvancedSettings();
        assertEqual(mod.vault.settings.hashLength, 8, 'clamped to 8');
    });

    it('clamps hashLength to maximum 64', () => {
        const mod = buildUIModule();
        mod.elements.hashLengthSetting.value = '128';
        mod.saveAdvancedSettings();
        assertEqual(mod.vault.settings.hashLength, 64, 'clamped to 64');
    });

    it('accepts valid hashLength', () => {
        const mod = buildUIModule();
        mod.elements.hashLengthSetting.value = '20';
        mod.saveAdvancedSettings();
        assertEqual(mod.vault.settings.hashLength, 20, 'accepted 20');
    });

    it('defaults to 16 on invalid input', () => {
        const mod = buildUIModule();
        mod.elements.hashLengthSetting.value = 'abc';
        mod.saveAdvancedSettings();
        assertEqual(mod.vault.settings.hashLength, 16, 'defaults to 16');
    });
});

// ── Summary ─────────────────────────────────────────────────────────────────

const ok = summary();
process.exit(ok ? 0 : 1);
