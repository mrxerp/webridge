(function() {
    'use strict';

    const API_BASE = '/api/v1';
    const MAX_RETRIES = 3;
    const RETRY_DELAYS = [1000, 2000, 4000];
    // Overwritten with the server's authoritative list at login (/me → all_perms).
    let ALL_PERMS = ['download', 'audit', 'users', 'groups'];
    const ALL_ACTIONS = [
        'login_success', 'login_failed', 'login_locked', 'login_unapproved', 'logout',
        'download_success', 'download_error', 'download_cancel',
        'user_created', 'user_updated', 'user_deleted',
        'group_created', 'group_updated', 'group_deleted',
        'ldap_updated', 'imap_updated', 'imap_tested'
    ];

    function trackEvent(action, detail) {
        fetch(API_BASE + '/audit/log', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action, detail }),
            credentials: 'same-origin'
        }).catch(() => {});
    }

    const elements = {
        container: document.getElementById('container'),
        loginSection: document.getElementById('loginSection'),
        loginForm: document.getElementById('loginForm'),
        loginUsername: document.getElementById('loginUsername'),
        loginPassword: document.getElementById('loginPassword'),
        loginBtn: document.getElementById('loginBtn'),
        loginError: document.getElementById('loginError'),
        appView: document.getElementById('appView'),
        userMenuBtn: document.getElementById('userMenuBtn'),
        userMenu: document.getElementById('userMenu'),
        userName: document.getElementById('userName'),
        downloadView: document.getElementById('downloadView'),
        logsView: document.getElementById('logsView'),
        settingsView: document.getElementById('settingsView'),
        auditCount: document.getElementById('auditCount'),
        auditTableWrap: document.getElementById('auditTableWrap'),
        metricActive: document.getElementById('metricActive'),
        metricCompleted: document.getElementById('metricCompleted'),
        metricFailed: document.getElementById('metricFailed'),
        metricBytes: document.getElementById('metricBytes'),
        metricLogins: document.getElementById('metricLogins'),
        metricLoginFails: document.getElementById('metricLoginFails'),
        auditBody: document.getElementById('auditBody'),
        logoutBtn: document.getElementById('logoutBtn'),
        auditFilterForm: document.getElementById('auditFilterForm'),
        exportCsvBtn: document.getElementById('exportCsvBtn'),
        filterAction: document.getElementById('filterAction'),
        filterUser: document.getElementById('filterUser'),
        filterFrom: document.getElementById('filterFrom'),
        supportedHint: document.getElementById('supportedHint'),
        filterTo: document.getElementById('filterTo'),
        clearFiltersBtn: document.getElementById('clearFiltersBtn'),
        newGroupPerms: document.getElementById('newGroupPerms'),
        addUserForm: document.getElementById('addUserForm'),
        newUsername: document.getElementById('newUsername'),
        newPassword: document.getElementById('newPassword'),
        newRole: document.getElementById('newRole'),
        usersError: document.getElementById('usersError'),
        usersBody: document.getElementById('usersBody'),
        ldapForm: document.getElementById('ldapForm'),
        ldapEnabled: document.getElementById('ldapEnabled'),
        ldapHost: document.getElementById('ldapHost'),
        ldapPort: document.getElementById('ldapPort'),
        ldapBindDN: document.getElementById('ldapBindDN'),
        ldapBindPassword: document.getElementById('ldapBindPassword'),
        ldapBaseDN: document.getElementById('ldapBaseDN'),
        ldapFilter: document.getElementById('ldapFilter'),
        ldapGroups: document.getElementById('ldapGroups'),
        ldapStartTLS: document.getElementById('ldapStartTLS'),
        ldapInsecure: document.getElementById('ldapInsecure'),
        ldapError: document.getElementById('ldapError'),
        imapForm: document.getElementById('imapForm'),
        imapEnabled: document.getElementById('imapEnabled'),
        imapHost: document.getElementById('imapHost'),
        imapPort: document.getElementById('imapPort'),
        imapDomains: document.getElementById('imapDomains'),
        imapGroups: document.getElementById('imapGroups'),
        imapStartTLS: document.getElementById('imapStartTLS'),
        imapInsecure: document.getElementById('imapInsecure'),
        imapAutoProvision: document.getElementById('imapAutoProvision'),
        imapError: document.getElementById('imapError'),
        imapTestBtn: document.getElementById('imapTestBtn'),
        addGroupForm: document.getElementById('addGroupForm'),
        newGroupName: document.getElementById('newGroupName'),
        groupsError: document.getElementById('groupsError'),
        groupsBody: document.getElementById('groupsBody'),
        urlInput: document.getElementById('urlInput'),
        checkBtn: document.getElementById('checkBtn'),
        urlError: document.getElementById('urlError'),
        inputSection: document.getElementById('inputSection'),
        passwordSection: document.getElementById('passwordSection'),
        passwordInput: document.getElementById('passwordInput'),
        passwordBtn: document.getElementById('passwordBtn'),
        passwordError: document.getElementById('passwordError'),
        passwordMessage: document.getElementById('passwordMessage'),
        infoSection: document.getElementById('infoSection'),
        fileName: document.getElementById('fileName'),
        fileSize: document.getElementById('fileSize'),
        fileCount: document.getElementById('fileCount'),
        fileCountValue: document.getElementById('fileCountValue'),
        providerBadge: document.getElementById('providerBadge'),
        downloadBtn: document.getElementById('downloadBtn'),
        retryBtn: document.getElementById('retryBtn'),
        cancelBtn: document.getElementById('cancelBtn'),
        progressSection: document.getElementById('progressSection'),
        progressFill: document.getElementById('progressFill'),
        progressPercent: document.getElementById('progressPercent'),
        progressSpeed: document.getElementById('progressSpeed'),
        progressEta: document.getElementById('progressEta'),
        progressStatus: document.getElementById('progressStatus'),
        downloadError: document.getElementById('downloadError'),
        recentSection: document.getElementById('recentSection'),
        recentBody: document.getElementById('recentBody'),
        bruteForceConfig: document.getElementById('bruteForceConfig'),
        bruteForceBody: document.getElementById('bruteForceBody')
    };

    let currentUser = null;
    let currentFileInfo = null;
    let currentUrl = null;
    let currentPassword = null;
    let abortController = null;

    function init() {
        elements.loginForm.addEventListener('submit', onLoginSubmit);
        elements.userMenuBtn.addEventListener('click', e => {
            e.stopPropagation();
            elements.userMenu.hidden = !elements.userMenu.hidden;
        });
        document.addEventListener('click', e => {
            if (!elements.userMenu.hidden && !e.target.closest('.dropdown')) {
                elements.userMenu.hidden = true;
            }
        });
        elements.userMenu.addEventListener('click', e => {
            const item = e.target.closest('.menu-item');
            if (!item) return;
            elements.userMenu.hidden = true;
            if (item.dataset.view) switchTab(item.dataset.view);
        });
        elements.logoutBtn.addEventListener('click', onLogout);
        elements.auditFilterForm.addEventListener('submit', e => {
            e.preventDefault();
            loadAuditData();
        });
        elements.clearFiltersBtn.addEventListener('click', () => {
            elements.auditFilterForm.reset();
            loadAuditData();
        });
        elements.addUserForm.addEventListener('submit', onAddUser);
        elements.addGroupForm.addEventListener('submit', onAddGroup);
        elements.ldapForm.addEventListener('submit', onSaveLDAP);
        elements.imapForm.addEventListener('submit', onSaveIMAP);
        elements.imapTestBtn.addEventListener('click', onTestIMAP);
        elements.auditTableWrap.addEventListener('scroll', () => {
            const el = elements.auditTableWrap;
            if (el.scrollTop + el.clientHeight >= el.scrollHeight - 60) loadMoreAudit();
        });

        for (const action of ALL_ACTIONS) {
            const opt = document.createElement('option');
            opt.value = action;
            opt.textContent = action.replaceAll('_', ' ');
            elements.filterAction.appendChild(opt);
        }
        elements.urlInput.addEventListener('input', onUrlInput);
        elements.urlInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') onCheckClick();
        });
        elements.checkBtn.addEventListener('click', onCheckClick);
        elements.passwordInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') onPasswordSubmit();
        });
        elements.passwordBtn.addEventListener('click', onPasswordSubmit);
        elements.downloadBtn.addEventListener('click', onDownloadClick);
        elements.retryBtn.addEventListener('click', onRetryClick);
        elements.cancelBtn.addEventListener('click', () => {
            if (abortController) {
                trackEvent('download_cancel', 'user_cancelled');
                abortController.abort();
                elements.cancelBtn.style.display = 'none';
                elements.progressStatus.textContent = 'Download cancelled.';
            }
        });

        setInterval(() => {
            if (!currentUser) return;
            // Audit list is paged/scroll-positioned, so it is not auto-refreshed.
            if (!elements.logsView.hidden) loadMetrics();
            if (!elements.settingsView.hidden) loadBruteForce();
        }, 5000);

        checkAuth();
    }

    async function checkAuth() {
        try {
            const res = await fetch(`${API_BASE}/me`);
            if (!res.ok) throw new Error();
            const me = await res.json();
            showApp(me);
        } catch {
            showLogin();
        }
    }

    function showLogin() {
        currentUser = null;
        elements.appView.hidden = true;
        elements.loginSection.hidden = false;
        elements.loginPassword.value = '';
        hideError(elements.loginError);
        elements.loginUsername.focus();
    }

    function can(perm) {
        if (!currentUser) return false;
        const perms = currentUser.permissions || [];
        return perms.includes(perm);
    }

    function showApp(user) {
        currentUser = user;
        if (Array.isArray(user.all_perms) && user.all_perms.length) ALL_PERMS = user.all_perms;
        elements.loginSection.hidden = true;
        elements.appView.hidden = false;
        elements.userName.textContent = user.username;
        elements.userMenu.querySelectorAll('.menu-item[data-perm]').forEach(el => {
            el.hidden = !can(el.dataset.perm);
        });
        elements.userMenu.hidden = true;
        switchTab('download');
        elements.urlInput.focus();
        loadProviders();
    }

    async function loadProviders() {
        try {
            const res = await fetch(`${API_BASE}/providers`);
            if (!res.ok) return;
            const { providers } = await res.json();
            if (providers && providers.length) {
                elements.supportedHint.textContent = 'Supported: ' + providers.join(', ');
            }
        } catch {}
    }

    async function onLoginSubmit(e) {
        e.preventDefault();
        const username = elements.loginUsername.value.trim();
        const password = elements.loginPassword.value;
        if (!username || !password) return;

        setLoading(elements.loginBtn, true);
        hideError(elements.loginError);

        try {
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (!res.ok) {
                showError(elements.loginError, res.status === 401 ? 'Invalid username or password.' : `Login failed (${res.status}).`);
                return;
            }
            const user = await res.json();
            showApp(user);
        } catch {
            showError(elements.loginError, 'Login failed. Please try again.');
        } finally {
            setLoading(elements.loginBtn, false);
        }
    }

    async function onLogout() {
        try {
            await fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
        } catch {}
        showLogin();
    }

    const VIEW_PERMS = { logs: 'audit', settings: 'users' };

    function switchTab(name) {
        if (VIEW_PERMS[name] && !can(VIEW_PERMS[name])) name = 'download';
        elements.downloadView.hidden = name !== 'download';
        elements.logsView.hidden = name !== 'logs';
        elements.settingsView.hidden = name !== 'settings';
        elements.container.classList.toggle('wide', name !== 'download');
        if (name === 'download') loadRecent();
        if (name === 'logs') {
            loadMetrics();
            loadAuditData();
        }
        if (name === 'settings') {
            buildPermLabels();
            loadBruteForce();
            loadUsersData();
            loadGroupsData();
        }
    }

    function buildPermLabels() {
        elements.newGroupPerms.textContent = '';
        for (const perm of ALL_PERMS) {
            const label = document.createElement('label');
            label.className = 'perm-label';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'new-perm';
            cb.value = perm;
            label.appendChild(cb);
            label.appendChild(document.createTextNode(' ' + perm));
            elements.newGroupPerms.appendChild(label);
        }
    }

    async function loadRecent() {
        try {
            const res = await fetch(`${API_BASE}/downloads/recent`);
            if (!res.ok) return;
            const { downloads } = await res.json();
            renderRecent(downloads || []);
        } catch {}
    }

    function renderRecent(downloads) {
        elements.recentBody.textContent = '';
        elements.recentSection.hidden = !downloads.length;
        for (const d of downloads) {
            const ok = d.action === 'download_success';
            const tr = document.createElement('tr');

            const tdFile = document.createElement('td');
            tdFile.className = 'recent-file';
            tdFile.textContent = d.filename || d.detail || d.url;
            tdFile.title = d.url || '';
            tr.appendChild(tdFile);

            const tdStatus = document.createElement('td');
            tdStatus.className = ok ? 'action-good' : 'action-bad';
            tdStatus.textContent = ok ? 'completed' : 'failed';
            tr.appendChild(tdStatus);

            const tdWhen = document.createElement('td');
            tdWhen.textContent = new Date(d.time).toLocaleString();
            tr.appendChild(tdWhen);

            const tdActions = document.createElement('td');
            if (d.url) {
                const retryBtn = document.createElement('button');
                retryBtn.className = 'btn btn-small';
                retryBtn.textContent = 'Retry';
                retryBtn.addEventListener('click', () => {
                    elements.urlInput.value = d.url;
                    onCheckClick();
                });
                tdActions.appendChild(retryBtn);
            }
            tr.appendChild(tdActions);

            elements.recentBody.appendChild(tr);
        }
    }

    async function loadUsersData() {
        try {
            const [usersRes, groupsRes] = await Promise.all([
                fetch(`${API_BASE}/admin/users`),
                fetch(`${API_BASE}/admin/groups`)
            ]);
            if (!usersRes.ok || !groupsRes.ok) return;
            const { users } = await usersRes.json();
            const { groups } = await groupsRes.json();
            renderUsers(users || [], groups || []);
        } catch {}
        loadLdapStatus();
        loadImapStatus();
    }

    async function loadImapStatus() {
        try {
            const res = await fetch(`${API_BASE}/admin/imap`);
            if (!res.ok) return;
            const s = await res.json();
            elements.imapForm.hidden = false;
            elements.imapEnabled.checked = !!s.enabled;
            elements.imapHost.value = s.host || '';
            elements.imapPort.value = s.port || '';
            elements.imapDomains.value = (s.allowed_domains || []).join(', ');
            elements.imapGroups.value = (s.default_groups || []).join(', ');
            elements.imapStartTLS.checked = !!s.starttls;
            elements.imapInsecure.checked = !!s.insecure_skip_verify;
            elements.imapAutoProvision.checked = !!s.auto_provision;
        } catch {}
    }

    function imapPayload() {
        return {
            enabled: elements.imapEnabled.checked,
            host: elements.imapHost.value.trim(),
            port: parseInt(elements.imapPort.value, 10) || 0,
            starttls: elements.imapStartTLS.checked,
            insecure_skip_verify: elements.imapInsecure.checked,
            allowed_domains: elements.imapDomains.value.split(',').map(s => s.trim()).filter(Boolean),
            default_groups: elements.imapGroups.value.split(',').map(s => s.trim()).filter(Boolean),
            auto_provision: elements.imapAutoProvision.checked
        };
    }

    async function onSaveIMAP(e) {
        e.preventDefault();
        const btn = elements.imapForm.querySelector('button[type="submit"]');
        setLoading(btn, true);
        hideError(elements.imapError);
        try {
            const res = await fetch(`${API_BASE}/admin/imap`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(imapPayload())
            });
            if (!res.ok) {
                showError(elements.imapError, await res.text().catch(() => 'Failed to save email sign-in settings.'));
                return;
            }
            await loadImapStatus();
        } finally {
            setLoading(btn, false);
        }
    }

    async function onTestIMAP() {
        hideError(elements.imapError);
        const email = prompt('Email address to test with:');
        if (!email) return;
        const password = prompt('Password for ' + email + ':');
        if (!password) return;
        setLoading(elements.imapTestBtn, true);
        try {
            // Save first so the test runs against the form's values.
            const saveRes = await fetch(`${API_BASE}/admin/imap`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(imapPayload())
            });
            if (!saveRes.ok) {
                showError(elements.imapError, await saveRes.text().catch(() => 'Failed to save settings before testing.'));
                return;
            }
            const res = await fetch(`${API_BASE}/admin/imap/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: email, password })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok || data.error) {
                showError(elements.imapError, data.error || `Test failed (${res.status}).`);
            } else if (!data.ok) {
                showError(elements.imapError, 'Server reachable, but the login was rejected.');
            } else {
                elements.imapError.hidden = true;
                alert('IMAP connection OK — login accepted.');
            }
        } catch {
            showError(elements.imapError, 'Test failed. Please try again.');
        } finally {
            setLoading(elements.imapTestBtn, false);
        }
    }

    async function loadLdapStatus() {
        try {
            const res = await fetch(`${API_BASE}/admin/ldap`);
            if (!res.ok) return;
            const s = await res.json();
            elements.ldapForm.hidden = false;
            elements.ldapEnabled.checked = !!s.enabled;
            elements.ldapHost.value = s.host || '';
            elements.ldapPort.value = s.port || '';
            elements.ldapBindDN.value = s.bind_dn || '';
            elements.ldapBindPassword.value = '';
            elements.ldapBaseDN.value = s.base_dn || '';
            elements.ldapFilter.value = s.user_filter || '';
            elements.ldapGroups.value = (s.default_groups || []).join(', ');
            elements.ldapStartTLS.checked = !!s.starttls;
            elements.ldapInsecure.checked = !!s.insecure_skip_verify;
        } catch {}
    }

    async function onSaveLDAP(e) {
        e.preventDefault();
        const btn = elements.ldapForm.querySelector('button[type="submit"]');
        setLoading(btn, true);
        hideError(elements.ldapError);
        try {
            const res = await fetch(`${API_BASE}/admin/ldap`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enabled: elements.ldapEnabled.checked,
                    host: elements.ldapHost.value.trim(),
                    port: parseInt(elements.ldapPort.value, 10) || 0,
                    starttls: elements.ldapStartTLS.checked,
                    insecure_skip_verify: elements.ldapInsecure.checked,
                    bind_dn: elements.ldapBindDN.value.trim(),
                    bind_password: elements.ldapBindPassword.value,
                    base_dn: elements.ldapBaseDN.value.trim(),
                    user_filter: elements.ldapFilter.value.trim(),
                    default_groups: elements.ldapGroups.value.split(',').map(s => s.trim()).filter(Boolean)
                })
            });
            if (!res.ok) {
                showError(elements.ldapError, await res.text().catch(() => 'Failed to save LDAP settings.'));
                return;
            }
            elements.ldapBindPassword.value = '';
            await loadLdapStatus();
        } finally {
            setLoading(btn, false);
        }
    }

    async function loadGroupsData() {
        try {
            const res = await fetch(`${API_BASE}/admin/groups`);
            if (!res.ok) return;
            const { groups } = await res.json();
            renderGroups(groups || []);
        } catch {}
    }

    function renderUsers(users, groups) {
        elements.usersBody.textContent = '';
        if (!users.length) {
            emptyRow(elements.usersBody, 5, 'No users.');
            return;
        }
        
        // Build group name list for checkboxes
        const groupNames = (groups || []).map(g => g.name).sort();
        
        for (const u of users) {
            const tr = document.createElement('tr');
            const isExternal = u.source && u.source !== 'local';
            const userGroups = u.groups || [];

            const tdName = document.createElement('td');
            tdName.textContent = u.username;
            tr.appendChild(tdName);

            const tdSource = document.createElement('td');
            tdSource.textContent = u.source || 'local';
            if (isExternal) tdSource.className = 'source-ext';
            tr.appendChild(tdSource);

            const tdRole = document.createElement('td');
            const roleSel = document.createElement('select');
            roleSel.className = 'row-select';
            for (const role of ['user', 'admin']) {
                const opt = document.createElement('option');
                opt.value = role;
                opt.textContent = role;
                if (u.role === role) opt.selected = true;
                roleSel.appendChild(opt);
            }
            roleSel.addEventListener('change', () => updateUser(u.username, { role: roleSel.value }));
            tdRole.appendChild(roleSel);
            tr.appendChild(tdRole);

            // Groups as checkboxes
            const tdGroups = document.createElement('td');
            tdGroups.className = 'groups-cell';
            if (groupNames.length === 0) {
                tdGroups.textContent = '—';
            } else {
                for (const gName of groupNames) {
                    const label = document.createElement('label');
                    label.className = 'group-checkbox-label';
                    const cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.value = gName;
                    cb.checked = userGroups.includes(gName);
                    cb.disabled = isExternal; // LDAP/IMAP users get groups from external config
                    cb.addEventListener('change', () => {
                        const selected = Array.from(tdGroups.querySelectorAll('input:checked')).map(i => i.value);
                        updateUser(u.username, { groups: selected });
                    });
                    label.appendChild(cb);
                    label.appendChild(document.createTextNode(' ' + gName));
                    tdGroups.appendChild(label);
                }
            }
            tr.appendChild(tdGroups);

            const tdActions = document.createElement('td');
            if (!isExternal) {
                const pwBtn = document.createElement('button');
                pwBtn.className = 'btn btn-small';
                pwBtn.textContent = 'Password';
                pwBtn.addEventListener('click', () => {
                    const pw = prompt(`New password for ${u.username}`);
                    if (pw) updateUser(u.username, { password: pw });
                });
                tdActions.appendChild(pwBtn);
            }
            const delBtn = document.createElement('button');
            delBtn.className = 'btn btn-danger btn-small';
            delBtn.textContent = 'Delete';
            delBtn.addEventListener('click', () => deleteUser(u.username));
            tdActions.appendChild(delBtn);
            tr.appendChild(tdActions);

            elements.usersBody.appendChild(tr);
        }
    }

    async function onAddUser(e) {
        e.preventDefault();
        const btn = elements.addUserForm.querySelector('button[type="submit"]');
        setLoading(btn, true);
        hideError(elements.usersError);
        try {
            const res = await fetch(`${API_BASE}/admin/users`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: elements.newUsername.value.trim(),
                    password: elements.newPassword.value,
                    role: elements.newRole.value
                })
            });
            if (!res.ok) {
                showError(elements.usersError, await res.text().catch(() => 'Failed to create user.'));
                return;
            }
            elements.addUserForm.reset();
            await loadUsersData();
        } finally {
            setLoading(btn, false);
        }
    }

    async function updateUser(name, patch) {
        const res = await fetch(`${API_BASE}/admin/users/${encodeURIComponent(name)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(patch)
        });
        if (!res.ok) showError(elements.usersError, await res.text().catch(() => 'Update failed.'));
        await loadUsersData();
    }

    async function deleteUser(name) {
        const res = await fetch(`${API_BASE}/admin/users/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (!res.ok) {
            showError(elements.usersError, await res.text().catch(() => 'Delete failed.'));
            return;
        }
        if (currentUser && currentUser.username === name) {
            showLogin();
            return;
        }
        await loadUsersData();
    }

    function renderGroups(groups) {
        elements.groupsBody.textContent = '';
        if (!groups.length) {
            emptyRow(elements.groupsBody, 3, 'No groups.');
            return;
        }
        for (const g of groups) {
            const tr = document.createElement('tr');

            const tdName = document.createElement('td');
            tdName.textContent = g.name;
            tr.appendChild(tdName);

            const tdPerms = document.createElement('td');
            for (const perm of ALL_PERMS) {
                const label = document.createElement('label');
                label.className = 'perm-label';
                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = (g.permissions || []).includes(perm);
                cb.addEventListener('change', () => {
                    const perms = Array.from(tdPerms.querySelectorAll('input:checked')).map(i => i.value);
                    updateGroup(g.name, perms);
                });
                label.appendChild(cb);
                label.appendChild(document.createTextNode(' ' + perm));
                tdPerms.appendChild(label);
            }
            tr.appendChild(tdPerms);

            const tdActions = document.createElement('td');
            const delBtn = document.createElement('button');
            delBtn.className = 'btn btn-danger btn-small';
            delBtn.textContent = 'Delete';
            delBtn.addEventListener('click', () => deleteGroup(g.name));
            tdActions.appendChild(delBtn);
            tr.appendChild(tdActions);

            elements.groupsBody.appendChild(tr);
        }
    }

    async function onAddGroup(e) {
        e.preventDefault();
        const btn = elements.addGroupForm.querySelector('button[type="submit"]');
        setLoading(btn, true);
        hideError(elements.groupsError);
        try {
            const res = await fetch(`${API_BASE}/admin/groups`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: elements.newGroupName.value.trim(),
                    permissions: Array.from(elements.addGroupForm.querySelectorAll('.new-perm:checked')).map(i => i.value)
                })
            });
            if (!res.ok) {
                showError(elements.groupsError, await res.text().catch(() => 'Failed to create group.'));
                return;
            }
            elements.addGroupForm.reset();
            await loadUsersData();
        } finally {
            setLoading(btn, false);
        }
    }

    async function updateGroup(name, permissions) {
        const res = await fetch(`${API_BASE}/admin/groups/${encodeURIComponent(name)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ permissions })
        });
        if (!res.ok) showError(elements.groupsError, await res.text().catch(() => 'Update failed.'));
        await loadUsersData();
    }

    async function deleteGroup(name) {
        const res = await fetch(`${API_BASE}/admin/groups/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (!res.ok) showError(elements.groupsError, await res.text().catch(() => 'Delete failed.'));
        await loadUsersData();
    }

    function emptyRow(body, colspan, text) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = colspan;
        td.className = 'empty-row';
        td.textContent = text;
        tr.appendChild(td);
        body.appendChild(tr);
    }

    async function loadMetrics() {
        try {
            const res = await fetch(`${API_BASE}/admin/metrics`);
            if (!res.ok) return;
            const m = await res.json();
            elements.metricActive.textContent = m.active_downloads;
            elements.metricCompleted.textContent = m.completed_downloads;
            elements.metricFailed.textContent = m.failed_downloads;
            elements.metricBytes.textContent = m.bytes_human;
            elements.metricLogins.textContent = m.logins;
            elements.metricLoginFails.textContent = m.failed_logins;
        } catch {}
    }

    async function loadBruteForce() {
        try {
            const res = await fetch(`${API_BASE}/admin/bruteforce`);
            if (!res.ok) return;
            const state = await res.json();
            const cfg = state.config || {};
            elements.bruteForceConfig.textContent = '';
            for (const [id, label, val] of [
                ['bfMaxAttempts', 'Max Attempts', cfg.max_attempts || 5],
                ['bfWindow', 'Window (min)', cfg.window_minutes || 15],
                ['bfBackoffBase', 'Backoff Base (min)', cfg.backoff_base_minutes || 1],
                ['bfBackoffMax', 'Backoff Max (min)', cfg.backoff_max_minutes || 64]
            ]) {
                const field = document.createElement('div');
                field.className = 'bf-field';
                const lab = document.createElement('label');
                lab.textContent = label;
                const input = document.createElement('input');
                input.type = 'number';
                input.id = id;
                input.min = 1;
                input.value = val;
                field.append(lab, input);
                elements.bruteForceConfig.appendChild(field);
            }
            const actions = document.createElement('div');
            actions.className = 'bf-actions';
            const saveBtn = document.createElement('button');
            saveBtn.className = 'btn btn-primary btn-small';
            saveBtn.textContent = 'Save';
            saveBtn.addEventListener('click', saveBruteForceConfig);
            const unlockAllBtn = document.createElement('button');
            unlockAllBtn.className = 'btn btn-danger btn-small';
            unlockAllBtn.textContent = 'Unlock All';
            unlockAllBtn.addEventListener('click', resetBruteForceAll);
            actions.append(saveBtn, unlockAllBtn);
            elements.bruteForceConfig.appendChild(actions);

            const locks = state.locks || [];
            elements.bruteForceBody.textContent = '';
            if (!locks.length) {
                emptyRow(elements.bruteForceBody, 5, 'No active lockouts.');
                return;
            }
            for (const lock of locks) {
                const tr = document.createElement('tr');
                const until = new Date(lock.lockout_until);
                const remaining = until > new Date() ? Math.ceil((until - new Date()) / 60000) + 'm' : 'expired';

                const tdType = document.createElement('td');
                tdType.innerHTML = `<span class="lock-type-${lock.type}"></span>`;
                tdType.firstChild.textContent = lock.type;
                tr.appendChild(tdType);

                const tdKey = document.createElement('td');
                tdKey.textContent = lock.key;
                tr.appendChild(tdKey);

                const tdFailures = document.createElement('td');
                tdFailures.textContent = lock.failures;
                tr.appendChild(tdFailures);

                const tdUntil = document.createElement('td');
                tdUntil.textContent = `${until.toLocaleString()} (${remaining})`;
                tr.appendChild(tdUntil);

                const tdActions = document.createElement('td');
                tdActions.className = 'action-cell';
                const unlockBtn = document.createElement('button');
                unlockBtn.className = 'btn btn-danger btn-small';
                unlockBtn.textContent = 'Unlock';
                unlockBtn.addEventListener('click', () => resetBruteForceItem(lock));
                tdActions.appendChild(unlockBtn);
                tr.appendChild(tdActions);

                elements.bruteForceBody.appendChild(tr);
            }
        } catch {}
    }

    async function saveBruteForceConfig() {
        const cfg = {
            max_attempts: parseInt(document.getElementById('bfMaxAttempts')?.value) || 5,
            window_minutes: parseInt(document.getElementById('bfWindow')?.value) || 15,
            backoff_base_minutes: parseInt(document.getElementById('bfBackoffBase')?.value) || 1,
            backoff_max_minutes: parseInt(document.getElementById('bfBackoffMax')?.value) || 64
        };
        await fetch(`${API_BASE}/admin/bruteforce/config`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg)
        });
        loadBruteForce();
    }

    async function resetBruteForceAll() {
        await fetch(`${API_BASE}/admin/bruteforce/reset`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ all: true })
        });
        loadBruteForce();
    }

    const AUDIT_PAGE = 200;
    let auditLoaded = 0;   // rows currently shown
    let auditTotal = null; // matching events per server, null until first page
    let auditLoading = false;

    function auditFilterParams() {
        const params = new URLSearchParams();
        if (elements.filterAction.value) params.set('action', elements.filterAction.value);
        if (elements.filterUser.value.trim()) params.set('user', elements.filterUser.value.trim());
        if (elements.filterFrom.value) params.set('from', String(new Date(elements.filterFrom.value + 'T00:00').getTime()));
        if (elements.filterTo.value) params.set('to', String(new Date(elements.filterTo.value + 'T23:59:59.999').getTime()));
        if (elements.exportCsvBtn) elements.exportCsvBtn.href = `${API_BASE}/admin/audit/export?${params}`;
        return params;
    }

    async function fetchAuditPage(offset) {
        const params = auditFilterParams();
        params.set('limit', String(AUDIT_PAGE));
        params.set('offset', String(offset));
        params.set('include_count', '1');
        const res = await fetch(`${API_BASE}/admin/audit?${params}`);
        if (!res.ok) throw new Error(String(res.status));
        return res.json();
    }

    async function loadAuditData() {
        try {
            const data = await fetchAuditPage(0);
            const events = data.events || [];
            auditLoaded = events.length;
            auditTotal = typeof data.total === 'number' ? data.total : null;
            renderAudit(events, false);
            updateAuditCount();
        } catch {}
    }

    async function loadMoreAudit() {
        if (auditLoading || auditTotal === null || auditLoaded >= auditTotal) return;
        auditLoading = true;
        try {
            const data = await fetchAuditPage(auditLoaded);
            const events = data.events || [];
            appendAuditRows(events);
            auditLoaded += events.length;
            if (typeof data.total === 'number') auditTotal = data.total;
            updateAuditCount();
        } catch {} finally {
            auditLoading = false;
        }
    }

    function updateAuditCount() {
        if (auditTotal === null) {
            elements.auditCount.textContent = '';
            return;
        }
        elements.auditCount.textContent =
            `Showing ${Math.min(auditLoaded, auditTotal).toLocaleString()} of ${auditTotal.toLocaleString()} events` +
            (auditLoaded >= auditTotal ? '' : ' — scroll for more');
    }

    function renderAudit(events, append) {
        if (!append) elements.auditBody.textContent = '';
        if (!append && !events.length) {
            emptyRow(elements.auditBody, 5, 'No events yet.');
            return;
        }
        appendAuditRows(events);
    }

    function appendAuditRows(events) {
        for (const ev of events) {
            const tr = document.createElement('tr');
            for (const val of [
                new Date(ev.time).toLocaleString(),
                ev.user || '—',
                ev.action,
                ev.ip || '—',
                ev.detail || ''
            ]) {
                const td = document.createElement('td');
                td.textContent = val;
                tr.appendChild(td);
            }
            const actionTd = tr.children[2];
            actionTd.className = 'action-cell ' +
                (ev.action.includes('failed') || ev.action === 'download_error' ? 'action-bad' :
                 ev.action === 'download_success' || ev.action === 'login_success' ? 'action-good' : '');
            elements.auditBody.appendChild(tr);
        }
    }

    function onUrlInput() {
        hideError(elements.urlError);
        elements.checkBtn.disabled = !elements.urlInput.value.trim();
    }

    async function onCheckClick() {
        const url = elements.urlInput.value.trim();
        if (!url) return;

        currentUrl = url;
        currentPassword = null;

        setLoading(elements.checkBtn, true);
        hideError(elements.urlError);

        try {
            const info = await fetchWithRetry(`${API_BASE}/info?url=${encodeURIComponent(url)}`);

            if (info.needs_password) {
                showPasswordSection(info.error || 'This transfer is password-protected.');
                return;
            }

            showFileInfo(info);
        } catch (err) {
            if (err.name === 'AuthError') return;
            if (isShortWeTransferUrl(url) && err.message.includes('blocked by WeTransfer')) {
                showError(elements.urlError, getUserErrorMessage(err, 'Failed to check file.'));
            } else if (err.message.includes('401') || err.message.includes('password')) {
                showPasswordSection('This transfer is password-protected.');
            } else {
                showError(elements.urlError, getUserErrorMessage(err, 'Failed to check file. Please verify the URL.'));
            }
        } finally {
            setLoading(elements.checkBtn, false);
        }
    }

    function showPasswordSection(message) {
        elements.passwordMessage.textContent = message;
        elements.passwordInput.value = '';
        hideError(elements.passwordError);
        elements.inputSection.hidden = true;
        elements.passwordSection.hidden = false;
        elements.passwordInput.focus();
    }

    async function onPasswordSubmit() {
        const password = elements.passwordInput.value.trim();
        if (!password) return;

        setLoading(elements.passwordBtn, true);
        hideError(elements.passwordError);

        try {
            const url = `${API_BASE}/info?url=${encodeURIComponent(currentUrl)}&password=${encodeURIComponent(password)}`;
            const info = await fetchWithRetry(url);

            if (info.needs_password) {
                showError(elements.passwordError, 'Incorrect password. Please try again.');
                return;
            }

            currentPassword = password;
            elements.passwordSection.hidden = true;
            showFileInfo(info);
        } catch (err) {
            if (err.name === 'AuthError') return;
            if (err.message.includes('401') || err.message.includes('password')) {
                showError(elements.passwordError, 'Incorrect password. Please try again.');
            } else {
                showError(elements.passwordError, getUserErrorMessage(err, 'Failed to verify password.'));
            }
        } finally {
            setLoading(elements.passwordBtn, false);
        }
    }

    function isShortWeTransferUrl(url) {
        return url.startsWith('https://we.tl/') || url.startsWith('http://we.tl/');
    }

    function showFileInfo(info) {
        currentFileInfo = info;
        elements.fileName.textContent = info.filename || 'Unknown file';
        elements.fileSize.textContent = info.size_human || formatBytes(info.size);
        
        if (info.file_count > 1) {
            elements.fileCount.hidden = false;
            elements.fileCountValue.textContent = info.file_count;
        } else {
            elements.fileCount.hidden = true;
        }

        elements.providerBadge.textContent = formatProviderName(info.provider) || 'WeTransfer';

        elements.inputSection.hidden = true;
        elements.infoSection.hidden = false;
        elements.downloadBtn.disabled = false;
        hideError(elements.downloadError);
        hideProgress();
    }

    async function onDownloadClick() {
        if (!currentFileInfo) return;

        abortController = new AbortController();
        
        setLoading(elements.downloadBtn, true);
        elements.downloadBtn.disabled = true;
        elements.retryBtn.hidden = true;
        elements.cancelBtn.style.display = '';
        hideError(elements.downloadError);
        showProgress();

        try {
            await startDownload(currentFileInfo);
        } catch (err) {
            if (err.name !== 'AbortError' && err.name !== 'AuthError') {
                showError(elements.downloadError, getUserErrorMessage(err, 'Download failed. Please try again.'));
                elements.retryBtn.hidden = false;
            }
            hideProgress();
        } finally {
            setLoading(elements.downloadBtn, false);
            elements.downloadBtn.disabled = false;
            elements.cancelBtn.style.display = 'none';
            loadRecent();
        }
    }

    async function startDownload(info) {
        let downloadUrl = `${API_BASE}/download?url=${encodeURIComponent(currentUrl || elements.urlInput.value.trim())}`;
        if (currentPassword) {
            downloadUrl += `&password=${encodeURIComponent(currentPassword)}`;
        }
        
        const response = await fetch(downloadUrl, {
            signal: abortController.signal
        });

        if (response.status === 401) {
            const data = await response.json().catch(() => null);
            if (data && data.needs_password) {
                elements.inputSection.hidden = true;
                elements.infoSection.hidden = true;
                showPasswordSection('Incorrect password. Please re-enter the transfer password.');
                return;
            }
            showLogin();
            throw Object.assign(new Error('Session expired'), { name: 'AuthError' });
        }

        if (!response.ok) {
            const errText = await response.text().catch(() => '');
            throw new Error(`Server error: ${response.status} ${errText}`);
        }

        const contentLength = response.headers.get('Content-Length');
        const total = contentLength ? parseInt(contentLength, 10) : null;
        const filename = extractFilename(response.headers.get('Content-Disposition')) || info.filename || 'download';

        const reader = response.body.getReader();
        const stream = new ReadableStream({
            start(controller) {
                return pump(reader, controller, total);
            }
        });

        await saveStream(stream, filename, total);
    }

    async function pump(reader, controller, total) {
        let loaded = 0;
        const startTime = Date.now();

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            loaded += value.length;
            controller.enqueue(value);

            updateProgress(loaded, total, loaded / ((Date.now() - startTime) / 1000));
        }
        controller.close();
    }

    async function saveStream(stream, filename, total) {
        const blob = await new Response(stream).blob();
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        
        showProgressComplete(filename);
    }

    function updateProgress(loaded, total, speed) {
        const percent = total ? Math.round((loaded / total) * 100) : 0;
        elements.progressFill.style.width = `${percent}%`;
        elements.progressPercent.textContent = `${percent}%`;
        elements.progressSpeed.textContent = formatSpeed(speed);
        
        if (total && speed > 0) {
            const remaining = (total - loaded) / speed;
            elements.progressEta.textContent = formatDuration(remaining);
        } else {
            elements.progressEta.textContent = '—';
        }
        
        elements.progressStatus.textContent = total 
            ? `Downloading... ${formatBytes(loaded)} / ${formatBytes(total)}`
            : `Downloading... ${formatBytes(loaded)}`;
    }

    function showProgress() {
        elements.progressSection.hidden = false;
        elements.progressFill.style.width = '0%';
        elements.progressPercent.textContent = '0%';
        elements.progressSpeed.textContent = '—';
        elements.progressEta.textContent = '—';
        elements.progressStatus.textContent = 'Preparing download...';
    }

    function hideProgress() {
        elements.progressSection.hidden = true;
    }

    function showProgressComplete(filename) {
        elements.progressFill.style.width = '100%';
        elements.progressPercent.textContent = '100%';
        elements.progressStatus.textContent = `Download complete: ${filename}`;
    }

    function onRetryClick() {
        elements.inputSection.hidden = false;
        elements.infoSection.hidden = true;
        elements.passwordSection.hidden = true;
        elements.urlInput.value = '';
        elements.urlInput.focus();
        currentFileInfo = null;
        currentPassword = null;
    }

    async function fetchWithRetry(url, attempt = 0) {
        let response;
        try {
            response = await fetch(url);
        } catch (err) {
            if (attempt < MAX_RETRIES - 1) {
                await sleep(RETRY_DELAYS[attempt]);
                return fetchWithRetry(url, attempt + 1);
            }
            throw err;
        }
        if (response.status === 401) {
            showLogin();
            throw Object.assign(new Error('Session expired'), { name: 'AuthError' });
        }
        if (!response.ok) {
            if (attempt < MAX_RETRIES - 1) {
                await sleep(RETRY_DELAYS[attempt]);
                return fetchWithRetry(url, attempt + 1);
            }
            throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
    }

    function setLoading(btn, loading) {
        const text = btn.querySelector('.btn-text');
        const loader = btn.querySelector('.btn-loader');
        btn.disabled = loading;
        if (text) text.hidden = loading;
        if (loader) loader.hidden = !loading;
    }

    function showError(el, msg) {
        el.textContent = msg;
        el.hidden = false;
    }

    function hideError(el) {
        el.hidden = true;
    }

    function extractFilename(cd) {
        if (!cd) return null;
        const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
        if (match) {
            let name = match[1].replace(/^['"]|['"]$/g, '');
            return decodeURIComponent(name);
        }
        return null;
    }

    function getUserErrorMessage(err, fallback) {
        const msg = (err && err.message) || '';
        if (!msg) return fallback;
        if (msg.includes('blocked by WeTransfer')) return 'Short WeTransfer links (we.tl/...) may be blocked on data center IPs. Use the full download link (wetransfer.com/downloads/...) instead.';
        if (msg.includes('401') || msg.toLowerCase().includes('password')) return 'Incorrect password. Please try again.';
        if (msg.includes('429')) return 'Too many requests. Please wait a moment and try again.';
        if (msg.includes('503') || msg.includes('502')) return 'The file host is temporarily unavailable. Please try again later.';
        if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) return 'Network error. Please check your connection and try again.';
        if (msg.startsWith('HTTP ') || msg.startsWith('Server error:')) return fallback;
        return msg.length < 120 ? msg : fallback;
    }

    function formatProviderName(name) {
        if (!name) return '';
        const map = { wetransfer: 'WeTransfer', sendgb: 'SendGB', transfernow: 'TransferNow', wesendit: 'Wesendit', sendspace: 'SendSpace' };
        return map[name] || name.charAt(0).toUpperCase() + name.slice(1);
    }

    function formatBytes(bytes) {
        if (!bytes && bytes !== 0) return '—';
        if (bytes < 1024) return `${bytes} B`;
        const units = ['KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return `${bytes.toFixed(1)} ${units[i]}`;
    }

    function formatSpeed(bytesPerSec) {
        return formatBytes(bytesPerSec) + '/s';
    }

    function formatDuration(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${Math.round(seconds / 3600)}h`;
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    document.addEventListener('DOMContentLoaded', init);
})();
