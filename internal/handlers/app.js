(function() {
    'use strict';

    const API_BASE = '/api/v1';
    const MAX_RETRIES = 3;
    const RETRY_DELAYS = [1000, 2000, 4000];
    const ALL_PERMS = ['download', 'dashboard', 'audit', 'users', 'groups'];
    const ALL_ACTIONS = [
        'login_success', 'login_failed', 'logout', 'info_check',
        'download_success', 'download_error',
        'user_created', 'user_updated', 'user_deleted',
        'group_created', 'group_updated', 'group_deleted'
    ];

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
        adminView: document.getElementById('adminView'),
        auditView: document.getElementById('auditView'),
        usersView: document.getElementById('usersView'),
        groupsView: document.getElementById('groupsView'),
        metricActive: document.getElementById('metricActive'),
        metricCompleted: document.getElementById('metricCompleted'),
        metricFailed: document.getElementById('metricFailed'),
        metricBytes: document.getElementById('metricBytes'),
        metricLogins: document.getElementById('metricLogins'),
        metricLoginFails: document.getElementById('metricLoginFails'),
        auditBody: document.getElementById('auditBody'),
        refreshAuditBtn: document.getElementById('refreshAuditBtn'),
        logoutBtn: document.getElementById('logoutBtn'),
        auditFilterForm: document.getElementById('auditFilterForm'),
        filterAction: document.getElementById('filterAction'),
        filterUser: document.getElementById('filterUser'),
        filterFrom: document.getElementById('filterFrom'),
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
        progressSection: document.getElementById('progressSection'),
        progressFill: document.getElementById('progressFill'),
        progressPercent: document.getElementById('progressPercent'),
        progressSpeed: document.getElementById('progressSpeed'),
        progressEta: document.getElementById('progressEta'),
        progressStatus: document.getElementById('progressStatus'),
        downloadError: document.getElementById('downloadError'),
        recentSection: document.getElementById('recentSection'),
        recentBody: document.getElementById('recentBody')
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

        for (const action of ALL_ACTIONS) {
            const opt = document.createElement('option');
            opt.value = action;
            opt.textContent = action.replaceAll('_', ' ');
            elements.filterAction.appendChild(opt);
        }
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

        setInterval(() => {
            if (!currentUser) return;
            if (!elements.adminView.hidden) loadMetrics();
            if (!elements.auditView.hidden) loadAuditData();
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
        elements.loginSection.hidden = true;
        elements.appView.hidden = false;
        elements.userName.textContent = user.username;
        elements.userMenu.querySelectorAll('.menu-item[data-perm]').forEach(el => {
            el.hidden = !can(el.dataset.perm);
        });
        elements.userMenu.hidden = true;
        switchTab('download');
        elements.urlInput.focus();
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

    const VIEW_PERMS = { dashboard: 'dashboard', audit: 'audit', users: 'users', groups: 'groups' };

    function switchTab(name) {
        if (VIEW_PERMS[name] && !can(VIEW_PERMS[name])) name = 'download';
        elements.downloadView.hidden = name !== 'download';
        elements.adminView.hidden = name !== 'dashboard';
        elements.auditView.hidden = name !== 'audit';
        elements.usersView.hidden = name !== 'users';
        elements.groupsView.hidden = name !== 'groups';
        elements.container.classList.toggle('wide', name !== 'download');
        if (name === 'download') loadRecent();
        if (name === 'dashboard') loadMetrics();
        if (name === 'audit') loadAuditData();
        if (name === 'users') loadUsersData();
        if (name === 'groups') loadGroupsData();
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
            tdFile.textContent = d.detail || d.url;
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
            const res = await fetch(`${API_BASE}/admin/users`);
            if (!res.ok) return;
            const { users } = await res.json();
            renderUsers(users || []);
        } catch {}
        loadLdapStatus();
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

    function renderUsers(users) {
        elements.usersBody.textContent = '';
        if (!users.length) {
            emptyRow(elements.usersBody, 5, 'No users.');
            return;
        }
        for (const u of users) {
            const tr = document.createElement('tr');

            const tdName = document.createElement('td');
            tdName.textContent = u.username;
            tr.appendChild(tdName);

            const tdSource = document.createElement('td');
            tdSource.textContent = u.source === 'ldap' ? 'ldap' : 'local';
            if (u.source === 'ldap') tdSource.className = 'source-ldap';
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

            const tdGroups = document.createElement('td');
            const groupsInput = document.createElement('input');
            groupsInput.type = 'text';
            groupsInput.className = 'row-input';
            groupsInput.value = (u.groups || []).join(', ');
            groupsInput.placeholder = 'none';
            groupsInput.addEventListener('change', () => updateUser(u.username, {
                groups: groupsInput.value.split(',').map(s => s.trim()).filter(Boolean)
            }));
            tdGroups.appendChild(groupsInput);
            tr.appendChild(tdGroups);

            const tdActions = document.createElement('td');
            if (u.source !== 'ldap') {
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

    async function loadAuditData() {
        const params = new URLSearchParams();
        if (elements.filterAction.value) params.set('action', elements.filterAction.value);
        if (elements.filterUser.value.trim()) params.set('user', elements.filterUser.value.trim());
        if (elements.filterFrom.value) params.set('from', String(new Date(elements.filterFrom.value).getTime()));
        if (elements.filterTo.value) params.set('to', String(new Date(elements.filterTo.value).getTime()));
        params.set('limit', '500');
        try {
            const res = await fetch(`${API_BASE}/admin/audit?${params}`);
            if (!res.ok) return;
            const { events } = await res.json();
            renderAudit(events || []);
        } catch {}
    }

    function renderAudit(events) {
        elements.auditBody.textContent = '';
        if (!events.length) {
            emptyRow(elements.auditBody, 5, 'No events yet.');
            return;
        }
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
                showError(elements.urlError, 'Short WeTransfer links (we.tl/...) work on residential IPs but may be blocked on data center IPs. Your server appears to be on a data center IP. Please use the full download link (https://wetransfer.com/downloads/...) instead. You can get it by opening the short link in a browser and copying the redirected URL.');
            } else if (err.message.includes('401') || err.message.includes('password')) {
                showPasswordSection('This transfer is password-protected.');
            } else {
                showError(elements.urlError, err.message || 'Failed to check file. Please verify the URL.');
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
                showError(elements.passwordError, err.message || 'Failed to verify password.');
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

        elements.providerBadge.textContent = info.provider || 'WeTransfer';

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
        hideError(elements.downloadError);
        showProgress();

        try {
            await startDownload(currentFileInfo);
        } catch (err) {
            if (err.name !== 'AbortError' && err.name !== 'AuthError') {
                showError(elements.downloadError, err.message || 'Download failed. Please try again.');
                elements.retryBtn.hidden = false;
            }
            hideProgress();
        } finally {
            setLoading(elements.downloadBtn, false);
            elements.downloadBtn.disabled = false;
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
