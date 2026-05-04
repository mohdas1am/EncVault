// ═══ EncVault Frontend — app.js ═══

// ─── State ──────────────────────────────────────────────────────────

let authMode = 'login'; // 'login' | 'signup'
let sessionToken = null;
let currentUser = null;
let selectedFileData = null;
let selectedFileName = null;
let lastDecryptedContent = null;
let lastDecryptedFilename = null;

// ─── Init ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Check for existing session
    sessionToken = sessionStorage.getItem('encvault_token');
    if (sessionToken) {
        loadDashboard();
    }

    // Setup dropzone drag & drop
    const dropzone = document.getElementById('dropzone');
    if (dropzone) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });
        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) handleFileInput(files[0]);
        });
    }
});

// ─── Auth ───────────────────────────────────────────────────────────

function switchAuthTab(mode) {
    authMode = mode;
    document.getElementById('tab-login').classList.toggle('active', mode === 'login');
    document.getElementById('tab-signup').classList.toggle('active', mode === 'signup');
    document.getElementById('tab-indicator').classList.toggle('signup', mode === 'signup');
    document.getElementById('auth-submit-btn').querySelector('.btn-text').textContent =
        mode === 'login' ? 'Sign In' : 'Create Account';
    hideMessages();
}

async function handleAuth(event) {
    event.preventDefault();
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value.trim();
    const btn = document.getElementById('auth-submit-btn');

    if (!username || !password) {
        showError('auth-error', 'Please enter both username and password');
        return;
    }

    setButtonLoading(btn, true);
    hideMessages();

    try {
        const endpoint = authMode === 'login' ? '/api/login' : '/api/signup';
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        const data = await res.json();

        if (data.success && data.token) {
            sessionToken = data.token;
            sessionStorage.setItem('encvault_token', sessionToken);
            showSuccess('auth-success', data.message);
            setTimeout(() => loadDashboard(), 600);
        } else {
            showError('auth-error', data.message || 'Authentication failed');
        }
    } catch (err) {
        showError('auth-error', 'Network error: could not connect to server');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function handleLogout() {
    try {
        await fetch('/api/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${sessionToken}` },
        });
    } catch (_) { }

    sessionToken = null;
    currentUser = null;
    sessionStorage.removeItem('encvault_token');
    showView('auth-view');
    document.getElementById('auth-username').value = '';
    document.getElementById('auth-password').value = '';
}

// ─── Dashboard ──────────────────────────────────────────────────────

async function loadDashboard() {
    showView('dashboard-view');

    try {
        const res = await fetch('/api/me', {
            headers: { 'Authorization': `Bearer ${sessionToken}` },
        });

        if (!res.ok) {
            handleLogout();
            return;
        }

        currentUser = await res.json();

        // Update UI
        document.getElementById('nav-username').textContent = currentUser.username;
        document.getElementById('user-avatar').textContent = currentUser.username[0].toUpperCase();

        // Truncate public key for display
        const pkShort = currentUser.public_key.substring(0, 48) + '...';
        document.getElementById('key-preview').textContent = pkShort;

        // Load file lists
        loadInbox();
        loadSent();
        loadUsers();
    } catch (err) {
        handleLogout();
    }
}

// ─── Section Switching ──────────────────────────────────────────────

function switchSection(section) {
    // Update sidebar
    document.querySelectorAll('.sidebar-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`nav-${section}`).classList.add('active');

    // Update sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(`section-${section}`).classList.add('active');

    // Refresh data for the selected section
    if (section === 'inbox') loadInbox();
    else if (section === 'sent') loadSent();
    else if (section === 'encrypt') loadUsers();
}

// ─── Encrypt ────────────────────────────────────────────────────────

function toggleRecipientSelect() {
    const recipientType = document.querySelector('input[name="recipient-type"]:checked').value;
    const otherGroup = document.getElementById('other-user-group');
    otherGroup.style.display = recipientType === 'other' ? 'block' : 'none';
}

async function loadUsers() {
    try {
        const res = await fetch('/api/users', {
            headers: { 'Authorization': `Bearer ${sessionToken}` },
        });
        const users = await res.json();
        const select = document.getElementById('recipient-select');

        // Clear previous options
        select.innerHTML = '<option value="">Choose a user...</option>';

        users.forEach(u => {
            if (u.username !== currentUser.username) {
                const opt = document.createElement('option');
                opt.value = u.username;
                opt.textContent = `${u.username} (PK: ${u.public_key.substring(0, 20)}...)`;
                select.appendChild(opt);
            }
        });
    } catch (_) { }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) handleFileInput(file);
}

function handleFileInput(file) {
    if (!file.name.endsWith('.json')) {
        showStatus('encrypt-status', 'Only .json files are supported', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const content = e.target.result;
            // Validate JSON
            JSON.parse(content);

            selectedFileData = content;
            selectedFileName = file.name;

            // Show preview
            document.getElementById('json-filename').textContent = file.name;
            document.getElementById('json-content').textContent =
                content.length > 2000 ? content.substring(0, 2000) + '\n... (truncated)' : content;
            document.getElementById('json-preview').style.display = 'block';
            document.getElementById('encrypt-btn').disabled = false;

            hideStatus('encrypt-status');
        } catch (_) {
            showStatus('encrypt-status', 'Invalid JSON file', 'error');
        }
    };
    reader.readAsText(file);
}

function clearFile() {
    selectedFileData = null;
    selectedFileName = null;
    document.getElementById('json-preview').style.display = 'none';
    document.getElementById('encrypt-btn').disabled = true;
    document.getElementById('file-input').value = '';
}

async function handleEncrypt() {
    if (!selectedFileData || !selectedFileName) return;

    const recipientType = document.querySelector('input[name="recipient-type"]:checked').value;
    let recipient;

    if (recipientType === 'self') {
        recipient = currentUser.username;
    } else {
        recipient = document.getElementById('recipient-select').value;
        if (!recipient) {
            showStatus('encrypt-status', 'Please select a recipient', 'error');
            return;
        }
    }

    const btn = document.getElementById('encrypt-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-loader"></span><span>Encrypting...</span>';

    try {
        const res = await fetch('/api/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sessionToken}`,
            },
            body: JSON.stringify({
                filename: selectedFileName,
                data: selectedFileData,
                recipient: recipient,
            }),
        });

        const data = await res.json();

        if (data.success) {
            showStatus('encrypt-status',
                `✔ ${data.message}`, 'success');
            clearFile();
            // Refresh lists
            loadInbox();
            loadSent();
        } else {
            showStatus('encrypt-status', data.error || 'Encryption failed', 'error');
        }
    } catch (err) {
        showStatus('encrypt-status', 'Network error', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span>Encrypt & Store</span>`;
    }
}

// ─── Inbox ──────────────────────────────────────────────────────────

async function loadInbox() {
    try {
        const res = await fetch('/api/files/inbox', {
            headers: { 'Authorization': `Bearer ${sessionToken}` },
        });
        const files = await res.json();

        const list = document.getElementById('inbox-list');
        const badge = document.getElementById('inbox-badge');

        if (files.length === 0) {
            list.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity="0.3">
                        <polyline points="22,12 16,12 14,15 10,15 8,12 2,12"/>
                        <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
                    </svg>
                    <p>No encrypted files in your inbox yet</p>
                </div>`;
            badge.style.display = 'none';
        } else {
            badge.textContent = files.length;
            badge.style.display = 'inline';
            list.innerHTML = files.map(f => `
                <div class="file-card" id="file-${f.id}">
                    <div class="file-icon inbox-icon">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                    </div>
                    <div class="file-info">
                        <div class="file-name">${escapeHtml(f.filename)}</div>
                        <div class="file-meta">
                            <span class="file-meta-tag tag-from">From: ${escapeHtml(f.sender)}</span>
                            <span>${f.timestamp}</span>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="btn btn-success btn-sm" onclick="handleDecrypt('${f.id}')">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
                            </svg>
                            Decrypt
                        </button>
                    </div>
                </div>
            `).join('');
        }
    } catch (_) { }
}

// ─── Sent ───────────────────────────────────────────────────────────

async function loadSent() {
    try {
        const res = await fetch('/api/files/sent', {
            headers: { 'Authorization': `Bearer ${sessionToken}` },
        });
        const files = await res.json();

        const list = document.getElementById('sent-list');
        const badge = document.getElementById('sent-badge');

        if (files.length === 0) {
            list.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity="0.3">
                        <line x1="22" y1="2" x2="11" y2="13"/>
                        <polygon points="22,2 15,22 11,13 2,9 22,2"/>
                    </svg>
                    <p>No files sent yet</p>
                </div>`;
            badge.style.display = 'none';
        } else {
            badge.textContent = files.length;
            badge.style.display = 'inline';
            list.innerHTML = files.map(f => `
                <div class="file-card" id="file-${f.id}">
                    <div class="file-icon sent-icon">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="22" y1="2" x2="11" y2="13"/>
                            <polygon points="22,2 15,22 11,13 2,9 22,2"/>
                        </svg>
                    </div>
                    <div class="file-info">
                        <div class="file-name">${escapeHtml(f.filename)}</div>
                        <div class="file-meta">
                            <span class="file-meta-tag tag-to">To: ${escapeHtml(f.recipient)}</span>
                            <span>${f.timestamp}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    } catch (_) { }
}

// ─── Decrypt ────────────────────────────────────────────────────────

async function handleDecrypt(fileId) {
    const btn = event.target.closest('button');
    const origHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-loader"></span>';

    try {
        const res = await fetch('/api/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sessionToken}`,
            },
            body: JSON.stringify({ file_id: fileId }),
        });

        const data = await res.json();

        if (data.success) {
            lastDecryptedContent = data.plaintext;
            lastDecryptedFilename = data.filename;

            // Try to pretty-print JSON
            try {
                const parsed = JSON.parse(data.plaintext);
                document.getElementById('modal-content').textContent =
                    JSON.stringify(parsed, null, 2);
            } catch (_) {
                document.getElementById('modal-content').textContent = data.plaintext;
            }

            document.getElementById('modal-filename').textContent = data.filename;
            document.getElementById('decrypt-modal').style.display = 'flex';
        } else {
            alert(data.message || 'Decryption failed');
        }
    } catch (err) {
        alert('Network error during decryption');
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHTML;
    }
}

function closeModal() {
    document.getElementById('decrypt-modal').style.display = 'none';
}

function downloadDecrypted() {
    if (!lastDecryptedContent || !lastDecryptedFilename) return;

    const blob = new Blob([lastDecryptedContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastDecryptedFilename.replace('.json', '_decrypted.json');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ─── Copy Public Key ────────────────────────────────────────────────

async function copyPublicKey() {
    if (!currentUser) return;

    try {
        await navigator.clipboard.writeText(currentUser.public_key);
        const btn = document.getElementById('copy-key-btn');
        const origHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20,6 9,17 4,12"/>
            </svg>
            <span>Copied!</span>`;
        setTimeout(() => { btn.innerHTML = origHTML; }, 2000);
    } catch (_) { }
}

// ─── Utilities ──────────────────────────────────────────────────────

function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
}

function setButtonLoading(btn, loading) {
    const text = btn.querySelector('.btn-text');
    const loader = btn.querySelector('.btn-loader');
    if (text) text.style.display = loading ? 'none' : 'inline';
    if (loader) loader.style.display = loading ? 'inline-block' : 'none';
    btn.disabled = loading;
}

function showError(elId, msg) {
    const el = document.getElementById(elId);
    el.textContent = msg;
    el.style.display = 'block';
}

function showSuccess(elId, msg) {
    const el = document.getElementById(elId);
    el.textContent = msg;
    el.style.display = 'block';
}

function showStatus(elId, msg, type) {
    const el = document.getElementById(elId);
    el.textContent = msg;
    el.className = `status-msg ${type || ''}`;
    el.style.display = 'block';
}

function hideStatus(elId) {
    document.getElementById(elId).style.display = 'none';
}

function hideMessages() {
    document.querySelectorAll('.error-msg, .success-msg').forEach(el => {
        el.style.display = 'none';
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Keyboard Shortcuts ─────────────────────────────────────────────

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }
});
