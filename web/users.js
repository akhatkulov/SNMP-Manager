/* ═══════════════════════════════════════════════════════════════════════
   SNMP Manager Admin Panel — Users & Roles (RBAC) Module
   ═══════════════════════════════════════════════════════════════════════ */

(() => {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const API_BASE = '/api/v1';

    let usersList = [];

    // Assuming app.js exposes a global fetch wrapper. Since it might not be exported globally,
    // we'll implement a standalone API caller here matching app.js format, using the apiKey.
    async function usersApiCall(method, endpoint, body = null) {
        const apiKey = localStorage.getItem('snmp_access_token') || localStorage.getItem('snmp_api_key') || '';
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) {
            if (apiKey.includes('.')) headers['Authorization'] = `Bearer ${apiKey}`;
            else headers['X-API-Key'] = apiKey;
        }
        const opts = { method, headers };
        if (body) opts.body = JSON.stringify(body);
        
        try {
            const res = await fetch(`${API_BASE}${endpoint}`, opts);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
            return data;
        } catch (e) {
            showToast(e.message, 'error');
            throw e;
        }
    }

    function showToast(message, type = 'info') {
        const container = $('#toastContainer');
        if(!container) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${message}</span>`;
        container.appendChild(toast);
        setTimeout(() => { toast.classList.add('toast-removing'); setTimeout(() => toast.remove(), 300); }, 4000);
    }

    async function loadUsersPage() {
        try {
            const data = await usersApiCall('GET', '/users');
            usersList = data || [];
            renderUsersTable();
        } catch (err) {
            console.error('Failed to load users:', err);
        }
    }

    function renderUsersTable() {
        const tbody = $('#usersTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (!usersList || usersList.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No users found.</td></tr>`;
            return;
        }
        
        usersList.forEach(u => {
            const tr = document.createElement('tr');
            
            let roleBadge = '';
            if (u.role === 'admin') roleBadge = `<span class="badge" style="background:rgba(255,107,107,0.1);color:#ff6b6b;border:1px solid rgba(255,107,107,0.3)">Admin</span>`;
            else if (u.role === 'operator') roleBadge = `<span class="badge" style="background:rgba(77,171,247,0.1);color:#4dabf7;border:1px solid rgba(77,171,247,0.3)">Operator</span>`;
            else roleBadge = `<span class="badge badge-outline">${u.role}</span>`;
            
            tr.innerHTML = `
                <td><strong>${escapeHtml(u.username)}</strong></td>
                <td>${roleBadge}</td>
                <td><span class="text-muted" style="font-size:0.85rem">${escapeHtml(u.tenant_id || 'Global')}</span></td>
                <td><div class="status-indicator"><div class="status-dot status-online"></div> Active</div></td>
                <td><span class="text-muted" style="font-size:0.85rem">${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</span></td>
                <td>
                    <div class="action-menu">
                        <button class="btn btn-ghost btn-sm" onclick="window._deleteUser('${u.id}', '${escapeHtml(u.username)}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;color:var(--accent-red)"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Modal HTML injection
    function injectUsersModal() {
        if ($('#addUserModal')) return;
        const html = `
            <div class="modal-overlay" id="addUserModal">
                <div class="modal modal-sm">
                    <div class="modal-header">
                        <h2>Add New User</h2>
                        <button class="modal-close" id="addUserClose" aria-label="Close">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </button>
                    </div>
                    <form id="addUserForm">
                        <div class="modal-body">
                            <div class="form-group">
                                <label for="newUsername">Username *</label>
                                <input type="text" id="newUsername" placeholder="Enter username" required>
                            </div>
                            <div class="form-group">
                                <label for="newPassword">Password *</label>
                                <input type="password" id="newPassword" placeholder="Minimum 6 characters" required>
                            </div>
                            <div class="form-group">
                                <label for="newRole">Role</label>
                                <select id="newRole">
                                    <option value="admin">Admin</option>
                                    <option value="operator" selected>Operator</option>
                                    <option value="viewer">Viewer</option>
                                    <option value="l1_support">L1 Support</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="newTenant">Tenant ID (Optional)</label>
                                <input type="text" id="newTenant" placeholder="Leave blank for Global">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-ghost" id="addUserCancel">Cancel</button>
                            <button type="submit" class="btn btn-primary">Create User</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', html);
        
        $('#addUserClose').addEventListener('click', () => $('#addUserModal').classList.remove('active'));
        $('#addUserCancel').addEventListener('click', () => $('#addUserModal').classList.remove('active'));
        
        $('#addUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = $('#newUsername').value.trim();
            const password = $('#newPassword').value;
            const role = $('#newRole').value;
            const tenant_id = $('#newTenant').value.trim();
            
            try {
                await usersApiCall('POST', '/users', { username, password, role, tenant_id });
                showToast('User created successfully', 'success');
                $('#addUserModal').classList.remove('active');
                $('#addUserForm').reset();
                loadUsersPage();
            } catch (err) {
                // handled by usersApiCall
            }
        });
    }

    // Assign globally
    window.loadUsersPage = loadUsersPage;
    window._deleteUser = async (id, username) => {
        if (!confirm(`Are you sure you want to delete user '${username}'?`)) return;
        try {
            await usersApiCall('DELETE', `/users/${id}`);
            showToast('User deleted', 'success');
            loadUsersPage();
        } catch (err) {}
    };

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
        injectUsersModal();
        $('#userAddBtn')?.addEventListener('click', () => {
            $('#addUserModal').classList.add('active');
            $('#newUsername').focus();
        });
    });

})();
