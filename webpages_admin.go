package mtlswhitelist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (a *MTlsOrWhitelist) serveAdminPage(rw http.ResponseWriter, req *http.Request) {
	callerIdentity, ok := a.isAdmin(req)
	if !ok {
		// Not admin or not authenticated — check why
		if callerIdentity != "" && a.isAdminIdentity(callerIdentity) {
			// Is admin but not authenticated — redirect to login
			loginURL := a.rawConfig.TwoFactor.PathPrefix + "login?redirect=" + req.URL.String()
			http.Redirect(rw, req, loginURL, http.StatusFound)
			return
		}
		http.Error(rw, "forbidden: admin access required", http.StatusForbidden)
		return
	}

	pathPrefix := a.rawConfig.TwoFactor.PathPrefix

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2FA Admin Panel</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; padding: 2rem; background: #f0f2f5; line-height: 1.5; color: #1c1e21; }
        .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 800px; margin: 0 auto; }
        h1 { color: #1877f2; margin-top: 0; }
        h2 { font-size: 1.1rem; margin-top: 1.5rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
        .info { background: #e7f3ff; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 5px solid #1877f2; }
        .success { background: #d4edda; color: #155724; padding: 1rem; border-radius: 8px; border-left: 5px solid #28a745; margin: 1rem 0; display: none; }
        .error { background: #f8d7da; color: #721c24; padding: 1rem; border-radius: 8px; border-left: 5px solid #dc3545; margin: 1rem 0; display: none; }
        table { width: 100%%; border-collapse: collapse; margin: 1rem 0; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        button { padding: 0.5rem 1rem; border: none; border-radius: 6px; cursor: pointer; font-size: 0.875rem; transition: background 0.2s; }
        .btn-primary { background: #1877f2; color: white; }
        .btn-primary:hover { background: #166fe5; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
        .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .badge-admin { background: #ffc107; color: #212529; }
        .badge-self { background: #17a2b8; color: white; }
        code { background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: ui-monospace, monospace; font-size: 0.85rem; }
        #userDetail { display: none; margin-top: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6; }
        .cred-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; margin: 0.25rem 0; background: white; border-radius: 4px; border: 1px solid #dee2e6; }
        .back-link { color: #1877f2; text-decoration: none; font-size: 0.9rem; }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1>2FA Admin Panel</h1>
            <a href="%sregister" class="back-link">&larr; Back to Register</a>
        </div>

        <div class="info">
            <strong>Logged in as:</strong> <code>%s</code> <span class="badge badge-admin">Admin</span>
        </div>

        <div id="successMsg" class="success"></div>
        <div id="errorMsg" class="error"></div>

        <h2>Registered Users</h2>
        <table id="usersTable">
            <thead><tr><th>Identity</th><th>Credentials</th><th>Role</th><th>Actions</th></tr></thead>
            <tbody id="usersBody"><tr><td colspan="4">Loading...</td></tr></tbody>
        </table>

        <div id="userDetail">
            <h2>Credentials for <code id="detailIdentity"></code></h2>
            <div id="credList"></div>
            <button class="btn-secondary btn-sm" onclick="closeDetail()" style="margin-top: 1rem;">Close</button>
        </div>
    </div>

    <script>
        const API_PREFIX = "%s";
        const SELF_IDENTITY = "%s";

        function showSuccess(msg) {
            const el = document.getElementById('successMsg');
            el.innerText = msg; el.style.display = 'block';
            document.getElementById('errorMsg').style.display = 'none';
            setTimeout(() => { el.style.display = 'none'; }, 3000);
        }

        function showError(msg) {
            const el = document.getElementById('errorMsg');
            el.innerText = msg; el.style.display = 'block';
            document.getElementById('successMsg').style.display = 'none';
        }

        async function loadUsers() {
            try {
                const resp = await fetch(API_PREFIX + 'admin/users');
                if (!resp.ok) { showError('Failed to load users'); return; }
                const data = await resp.json();
                renderUsers(data.users, data.admins);
            } catch (err) { showError('Error: ' + err.message); }
        }

        function renderUsers(users, admins) {
            const tbody = document.getElementById('usersBody');
            tbody.innerHTML = '';
            const adminSet = new Set((admins || []).map(a => a.toLowerCase()));

            const identities = Object.keys(users).sort();
            if (identities.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="color: #999;">No users registered</td></tr>';
                return;
            }

            for (const id of identities) {
                const creds = Array.isArray(users[id]) ? users[id] : [users[id]];
                const isAdmin = adminSet.has(id.toLowerCase());
                const isSelf = id.toLowerCase() === SELF_IDENTITY.toLowerCase();
                const tr = document.createElement('tr');

                let badges = '';
                if (isAdmin) badges += '<span class="badge badge-admin">Admin</span> ';
                if (isSelf) badges += '<span class="badge badge-self">You</span>';

                let actions = '<button class="btn-primary btn-sm" onclick="viewUser(\'' + escapeHtml(id) + '\')">View</button> ';
                if (!isSelf) {
                    if (isAdmin) {
                        actions += '<button class="btn-secondary btn-sm" onclick="toggleAdmin(\'' + escapeHtml(id) + '\', false)">Remove Admin</button>';
                    } else {
                        actions += '<button class="btn-success btn-sm" onclick="toggleAdmin(\'' + escapeHtml(id) + '\', true)">Make Admin</button>';
                    }
                }

                tr.innerHTML = '<td><code>' + escapeHtml(id) + '</code></td>'
                    + '<td>' + creds.length + '</td>'
                    + '<td>' + badges + '</td>'
                    + '<td>' + actions + '</td>';
                tbody.appendChild(tr);
            }
        }

        async function viewUser(identity) {
            try {
                const resp = await fetch(API_PREFIX + 'admin/user?identity=' + encodeURIComponent(identity));
                if (!resp.ok) { showError('Failed to load user'); return; }
                const data = await resp.json();
                renderDetail(identity, data.credentials, data.isSelf);
            } catch (err) { showError('Error: ' + err.message); }
        }

        function renderDetail(identity, credentials, isSelf) {
            document.getElementById('detailIdentity').innerText = identity;
            const list = document.getElementById('credList');
            list.innerHTML = '';

            const creds = Array.isArray(credentials) ? credentials : (credentials ? [credentials] : []);
            creds.forEach((cred, idx) => {
                const div = document.createElement('div');
                div.className = 'cred-item';
                let label = '';
                if (typeof cred === 'string') {
                    label = 'TOTP: ' + cred.substring(0, 8) + '...';
                } else if (cred && cred.totp) {
                    label = 'TOTP: ' + cred.totp.substring(0, 8) + '...';
                } else if (cred && cred.credentialId) {
                    label = 'Passkey: ' + cred.credentialId.substring(0, 16) + '...';
                } else {
                    label = JSON.stringify(cred).substring(0, 40) + '...';
                }

                let deleteBtn = '';
                if (!isSelf) {
                    deleteBtn = '<button class="btn-danger btn-sm" onclick="deleteCred(\'' + escapeHtml(identity) + '\', ' + idx + ')">Delete</button>';
                }

                div.innerHTML = '<span>' + escapeHtml(label) + '</span>' + deleteBtn;
                list.appendChild(div);
            });

            if (creds.length === 0) {
                list.innerHTML = '<p style="color: #999;">No credentials</p>';
            }

            document.getElementById('userDetail').style.display = 'block';
            document.getElementById('userDetail').scrollIntoView({ behavior: 'smooth' });
        }

        function closeDetail() {
            document.getElementById('userDetail').style.display = 'none';
        }

        async function deleteCred(identity, index) {
            if (!confirm('Delete credential #' + (index + 1) + ' for ' + identity + '?')) return;
            try {
                const resp = await fetch(API_PREFIX + 'admin/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ identity: identity, index: index })
                });
                if (resp.ok) {
                    showSuccess('Credential deleted');
                    loadUsers();
                    viewUser(identity);
                } else {
                    const text = await resp.text();
                    showError('Failed: ' + text);
                }
            } catch (err) { showError('Error: ' + err.message); }
        }

        async function toggleAdmin(identity, makeAdmin) {
            const action = makeAdmin ? 'grant admin to' : 'remove admin from';
            if (!confirm('Are you sure you want to ' + action + ' ' + identity + '?')) return;
            try {
                const resp = await fetch(API_PREFIX + 'admin/set-admin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ identity: identity, admin: makeAdmin })
                });
                if (resp.ok) {
                    showSuccess(makeAdmin ? identity + ' is now admin' : identity + ' admin removed');
                    loadUsers();
                } else {
                    const text = await resp.text();
                    showError('Failed: ' + text);
                }
            } catch (err) { showError('Error: ' + err.message); }
        }

        function escapeHtml(str) {
            const div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        }

        loadUsers();
    </script>
</body>
</html>
`, pathPrefix, callerIdentity, pathPrefix, callerIdentity)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := rw.Write([]byte(html)); err != nil {
		fmt.Printf("Error writing admin page: %v\n", err)
	}
}

func (a *MTlsOrWhitelist) handleAdminListUsers(rw http.ResponseWriter, req *http.Request) {
	callerIdentity, ok := a.isAdmin(req)
	if !ok {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	_ = callerIdentity

	users, err := a.userStore.ListUsers()
	if err != nil {
		http.Error(rw, "failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter out the admin store key from the user list
	filtered := make(map[string]interface{}, len(users))
	for k, v := range users {
		if k == adminStoreKey {
			continue
		}
		filtered[k] = v
	}

	admins := a.getAdmins()

	rw.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"users": filtered, "admins": admins}
	if encErr := json.NewEncoder(rw).Encode(resp); encErr != nil {
		fmt.Printf("[Admin] Failed to encode response: %v\n", encErr)
	}
}

func (a *MTlsOrWhitelist) handleAdminGetUser(rw http.ResponseWriter, req *http.Request) {
	callerIdentity, ok := a.isAdmin(req)
	if !ok {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}

	targetIdentity := req.URL.Query().Get("identity")
	if targetIdentity == "" {
		http.Error(rw, "missing identity parameter", http.StatusBadRequest)
		return
	}

	userData, found, err := a.userStore.GetUserData(targetIdentity)
	if err != nil {
		http.Error(rw, "failed to get user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(rw, "user not found", http.StatusNotFound)
		return
	}

	isSelf := strings.EqualFold(callerIdentity, targetIdentity)

	rw.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"identity": targetIdentity, "credentials": userData, "isSelf": isSelf}
	if encErr := json.NewEncoder(rw).Encode(resp); encErr != nil {
		fmt.Printf("[Admin] Failed to encode response: %v\n", encErr)
	}
}

//
//nolint:gocyclo // admin delete requires multiple authorization and validation checks
func (a *MTlsOrWhitelist) handleAdminDeleteCredential(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	callerIdentity, ok := a.isAdmin(req)
	if !ok {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}

	var delReq struct {
		Identity string `json:"identity"`
		Index    int    `json:"index"`
	}
	if err := json.NewDecoder(req.Body).Decode(&delReq); err != nil {
		http.Error(rw, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Cannot delete own credentials via admin panel
	if strings.EqualFold(callerIdentity, delReq.Identity) {
		http.Error(rw, "cannot delete own credentials via admin panel; use self-management", http.StatusForbidden)
		return
	}

	existing, found, err := a.userStore.GetUserData(delReq.Identity)
	if err != nil || !found {
		http.Error(rw, "user not found", http.StatusNotFound)
		return
	}

	credentials := a.toCredentialSlice(existing)
	if delReq.Index < 0 || delReq.Index >= len(credentials) {
		http.Error(rw, "index out of range", http.StatusBadRequest)
		return
	}

	// Check last-admin protection: if target is sole admin, keep at least one credential
	if a.isAdminIdentity(delReq.Identity) && len(credentials) == 1 {
		admins := a.getAdmins()
		if len(admins) == 1 && strings.EqualFold(admins[0], delReq.Identity) {
			http.Error(rw, "cannot delete last credential of the sole admin", http.StatusForbidden)
			return
		}
	}

	credentials = append(credentials[:delReq.Index], credentials[delReq.Index+1:]...)

	if len(credentials) == 0 {
		if saveErr := a.userStore.SetUserData(delReq.Identity, nil); saveErr != nil {
			http.Error(rw, "failed to save: "+saveErr.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if saveErr := a.userStore.SetUserData(delReq.Identity, credentials); saveErr != nil {
			http.Error(rw, "failed to save: "+saveErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"status": "ok", "remaining": len(credentials)}
	if encErr := json.NewEncoder(rw).Encode(resp); encErr != nil {
		fmt.Printf("[Admin] Failed to encode response: %v\n", encErr)
	}
}

//
//nolint:gocyclo // admin set requires authorization, sole-admin check, and add/remove logic
func (a *MTlsOrWhitelist) handleAdminSetAdmin(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	callerIdentity, ok := a.isAdmin(req)
	if !ok {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}

	var adminReq struct {
		Identity string `json:"identity"`
		Admin    bool   `json:"admin"`
	}
	if err := json.NewDecoder(req.Body).Decode(&adminReq); err != nil {
		http.Error(rw, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Cannot remove self as admin if sole admin
	if !adminReq.Admin && strings.EqualFold(callerIdentity, adminReq.Identity) {
		admins := a.getAdmins()
		if len(admins) == 1 {
			http.Error(rw, "cannot remove sole admin", http.StatusForbidden)
			return
		}
	}

	admins := a.getAdmins()

	if adminReq.Admin {
		// Add to admin list (if not already)
		if !a.isAdminIdentity(adminReq.Identity) {
			admins = append(admins, adminReq.Identity)
		}
	} else {
		// Remove from admin list
		filtered := make([]string, 0, len(admins))
		for _, admin := range admins {
			if !strings.EqualFold(admin, adminReq.Identity) {
				filtered = append(filtered, admin)
			}
		}
		admins = filtered
	}

	if err := a.setAdmins(admins); err != nil {
		http.Error(rw, "failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"status": "ok", "identity": adminReq.Identity}
	if encErr := json.NewEncoder(rw).Encode(resp); encErr != nil {
		fmt.Printf("[Admin] Failed to encode response: %v\n", encErr)
	}
}
