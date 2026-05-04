(function() {
  'use strict';

  let authToken = sessionStorage.getItem('pat_monitor_token') || '';
  let report = null;
  let patSort = { col: 'owner_login', asc: true };
  let appSort = { col: 'app_name', asc: true };
  let ssoSort = { col: 'login', asc: true };
  let secretSort = { col: 'name', asc: true };
  let dkSort = { col: 'repo_name', asc: true };
  let wpSort = { col: 'repo_name', asc: true };
  let wfSort = { col: 'repo_name', asc: true };
  let violSort = { col: 'severity', asc: true };

  // --- Auth ---

  function checkAuth() {
    return fetchJSON('/api/summary').then(function() {
      document.getElementById('auth-overlay').style.display = 'none';
      return true;
    }).catch(function(err) {
      if (err.status === 401) {
        document.getElementById('auth-overlay').style.display = 'flex';
        return false;
      }
      document.getElementById('auth-overlay').style.display = 'none';
      return true;
    });
  }

  document.getElementById('auth-submit').addEventListener('click', function() {
    authToken = document.getElementById('auth-input').value;
    sessionStorage.setItem('pat_monitor_token', authToken);
    checkAuth().then(function(ok) {
      if (ok) loadAll();
      else {
        var errEl = document.getElementById('auth-error');
        errEl.textContent = 'Invalid token';
        errEl.style.display = 'block';
      }
    });
  });

  document.getElementById('auth-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') document.getElementById('auth-submit').click();
  });

  // --- Fetch helper ---

  function fetchJSON(url) {
    var headers = { 'Accept': 'application/json' };
    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
    return fetch(url, { headers: headers }).then(function(resp) {
      if (!resp.ok) {
        var err = new Error(resp.statusText);
        err.status = resp.status;
        throw err;
      }
      return resp.json();
    });
  }

  // --- Load data ---

  function loadAll() {
    fetchJSON('/api/report').then(function(data) {
      report = data;
      renderSummary(data.summary);
      renderPATs(data.pats);
      renderApps(data.apps);
      renderRequests(data.pending_requests);
      renderSSOCredentials(data.sso_credentials);
      renderSecrets(data.secrets);
      renderDeployKeys(data.deploy_keys);
      renderWorkflowPerms(data.workflow_permissions);
      renderWorkflowFiles(data.workflow_files);
      document.getElementById('org-name').textContent = data.org;
      document.getElementById('scan-time').textContent =
        ' | Last scan: ' + new Date(data.scanned_at).toLocaleString();
    }).catch(function(err) {
      console.error('Failed to load report:', err);
    });

    // Load violations separately
    fetchJSON('/api/violations').then(function(data) {
      renderViolations(data);
    }).catch(function() {});
  }

  // --- Summary ---

  function renderSummary(s) {
    var container = document.getElementById('summary-cards');
    container.innerHTML = '';

    var cards = [
      { label: 'Total PATs', value: s.total_pats, detail: s.active_pats + ' active, ' + s.expired_pats + ' expired', cls: '' },
      { label: 'Expiring Soon', value: s.expiring_soon, detail: 'Within 30 days', cls: s.expiring_soon > 0 ? 'warn' : '' },
      { label: 'Installed Apps', value: s.total_apps, detail: s.high_risk_apps + ' with high-risk perms', cls: s.high_risk_apps > 0 ? 'danger' : '' },
      { label: 'Pending Requests', value: s.pending_requests, detail: 'Awaiting approval', cls: s.pending_requests > 0 ? 'warn' : '' },
      { label: 'All-Repo Access', value: s.all_repo_access_pats + s.all_repo_access_apps, detail: s.all_repo_access_pats + ' PATs, ' + s.all_repo_access_apps + ' Apps', cls: (s.all_repo_access_pats + s.all_repo_access_apps) > 0 ? 'danger' : '' },
      { label: 'SSO Credentials', value: s.sso_credentials, detail: s.sso_classic_pats + ' classic PATs, ' + s.sso_ssh_keys + ' SSH keys', cls: s.sso_classic_pats > 0 ? 'warn' : '' },
      { label: 'Secrets', value: s.total_secrets, detail: s.org_secrets + ' org-level, ' + s.org_wide_secrets + ' org-wide', cls: s.org_wide_secrets > 0 ? 'danger' : '' },
      { label: 'Deploy Keys', value: s.total_deploy_keys, detail: s.write_deploy_keys + ' with write access', cls: s.write_deploy_keys > 0 ? 'danger' : '' },
      { label: 'GITHUB_TOKEN Write', value: s.write_all_workflows, detail: 'Repos with write-all default', cls: s.write_all_workflows > 0 ? 'danger' : '' },
      { label: 'Unpinned Actions', value: s.unpinned_action_repos, detail: 'Repos with tag-based refs', cls: s.unpinned_action_repos > 0 ? 'warn' : '' },
    ];

    cards.forEach(function(c) {
      var card = document.createElement('div');
      card.className = 'card ' + c.cls;

      var label = document.createElement('div');
      label.className = 'label';
      label.textContent = c.label;

      var value = document.createElement('div');
      value.className = 'value';
      value.textContent = c.value;

      var detail = document.createElement('div');
      detail.className = 'detail';
      detail.textContent = c.detail;

      card.appendChild(label);
      card.appendChild(value);
      card.appendChild(detail);
      container.appendChild(card);
    });
  }

  // --- Generic sortable table ---

  function sortData(data, sortState) {
    return data.slice().sort(function(a, b) {
      var va = a[sortState.col] || '';
      var vb = b[sortState.col] || '';
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortState.asc ? -1 : 1;
      if (va > vb) return sortState.asc ? 1 : -1;
      return 0;
    });
  }

  function buildHeader(cols, sortState, rerenderFn) {
    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    cols.forEach(function(col) {
      var th = document.createElement('th');
      th.textContent = col.label;
      if (col.key) {
        var arrow = document.createElement('span');
        arrow.className = 'sort-arrow';
        if (sortState.col === col.key) arrow.textContent = sortState.asc ? ' \u25B2' : ' \u25BC';
        th.appendChild(arrow);
        th.addEventListener('click', function() {
          if (sortState.col === col.key) sortState.asc = !sortState.asc;
          else { sortState.col = col.key; sortState.asc = true; }
          rerenderFn();
        });
      }
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    return thead;
  }

  // --- PATs Table ---

  function renderPATs(pats) {
    if (!pats) pats = [];
    var sorted = sortData(pats, patSort);
    var table = document.getElementById('pats-table');
    table.innerHTML = '';

    var cols = [
      { key: 'owner_login', label: 'Owner' },
      { key: 'token_name', label: 'Token Name' },
      { key: 'repository_selection', label: 'Repo Access' },
      { key: '', label: 'Permissions' },
      { key: 'token_expires_at', label: 'Expires' },
      { key: 'token_last_used_at', label: 'Last Used' },
      { key: 'token_expired', label: 'Status' },
    ];

    table.appendChild(buildHeader(cols, patSort, function() { renderPATs(report.pats); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(p) {
      var tr = document.createElement('tr');
      tr.className = 'expandable';

      addCell(tr, p.owner_login);
      addCell(tr, p.token_name);
      addCell(tr, p.repository_selection);

      var permCell = document.createElement('td');
      renderPermBadges(permCell, p.permissions);
      tr.appendChild(permCell);

      addCell(tr, p.token_expires_at ? new Date(p.token_expires_at).toLocaleDateString() : 'Never');
      addCell(tr, p.token_last_used_at ? new Date(p.token_last_used_at).toLocaleDateString() : 'Never');

      var statusCell = document.createElement('td');
      var statusSpan = document.createElement('span');
      statusSpan.textContent = p.token_expired ? 'Expired' : 'Active';
      statusSpan.className = p.token_expired ? 'status-expired' : 'status-active';
      statusCell.appendChild(statusSpan);
      tr.appendChild(statusCell);

      tr.addEventListener('click', function() {
        var next = tr.nextElementSibling;
        if (next && next.classList.contains('repo-row')) {
          next.remove();
          return;
        }
        var expandRow = document.createElement('tr');
        expandRow.className = 'repo-row';
        var expandCell = document.createElement('td');
        expandCell.colSpan = 7;
        expandCell.textContent = 'Loading repositories...';
        expandRow.appendChild(expandCell);
        tr.after(expandRow);

        fetchJSON('/api/pats/' + p.id + '/repos').then(function(repos) {
          expandCell.textContent = '';
          var div = document.createElement('div');
          div.className = 'repo-list';
          if (!repos || repos.length === 0) {
            div.textContent = 'No specific repositories (or access to all)';
          } else {
            var ul = document.createElement('ul');
            repos.forEach(function(r) {
              var li = document.createElement('li');
              li.textContent = r.full_name;
              if (r.private) li.className = 'private';
              ul.appendChild(li);
            });
            div.appendChild(ul);
          }
          expandCell.appendChild(div);
        }).catch(function() {
          expandCell.textContent = 'Failed to load repositories';
        });
      });

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Apps Table ---

  function renderApps(apps) {
    if (!apps) apps = [];
    var sorted = sortData(apps, appSort);
    var table = document.getElementById('apps-table');
    table.innerHTML = '';

    var cols = [
      { key: 'app_name', label: 'App Name' },
      { key: 'repository_selection', label: 'Repo Access' },
      { key: 'high_risk_count', label: 'High Risk' },
      { key: 'medium_risk_count', label: 'Medium' },
      { key: 'low_risk_count', label: 'Low' },
      { key: '', label: 'Events' },
      { key: 'created_at', label: 'Installed' },
      { key: 'suspended', label: 'Status' },
    ];

    table.appendChild(buildHeader(cols, appSort, function() { renderApps(report.apps); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(a) {
      var tr = document.createElement('tr');
      addCell(tr, a.app_name);
      addCell(tr, a.repository_selection);
      addCell(tr, String(a.high_risk_count));
      addCell(tr, String(a.medium_risk_count));
      addCell(tr, String(a.low_risk_count));
      addCell(tr, (a.events || []).join(', '));
      addCell(tr, new Date(a.created_at).toLocaleDateString());

      var statusCell = document.createElement('td');
      var statusSpan = document.createElement('span');
      statusSpan.textContent = a.suspended ? 'Suspended' : 'Active';
      statusSpan.className = a.suspended ? 'status-suspended' : 'status-active';
      statusCell.appendChild(statusSpan);
      tr.appendChild(statusCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Pending Requests ---

  function renderRequests(requests) {
    var section = document.getElementById('requests-section');
    if (!requests || requests.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var table = document.getElementById('requests-table');
    table.innerHTML = '';

    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    ['Owner', 'Token Name', 'Repo Access', 'Permissions', 'Requested', 'Actions'].forEach(function(label) {
      var th = document.createElement('th');
      th.textContent = label;
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    requests.forEach(function(r) {
      var tr = document.createElement('tr');
      addCell(tr, r.owner_login);
      addCell(tr, r.token_name);
      addCell(tr, r.repository_selection);

      var permCell = document.createElement('td');
      renderPermBadges(permCell, r.permissions);
      tr.appendChild(permCell);

      addCell(tr, new Date(r.created_at).toLocaleDateString());

      var actionsCell = document.createElement('td');
      var approveBtn = document.createElement('button');
      approveBtn.className = 'action-btn approve';
      approveBtn.textContent = 'Approve';
      approveBtn.addEventListener('click', function() { reviewPATRequest(r.id, 'approve'); });
      actionsCell.appendChild(approveBtn);

      var denyBtn = document.createElement('button');
      denyBtn.className = 'action-btn deny';
      denyBtn.textContent = 'Deny';
      denyBtn.addEventListener('click', function() { reviewPATRequest(r.id, 'deny'); });
      actionsCell.appendChild(denyBtn);
      tr.appendChild(actionsCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- SSO Credentials ---

  function renderSSOCredentials(creds) {
    var section = document.getElementById('sso-section');
    if (!creds || creds.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(creds, ssoSort);
    var table = document.getElementById('sso-table');
    table.innerHTML = '';

    var cols = [
      { key: 'login', label: 'Owner' },
      { key: 'credential_type', label: 'Type' },
      { key: 'authorized_credential_title', label: 'Title' },
      { key: 'token_last_eight', label: 'Token (last 8)' },
      { key: '', label: 'Scopes' },
      { key: 'credential_authorized_at', label: 'Authorized' },
      { key: 'credential_accessed_at', label: 'Last Accessed' },
      { key: 'authorized_credential_expires_at', label: 'Expires' },
    ];

    table.appendChild(buildHeader(cols, ssoSort, function() { renderSSOCredentials(report.sso_credentials); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(c) {
      var tr = document.createElement('tr');

      addCell(tr, c.login);

      var typeCell = document.createElement('td');
      var typeBadge = document.createElement('span');
      typeBadge.className = 'badge ' + (c.credential_type === 'personal access token' ? 'medium' : 'low');
      typeBadge.textContent = c.credential_type;
      typeCell.appendChild(typeBadge);
      tr.appendChild(typeCell);

      addCell(tr, c.authorized_credential_title || '-');
      addCell(tr, c.token_last_eight || c.fingerprint || '-');

      var scopeCell = document.createElement('td');
      if (c.scopes && c.scopes.length > 0) {
        c.scopes.forEach(function(scope) {
          var badge = document.createElement('span');
          var highScopes = ['admin:org', 'repo', 'admin:repo_hook', 'delete_repo', 'admin:org_hook', 'admin:gpg_key', 'admin:ssh_signing_key'];
          var risk = highScopes.indexOf(scope) !== -1 ? 'high' : 'low';
          badge.className = 'badge ' + risk;
          badge.textContent = scope;
          scopeCell.appendChild(badge);
        });
      } else {
        scopeCell.textContent = '-';
      }
      tr.appendChild(scopeCell);

      addCell(tr, c.credential_authorized_at ? new Date(c.credential_authorized_at).toLocaleDateString() : '-');
      addCell(tr, c.credential_accessed_at ? new Date(c.credential_accessed_at).toLocaleDateString() : 'Never');
      addCell(tr, c.authorized_credential_expires_at ? new Date(c.authorized_credential_expires_at).toLocaleDateString() : 'Never');

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Secrets ---

  function renderSecrets(secrets) {
    var section = document.getElementById('secrets-section');
    if (!secrets || secrets.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(secrets, secretSort);
    var table = document.getElementById('secrets-table');
    table.innerHTML = '';

    var cols = [
      { key: 'name', label: 'Secret Name' },
      { key: 'scope', label: 'Scope' },
      { key: 'repo_name', label: 'Repository' },
      { key: 'env_name', label: 'Environment' },
      { key: 'visibility', label: 'Visibility' },
      { key: 'updated_at', label: 'Last Updated' },
      { key: 'risk', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, secretSort, function() { renderSecrets(report.secrets); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(s) {
      var tr = document.createElement('tr');
      addCell(tr, s.name);

      var scopeCell = document.createElement('td');
      var scopeBadge = document.createElement('span');
      scopeBadge.className = 'badge ' + (s.scope === 'org' ? 'high' : 'low');
      scopeBadge.textContent = s.scope;
      scopeCell.appendChild(scopeBadge);
      tr.appendChild(scopeCell);

      addCell(tr, s.repo_name || '-');
      addCell(tr, s.env_name || '-');

      var visCell = document.createElement('td');
      if (s.visibility) {
        var visBadge = document.createElement('span');
        visBadge.className = 'badge ' + (s.visibility === 'all' ? 'high' : s.visibility === 'private' ? 'medium' : 'low');
        visBadge.textContent = s.visibility;
        visCell.appendChild(visBadge);
      } else {
        visCell.textContent = '-';
      }
      tr.appendChild(visCell);

      addCell(tr, s.updated_at ? new Date(s.updated_at).toLocaleDateString() : '-');

      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'badge ' + s.risk;
      riskBadge.textContent = s.risk;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Deploy Keys ---

  function renderDeployKeys(keys) {
    var section = document.getElementById('deploy-keys-section');
    if (!keys || keys.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(keys, dkSort);
    var table = document.getElementById('deploy-keys-table');
    table.innerHTML = '';

    var cols = [
      { key: 'repo_name', label: 'Repository' },
      { key: 'title', label: 'Key Title' },
      { key: 'read_only', label: 'Access' },
      { key: 'added_by', label: 'Added By' },
      { key: 'created_at', label: 'Created' },
      { key: 'last_used', label: 'Last Used' },
      { key: 'risk', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, dkSort, function() { renderDeployKeys(report.deploy_keys); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(k) {
      var tr = document.createElement('tr');
      addCell(tr, k.repo_name);
      addCell(tr, k.title);

      var accessCell = document.createElement('td');
      var accessBadge = document.createElement('span');
      accessBadge.className = 'badge ' + (k.read_only ? 'low' : 'high');
      accessBadge.textContent = k.read_only ? 'read-only' : 'read-write';
      accessCell.appendChild(accessBadge);
      tr.appendChild(accessCell);

      addCell(tr, k.added_by || '-');
      addCell(tr, k.created_at ? new Date(k.created_at).toLocaleDateString() : '-');
      addCell(tr, k.last_used ? new Date(k.last_used).toLocaleDateString() : 'Never');

      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'badge ' + k.risk;
      riskBadge.textContent = k.risk;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Workflow Permissions ---

  function renderWorkflowPerms(perms) {
    var section = document.getElementById('workflow-perms-section');
    if (!perms || perms.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(perms, wpSort);
    var table = document.getElementById('workflow-perms-table');
    table.innerHTML = '';

    var cols = [
      { key: 'repo_name', label: 'Repository' },
      { key: 'default_permission', label: 'Default Permission' },
      { key: 'can_approve_pull_requests', label: 'Can Approve PRs' },
      { key: 'risk', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, wpSort, function() { renderWorkflowPerms(report.workflow_permissions); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(wp) {
      var tr = document.createElement('tr');
      addCell(tr, wp.repo_name);

      var permCell = document.createElement('td');
      var permBadge = document.createElement('span');
      permBadge.className = 'badge ' + (wp.default_permission === 'write' ? 'high' : 'low');
      permBadge.textContent = wp.default_permission;
      permCell.appendChild(permBadge);
      tr.appendChild(permCell);

      var prCell = document.createElement('td');
      var prBadge = document.createElement('span');
      prBadge.className = 'badge ' + (wp.can_approve_pull_requests ? 'medium' : 'low');
      prBadge.textContent = wp.can_approve_pull_requests ? 'Yes' : 'No';
      prCell.appendChild(prBadge);
      tr.appendChild(prCell);

      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'badge ' + wp.risk;
      riskBadge.textContent = wp.risk;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Workflow Files Audit ---

  function renderWorkflowFiles(files) {
    var section = document.getElementById('workflow-files-section');
    if (!files || files.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(files, wfSort);
    var table = document.getElementById('workflow-files-table');
    table.innerHTML = '';

    var cols = [
      { key: 'repo_name', label: 'Repository' },
      { key: 'file_name', label: 'Workflow' },
      { key: 'permissions', label: 'Permissions' },
      { key: 'has_pinned_actions', label: 'Actions Pinned' },
      { key: '', label: 'Unpinned Actions' },
      { key: 'risk', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, wfSort, function() { renderWorkflowFiles(report.workflow_files); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(wf) {
      var tr = document.createElement('tr');
      addCell(tr, wf.repo_name);
      addCell(tr, wf.file_name);

      var permCell = document.createElement('td');
      var permBadge = document.createElement('span');
      var permRisk = (wf.permissions === 'write-all' || wf.permissions === 'not set') ? 'high' : 'low';
      permBadge.className = 'badge ' + permRisk;
      permBadge.textContent = wf.permissions;
      permCell.appendChild(permBadge);
      tr.appendChild(permCell);

      var pinnedCell = document.createElement('td');
      var pinnedBadge = document.createElement('span');
      pinnedBadge.className = 'badge ' + (wf.has_pinned_actions ? 'low' : 'medium');
      pinnedBadge.textContent = wf.has_pinned_actions ? 'Yes' : 'No';
      pinnedCell.appendChild(pinnedBadge);
      tr.appendChild(pinnedCell);

      var unpinnedCell = document.createElement('td');
      if (wf.unpinned_actions && wf.unpinned_actions.length > 0) {
        wf.unpinned_actions.forEach(function(a) {
          var badge = document.createElement('span');
          badge.className = 'badge medium';
          badge.textContent = a;
          unpinnedCell.appendChild(badge);
        });
      } else {
        unpinnedCell.textContent = '-';
      }
      tr.appendChild(unpinnedCell);

      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'badge ' + wf.risk;
      riskBadge.textContent = wf.risk;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Violations ---

  function renderViolations(violations) {
    var section = document.getElementById('violations-section');
    if (!violations || violations.length === 0) {
      section.style.display = 'none';
      return;
    }
    section.style.display = 'block';

    var sorted = sortData(violations, violSort);
    var table = document.getElementById('violations-table');
    table.innerHTML = '';

    var cols = [
      { key: 'severity', label: 'Severity' },
      { key: 'rule', label: 'Rule' },
      { key: 'resource', label: 'Resource' },
      { key: 'message', label: 'Message' },
    ];

    table.appendChild(buildHeader(cols, violSort, function() { renderViolations(violations); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(v) {
      var tr = document.createElement('tr');

      var sevCell = document.createElement('td');
      var sevBadge = document.createElement('span');
      sevBadge.className = 'badge ' + v.severity;
      sevBadge.textContent = v.severity.toUpperCase();
      sevCell.appendChild(sevBadge);
      tr.appendChild(sevCell);

      addCell(tr, v.rule);
      addCell(tr, v.resource);
      addCell(tr, v.message);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Helpers ---

  function addCell(tr, text) {
    var td = document.createElement('td');
    td.textContent = text;
    tr.appendChild(td);
  }

  function renderPermBadges(container, perms) {
    if (!perms || perms.length === 0) {
      container.textContent = 'none';
      return;
    }
    perms.forEach(function(p) {
      var badge = document.createElement('span');
      badge.className = 'badge ' + p.risk;
      badge.textContent = p.name + ':' + p.level;
      container.appendChild(badge);
    });
  }

  // --- Filter ---

  function setupFilter(inputId, renderFn, dataKey) {
    document.getElementById(inputId).addEventListener('input', function(e) {
      var query = e.target.value.toLowerCase();
      if (!report) return;
      var data = report[dataKey] || [];
      if (!query) { renderFn(data); return; }
      var filtered = data.filter(function(item) {
        return JSON.stringify(item).toLowerCase().indexOf(query) !== -1;
      });
      renderFn(filtered);
    });
  }

  setupFilter('pats-filter', renderPATs, 'pats');
  setupFilter('apps-filter', renderApps, 'apps');
  setupFilter('sso-filter', renderSSOCredentials, 'sso_credentials');
  setupFilter('secrets-filter', renderSecrets, 'secrets');
  setupFilter('deploy-keys-filter', renderDeployKeys, 'deploy_keys');
  setupFilter('workflow-perms-filter', renderWorkflowPerms, 'workflow_permissions');
  setupFilter('workflow-files-filter', renderWorkflowFiles, 'workflow_files');

  // Violations filter loads from API, not report
  document.getElementById('violations-filter').addEventListener('input', function(e) {
    var query = e.target.value.toLowerCase();
    fetchJSON('/api/violations').then(function(data) {
      if (!query) { renderViolations(data); return; }
      var filtered = data.filter(function(item) {
        return JSON.stringify(item).toLowerCase().indexOf(query) !== -1;
      });
      renderViolations(filtered);
    });
  });

  // --- Rescan ---

  document.getElementById('rescan-btn').addEventListener('click', function() {
    var btn = document.getElementById('rescan-btn');
    btn.disabled = true;
    btn.textContent = 'Scanning...';

    var headers = { 'Accept': 'application/json' };
    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;

    fetch('/api/scan', { method: 'POST', headers: headers }).then(function(resp) {
      if (!resp.ok) throw new Error(resp.statusText);
      return resp.json();
    }).then(function(data) {
      report = data;
      renderSummary(data.summary);
      renderPATs(data.pats);
      renderApps(data.apps);
      renderRequests(data.pending_requests);
      renderSSOCredentials(data.sso_credentials);
      renderSecrets(data.secrets);
      renderDeployKeys(data.deploy_keys);
      renderWorkflowPerms(data.workflow_permissions);
      renderWorkflowFiles(data.workflow_files);
      document.getElementById('scan-time').textContent =
        ' | Last scan: ' + new Date(data.scanned_at).toLocaleString();

      // Reload violations
      fetchJSON('/api/violations').then(function(v) { renderViolations(v); });
    }).catch(function(err) {
      alert('Scan failed: ' + err.message);
    }).finally(function() {
      btn.disabled = false;
      btn.textContent = 'Rescan';
    });
  });

  // --- Compliance ---

  function loadCompliance() {
    fetchJSON('/api/compliance').then(function(checks) {
      renderCompliance(checks);
    }).catch(function() {});
  }

  function renderCompliance(checks) {
    var container = document.getElementById('compliance-cards');
    container.innerHTML = '';

    checks.forEach(function(c) {
      var card = document.createElement('div');
      card.className = 'compliance-card status-' + c.status;

      var header = document.createElement('div');
      header.className = 'cc-header';

      var dot = document.createElement('div');
      dot.className = 'cc-status ' + c.status;
      header.appendChild(dot);

      var title = document.createElement('div');
      title.className = 'cc-title';
      title.textContent = c.name;
      header.appendChild(title);

      card.appendChild(header);

      var desc = document.createElement('div');
      desc.className = 'cc-desc';
      desc.textContent = c.description;
      card.appendChild(desc);

      var detail = document.createElement('div');
      detail.className = 'cc-detail';
      detail.textContent = c.detail;
      card.appendChild(detail);

      if (c.fix_url && c.status !== 'pass') {
        var fix = document.createElement('a');
        fix.className = 'cc-fix';
        fix.href = c.fix_url;
        fix.target = '_blank';
        fix.textContent = 'Fix in GitHub Settings \u2192';
        card.appendChild(fix);
      }

      container.appendChild(card);
    });
  }

  // --- Audit Log ---

  function loadAuditLog() {
    fetchJSON('/api/audit-log').then(function(data) {
      var statusEl = document.getElementById('audit-status');
      if (!data.available) {
        statusEl.innerHTML = '<div class="empty-state">Audit log requires GitHub Enterprise Cloud. Not available for this organization.</div>';
        document.getElementById('audit-table').style.display = 'none';
        return;
      }
      statusEl.innerHTML = '';
      document.getElementById('audit-table').style.display = '';
      renderAuditLog(data.entries || []);
    }).catch(function() {
      document.getElementById('audit-status').innerHTML = '<div class="empty-state">Failed to load audit log.</div>';
    });
  }

  function renderAuditLog(entries) {
    var table = document.getElementById('audit-table');
    table.innerHTML = '';

    if (entries.length === 0) {
      table.innerHTML = '<tbody><tr><td class="empty-state" colspan="4">No PAT-related audit events found.</td></tr></tbody>';
      return;
    }

    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    ['Action', 'Actor', 'User', 'Time'].forEach(function(label) {
      var th = document.createElement('th');
      th.textContent = label;
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    entries.forEach(function(e) {
      var tr = document.createElement('tr');

      var actionCell = document.createElement('td');
      var actionBadge = document.createElement('span');
      var actionShort = e.action.replace('personal_access_token.', '');
      var actionRisk = 'low';
      if (actionShort === 'access_revoked' || actionShort === 'destroy') actionRisk = 'medium';
      if (actionShort === 'access_denied') actionRisk = 'high';
      if (actionShort === 'access_granted' || actionShort === 'create') actionRisk = 'low';
      actionBadge.className = 'badge ' + actionRisk;
      actionBadge.textContent = actionShort;
      actionCell.appendChild(actionBadge);
      tr.appendChild(actionCell);

      addCell(tr, e.actor || '-');
      addCell(tr, e.user || '-');
      addCell(tr, e.created_at ? new Date(e.created_at).toLocaleString() : '-');

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- PAT Actions (approve/deny/revoke) ---

  function reviewPATRequest(patId, action) {
    var headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;

    fetch('/api/pats/requests/' + patId + '/review', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ action: action })
    }).then(function(resp) {
      if (!resp.ok) throw new Error(resp.statusText);
      return resp.json();
    }).then(function() {
      // Reload data
      loadAll();
    }).catch(function(err) {
      alert('Failed to ' + action + ' PAT: ' + err.message);
    });
  }

  function revokePAT(patId) {
    if (!confirm('Revoke this PAT? This cannot be undone.')) return;

    var headers = { 'Accept': 'application/json' };
    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;

    fetch('/api/pats/' + patId + '/revoke', {
      method: 'POST',
      headers: headers
    }).then(function(resp) {
      if (!resp.ok) throw new Error(resp.statusText);
      return resp.json();
    }).then(function() {
      loadAll();
    }).catch(function(err) {
      alert('Failed to revoke PAT: ' + err.message);
    });
  }

  // --- Tab navigation ---

  document.getElementById('tab-nav').addEventListener('click', function(e) {
    var btn = e.target.closest('button');
    if (!btn) return;
    var tabId = btn.getAttribute('data-tab');
    if (!tabId) return;

    // Deactivate all tabs
    document.querySelectorAll('.tab-nav button').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });

    // Activate selected
    btn.classList.add('active');
    var target = document.getElementById(tabId);
    if (target) target.classList.add('active');
  });

  function updateTabCounts() {
    if (!report) return;

    setCount('count-pats', (report.pats || []).length);
    setCount('count-apps', (report.apps || []).length);

    var reqCount = (report.pending_requests || []).length;
    setCount('count-requests', reqCount);
    showTab('tab-requests', reqCount > 0);

    var ssoCount = (report.sso_credentials || []).length;
    setCount('count-sso', ssoCount);
    showTab('tab-sso', ssoCount > 0);

    var secCount = (report.secrets || []).length;
    setCount('count-secrets', secCount);
    showTab('tab-secrets', secCount > 0);

    var dkCount = (report.deploy_keys || []).length;
    setCount('count-deploy-keys', dkCount);
    showTab('tab-deploy-keys', dkCount > 0);

    var wpCount = (report.workflow_permissions || []).length;
    setCount('count-workflow-perms', wpCount);
    showTab('tab-workflow-perms', wpCount > 0);

    var wfCount = (report.workflow_files || []).length;
    setCount('count-workflow-files', wfCount);
    showTab('tab-workflow-files', wfCount > 0);
  }

  function setCount(id, count) {
    var el = document.getElementById(id);
    if (el) el.textContent = count;
  }

  function showTab(tabId, show) {
    var btn = document.querySelector('[data-tab="' + tabId + '"]');
    if (btn) btn.style.display = show ? '' : 'none';
  }

  function updateViolationCount(count) {
    setCount('count-violations', count);
    showTab('tab-violations', count > 0);
  }

  // Override loadAll to also update tab counts and load compliance/audit
  var _origLoadAll = loadAll;
  loadAll = function() {
    fetchJSON('/api/report').then(function(data) {
      report = data;
      renderSummary(data.summary);
      renderPATs(data.pats);
      renderApps(data.apps);
      renderRequests(data.pending_requests);
      renderSSOCredentials(data.sso_credentials);
      renderSecrets(data.secrets);
      renderDeployKeys(data.deploy_keys);
      renderWorkflowPerms(data.workflow_permissions);
      renderWorkflowFiles(data.workflow_files);
      document.getElementById('org-name').textContent = data.org;
      document.getElementById('scan-time').textContent =
        ' | Last scan: ' + new Date(data.scanned_at).toLocaleString();
      updateTabCounts();
    }).catch(function(err) {
      console.error('Failed to load report:', err);
    });

    fetchJSON('/api/violations').then(function(data) {
      renderViolations(data);
      updateViolationCount(data.length);
    }).catch(function() {});

    loadCompliance();
    loadAuditLog();
  };

  // --- Init ---
  checkAuth().then(function(ok) {
    if (ok) loadAll();
  });

})();
