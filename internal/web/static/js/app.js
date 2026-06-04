(function() {
  'use strict';

  let report = null;
  let diffData = null;

  // Default sorts: risk-first for risk-bearing tables
  let patSort  = { col: 'owner_login', asc: true };
  let appSort  = { col: 'high_risk_count', asc: false };
  let ssoSort  = { col: 'login', asc: true };
  let secretSort = { col: 'risk', asc: false };
  let dkSort   = { col: 'risk', asc: false };
  let wpSort   = { col: 'default_permission', asc: false };
  let wfSort   = { col: 'risk', asc: false };
  let violSort = { col: 'severity', asc: false };

  // --- Fetch helper (session cookie sent automatically) ---

  function fetchJSON(url) {
    return fetch(url, { headers: { 'Accept': 'application/json' } }).then(function(resp) {
      if (resp.status === 401) {
        window.location.href = '/login';
        throw new Error('session expired');
      }
      if (!resp.ok) {
        var err = new Error(resp.statusText);
        err.status = resp.status;
        throw err;
      }
      return resp.json();
    });
  }

  // --- Logout ---

  document.getElementById('logout-btn').addEventListener('click', function() {
    fetch('/auth/logout', { method: 'POST' }).finally(function() {
      window.location.href = '/login';
    });
  });

  // --- Scanning state ---

  function setScanningState(scanning) {
    var bar = document.getElementById('scan-progress-bar');
    var badge = document.getElementById('scan-status');
    var header = document.querySelector('header');
    var btn = document.getElementById('rescan-btn');
    if (scanning) {
      bar.style.display = 'block';
      badge.style.display = 'inline-block';
      header.classList.add('scanning');
      btn.disabled = true;
      btn.textContent = 'Scanning...';
    } else {
      bar.style.display = 'none';
      badge.style.display = 'none';
      header.classList.remove('scanning');
      btn.disabled = false;
      btn.textContent = 'Rescan';
    }
  }

  // --- Export ---

  window.exportCSV = function() {
    fetch('/api/export').then(function(resp) {
      if (resp.status === 401) { window.location.href = '/login'; return; }
      if (!resp.ok) throw new Error('Export failed');
      return resp.blob();
    }).then(function(blob) {
      if (!blob) return;
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'pat-monitor-export.csv';
      a.click();
      URL.revokeObjectURL(a.href);
    }).catch(function(err) {
      alert('Export failed: ' + err.message);
    });
  };

  // --- Load all data ---

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
        'Last scan\n' + new Date(data.scanned_at).toLocaleString();
      updateTabCounts();
    }).catch(function(err) {
      console.error('Failed to load report:', err);
    });

    fetchJSON('/api/violations').then(function(data) {
      renderViolations(data);
      updateViolationCount(data.length);
    }).catch(function() {});

    fetchJSON('/api/diff').then(function(data) {
      diffData = data;
      renderDiff(data);
    }).catch(function() {});

    loadCompliance();
  }

  // --- Diff section ---

  function renderDiff(diff) {
    var section = document.getElementById('diff-section');
    var content = document.getElementById('diff-content');
    var ts = document.getElementById('diff-timestamp');

    if (!diff || !diff.has_prev) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';

    if (diff.prev_scanned_at) {
      ts.textContent = 'vs ' + new Date(diff.prev_scanned_at).toLocaleString();
    }

    content.innerHTML = '';

    if (diff.total_changes === 0) {
      var noChange = document.createElement('span');
      noChange.className = 'diff-no-changes';
      noChange.textContent = 'No changes detected';
      content.appendChild(noChange);
      return;
    }

    function addDiffItem(kind, text) {
      var item = document.createElement('div');
      item.className = 'diff-item ' + kind;
      var dot = document.createElement('span');
      dot.className = 'diff-dot';
      item.appendChild(dot);
      var label = document.createElement('span');
      label.innerHTML = text;
      item.appendChild(label);
      content.appendChild(item);
    }

    var newPATs = (diff.new_pats || []).length;
    var removedPATs = (diff.removed_pats || []).length;
    var changedPATs = (diff.changed_pats || []).length;
    var newApps = (diff.new_apps || []).length;
    var removedApps = (diff.removed_apps || []).length;
    var newSecrets = (diff.new_secrets || []).length;
    var removedSecrets = (diff.removed_secrets || []).length;
    var newDKs = (diff.new_deploy_keys || []).length;

    if (newPATs > 0) addDiffItem('new', '<strong>' + newPATs + ' new PAT' + (newPATs > 1 ? 's' : '') + '</strong>');
    if (removedPATs > 0) addDiffItem('removed', '<strong>' + removedPATs + ' PAT' + (removedPATs > 1 ? 's' : '') + ' removed</strong>');
    if (changedPATs > 0) addDiffItem('changed', '<strong>' + changedPATs + ' PAT' + (changedPATs > 1 ? 's' : '') + ' changed</strong>');
    if (newApps > 0) addDiffItem('new', '<strong>' + newApps + ' new app' + (newApps > 1 ? 's' : '') + '</strong>');
    if (removedApps > 0) addDiffItem('removed', '<strong>' + removedApps + ' app' + (removedApps > 1 ? 's' : '') + ' removed</strong>');
    if (newSecrets > 0) addDiffItem('new', '<strong>' + newSecrets + ' new secret' + (newSecrets > 1 ? 's' : '') + '</strong>');
    if (removedSecrets > 0) addDiffItem('removed', '<strong>' + removedSecrets + ' secret' + (removedSecrets > 1 ? 's' : '') + ' removed</strong>');
    if (newDKs > 0) addDiffItem('new', '<strong>' + newDKs + ' new deploy key' + (newDKs > 1 ? 's' : '') + '</strong>');

    // Show changed PAT details inline
    if (diff.changed_pats && diff.changed_pats.length > 0) {
      diff.changed_pats.slice(0, 3).forEach(function(c) {
        addDiffItem('changed', c.pat.owner_login + '/<strong>' + c.pat.token_name + '</strong>: ' + c.changed_fields.join(', '));
      });
      if (diff.changed_pats.length > 3) {
        addDiffItem('changed', 'and ' + (diff.changed_pats.length - 3) + ' more changes');
      }
    }
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

  function riskWeight(r) { return { high: 3, medium: 2, low: 1 }[r] || 0; }

  function sortData(data, sortState) {
    return data.slice().sort(function(a, b) {
      var va = a[sortState.col];
      var vb = b[sortState.col];

      if (sortState.col === 'risk' || sortState.col === 'severity') {
        va = riskWeight(va);
        vb = riskWeight(vb);
      } else {
        va = va === null || va === undefined ? '' : va;
        vb = vb === null || vb === undefined ? '' : vb;
        if (typeof va === 'string') va = va.toLowerCase();
        if (typeof vb === 'string') vb = vb.toLowerCase();
      }

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
        if (sortState.col === col.key) arrow.textContent = sortState.asc ? ' ▲' : ' ▼';
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

  function isNewItem(id, entityType) {
    if (!diffData || !diffData.has_prev) return false;
    if (entityType === 'pat') return (diffData.new_pats || []).some(function(p) { return p.id === id; });
    if (entityType === 'app') return (diffData.new_apps || []).some(function(a) { return a.id === id; });
    if (entityType === 'secret') return (diffData.new_secrets || []).some(function(s) { return s.name === id; });
    if (entityType === 'deploy_key') return (diffData.new_deploy_keys || []).some(function(dk) { return dk.id === id; });
    return false;
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
      if (isNewItem(p.id, 'pat')) tr.classList.add('diff-new');

      addCell(tr, p.owner_login);
      addCell(tr, p.token_name);

      var repoCell = document.createElement('td');
      var repoBadge = document.createElement('span');
      repoBadge.className = 'badge ' + (p.repository_selection === 'all' ? 'high' : 'low');
      repoBadge.textContent = p.repository_selection;
      repoCell.appendChild(repoBadge);
      tr.appendChild(repoCell);

      var permCell = document.createElement('td');
      permCell.className = 'cell-wrap';
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
        if (next && next.classList.contains('repo-row')) { next.remove(); return; }
        var expandRow = document.createElement('tr');
        expandRow.className = 'repo-row';
        var expandCell = document.createElement('td');
        expandCell.colSpan = 8;
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
        }).catch(function() { expandCell.textContent = 'Failed to load repositories'; });
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
      if (isNewItem(a.id, 'app')) tr.classList.add('diff-new');

      addCell(tr, a.app_name);

      var repoCell = document.createElement('td');
      var repoBadge = document.createElement('span');
      repoBadge.className = 'badge ' + (a.repository_selection === 'all' ? 'high' : 'low');
      repoBadge.textContent = a.repository_selection;
      repoCell.appendChild(repoBadge);
      tr.appendChild(repoCell);

      var highCell = document.createElement('td');
      if (a.high_risk_count > 0) {
        var hb = document.createElement('span');
        hb.className = 'badge high';
        hb.textContent = a.high_risk_count;
        highCell.appendChild(hb);
      } else {
        highCell.textContent = '0';
      }
      tr.appendChild(highCell);

      addCell(tr, String(a.medium_risk_count));
      addCell(tr, String(a.low_risk_count));
      addCell(tr, (a.events || []).join(', ') || '-');
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
    var table = document.getElementById('requests-table');
    if (!requests || requests.length === 0) { table.innerHTML = ''; return; }
    table.innerHTML = '';

    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    ['Owner', 'Token Name', 'Repo Access', 'Permissions', 'Requested'].forEach(function(label) {
      var th = document.createElement('th'); th.textContent = label; headerRow.appendChild(th);
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
      permCell.className = 'cell-wrap';
      renderPermBadges(permCell, r.permissions);
      tr.appendChild(permCell);
      addCell(tr, new Date(r.created_at).toLocaleDateString());
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- SSO Credentials ---

  function renderSSOCredentials(creds) {
    if (!creds || creds.length === 0) return;

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
          var highScopes = ['admin:org', 'repo', 'admin:repo_hook', 'delete_repo', 'admin:org_hook'];
          badge.className = 'badge ' + (highScopes.indexOf(scope) !== -1 ? 'high' : 'low');
          badge.textContent = scope;
          scopeCell.appendChild(badge);
        });
      } else { scopeCell.textContent = '-'; }
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
    if (!secrets || secrets.length === 0) return;

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
      if (isNewItem(s.name, 'secret')) tr.classList.add('diff-new');
      addCell(tr, s.name);
      var scopeCell = document.createElement('td');
      var scopeBadge = document.createElement('span');
      scopeBadge.className = 'badge ' + (s.scope === 'org' ? 'medium' : 'low');
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
      } else { visCell.textContent = '-'; }
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
    if (!keys || keys.length === 0) return;

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
      if (isNewItem(k.id, 'deploy_key')) tr.classList.add('diff-new');
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
    if (!perms || perms.length === 0) return;

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
    if (!files || files.length === 0) return;

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
      permBadge.className = 'badge ' + ((wf.permissions === 'write-all' || wf.permissions === 'not set') ? 'high' : 'low');
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
        wf.unpinned_actions.slice(0, 3).forEach(function(a) {
          var badge = document.createElement('span');
          badge.className = 'badge medium';
          badge.textContent = a;
          unpinnedCell.appendChild(badge);
        });
        if (wf.unpinned_actions.length > 3) {
          var more = document.createElement('span');
          more.style.cssText = 'font-size:0.7rem;color:var(--text-dim);margin-left:4px';
          more.textContent = '+' + (wf.unpinned_actions.length - 3) + ' more';
          unpinnedCell.appendChild(more);
        }
      } else { unpinnedCell.textContent = '-'; }
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
    if (!violations || violations.length === 0) return;

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
    if (!perms || perms.length === 0) { container.textContent = 'none'; return; }
    var sorted = perms.slice().sort(function(a, b) { return riskWeight(b.risk) - riskWeight(a.risk); });
    sorted.forEach(function(p) {
      var badge = document.createElement('span');
      badge.className = 'badge ' + p.risk;
      badge.textContent = p.name + ':' + p.level;
      container.appendChild(badge);
    });
  }

  // --- Filters ---

  function setupFilter(inputId, renderFn, dataKey) {
    document.getElementById(inputId).addEventListener('input', function(e) {
      var query = e.target.value.toLowerCase();
      if (!report) return;
      var data = report[dataKey] || [];
      if (!query) { renderFn(data); return; }
      renderFn(data.filter(function(item) {
        return JSON.stringify(item).toLowerCase().indexOf(query) !== -1;
      }));
    });
  }

  setupFilter('pats-filter', renderPATs, 'pats');
  setupFilter('apps-filter', renderApps, 'apps');
  setupFilter('sso-filter', renderSSOCredentials, 'sso_credentials');
  setupFilter('secrets-filter', renderSecrets, 'secrets');
  setupFilter('deploy-keys-filter', renderDeployKeys, 'deploy_keys');
  setupFilter('workflow-perms-filter', renderWorkflowPerms, 'workflow_permissions');
  setupFilter('workflow-files-filter', renderWorkflowFiles, 'workflow_files');

  document.getElementById('violations-filter').addEventListener('input', function(e) {
    var query = e.target.value.toLowerCase();
    fetchJSON('/api/violations').then(function(data) {
      if (!query) { renderViolations(data); return; }
      renderViolations(data.filter(function(item) {
        return JSON.stringify(item).toLowerCase().indexOf(query) !== -1;
      }));
    });
  });

  // --- Rescan ---

  document.getElementById('rescan-btn').addEventListener('click', function() {
    setScanningState(true);

    fetch('/api/scan', { method: 'POST', headers: { 'Accept': 'application/json' } }).then(function(resp) {
      if (resp.status === 401) { window.location.href = '/login'; return; }
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
        'Last scan\n' + new Date(data.scanned_at).toLocaleString();
      updateTabCounts();

      // Reload violations and diff after scan
      fetchJSON('/api/violations').then(function(v) { renderViolations(v); updateViolationCount(v.length); });
      fetchJSON('/api/diff').then(function(d) { diffData = d; renderDiff(d); });
    }).catch(function(err) {
      alert('Scan failed: ' + err.message);
    }).finally(function() {
      setScanningState(false);
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

    var passCount = checks.filter(function(c) { return c.status === 'pass'; }).length;
    var scoreEl = document.getElementById('compliance-score');
    scoreEl.textContent = passCount + '/' + checks.length + ' passing';
    var failCount = checks.length - passCount;
    scoreEl.className = 'compliance-score ' + (failCount === 0 ? 'all-pass' : failCount > 3 ? 'many-fail' : 'some-fail');

    // Update compliance tab count
    var countEl = document.getElementById('count-compliance');
    if (countEl) {
      if (failCount > 0) {
        countEl.textContent = failCount;
        countEl.className = 'nav-badge warn';
      } else {
        countEl.textContent = passCount + '/' + checks.length;
        countEl.className = 'nav-badge';
      }
    }

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
        fix.textContent = 'Fix in GitHub Settings →';
        card.appendChild(fix);
      }
      container.appendChild(card);
    });
  }

  // --- Sidebar navigation ---

  document.getElementById('sidebar-nav').addEventListener('click', function(e) {
    var btn = e.target.closest('button.nav-item');
    if (!btn) return;
    var tabId = btn.getAttribute('data-tab');
    if (!tabId) return;
    document.querySelectorAll('.nav-item').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
    btn.classList.add('active');
    var target = document.getElementById(tabId);
    if (target) target.classList.add('active');
    var title = btn.getAttribute('data-title') || btn.textContent.trim();
    var titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = title;
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


  // --- Init ---
  loadAll();

})();
