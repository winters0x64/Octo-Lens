(function() {
  'use strict';

  let report = null;
  let diffData = null;
  let orgName = '';

  // Default sorts: risk-first for risk-bearing tables
  let patSort  = { col: 'owner_login', asc: true };
  let appSort  = { col: 'high_risk_count', asc: false };
  let ssoSort  = { col: 'login', asc: true };

  var PAGE_SIZE = 20;
  var appPage   = 1;
  var ssoPage   = 1;
  var ssoTypeFilter = '';   // '' = all, 'personal access token', 'ssh key'
  let secretSort = { col: 'risk', asc: false };
  let dkSort   = { col: 'risk', asc: false };
  let wpSort   = { col: 'default_permission', asc: false };
  let wfSort   = { col: 'risk', asc: false };
  let violSort = { col: 'severity', asc: false };

  // --- Fetch helper (session cookie sent automatically) ---

  function fetchJSON(url, opts) {
    var fetchOpts = Object.assign({ headers: { 'Accept': 'application/json' } }, opts || {});
    return fetch(url, fetchOpts).then(function(resp) {
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
    graphBuilt = false;
    if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
    fetchJSON('/api/report').then(function(data) {
      report = data;
      orgName = data.org;
      buildSupplyChainMap(data);
      renderSummary(data.summary);
      renderPATs(data.pats);
      appPage = 1; renderApps(data.apps);
      renderRequests(data.pending_requests);
      ssoPage = 1; renderSSOCredentials(data.sso_credentials);
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
      if (report) report.violations = data;
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

  // --- Overview Charts ---

  var chartInstances = {};

  var centerTextPlugin = {
    id: 'centerText',
    afterDraw: function(chart) {
      if (!chart.config.options.plugins.centerText) return;
      var text = chart.config.options.plugins.centerText.text;
      var sub = chart.config.options.plugins.centerText.sub || '';
      var ctx = chart.ctx;
      var centerX = (chart.chartArea.left + chart.chartArea.right) / 2;
      var centerY = (chart.chartArea.top + chart.chartArea.bottom) / 2;

      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '600 22px Inter, sans-serif';
      ctx.fillStyle = '#0f172a';
      ctx.fillText(text, centerX, sub ? centerY - 8 : centerY);
      if (sub) {
        ctx.font = '400 10px Inter, sans-serif';
        ctx.fillStyle = '#475569';
        ctx.fillText(sub, centerX, centerY + 12);
      }
      ctx.restore();
    }
  };

  function makeChart(canvasId, labels, data, colors, centerText, centerSub) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return;

    if (chartInstances[canvasId]) {
      chartInstances[canvasId].destroy();
    }

    var hasData = data.some(function(v) { return v > 0; });
    if (!hasData) {
      data = [1];
      labels = ['No data'];
      colors = ['#e2e8f0'];
    }

    chartInstances[canvasId] = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderWidth: 0,
          hoverBorderWidth: 2,
          hoverBorderColor: '#F0F4FF',
        }]
      },
      options: {
        cutout: '65%',
        responsive: true,
        maintainAspectRatio: true,
        animation: { animateRotate: true, duration: 800 },
        plugins: {
          centerText: { text: String(centerText), sub: centerSub || '' },
          legend: {
            position: 'bottom',
            labels: {
              color: '#475569',
              font: { size: 11, family: 'Inter, sans-serif' },
              padding: 10,
              usePointStyle: true,
              pointStyleWidth: 8,
            }
          },
          tooltip: {
            backgroundColor: '#ffffff',
            titleColor: '#0f172a',
            bodyColor: '#475569',
            borderColor: '#e2e8f0',
            borderWidth: 1,
            cornerRadius: 6,
            padding: 10,
            callbacks: {
              label: function(ctx) {
                var total = ctx.dataset.data.reduce(function(a, b) { return a + b; }, 0);
                var pct = total > 0 ? Math.round(ctx.raw / total * 100) : 0;
                return ' ' + ctx.label + ': ' + ctx.raw + ' (' + pct + '%)';
              }
            }
          }
        }
      },
      plugins: [centerTextPlugin]
    });
  }

  function renderOverviewCharts(s) {
    // 1. PAT Status
    makeChart('chart-pat-status',
      ['Active', 'Expired', 'Expiring Soon'],
      [s.active_pats, s.expired_pats, s.expiring_soon],
      ['#00E396', '#FF4560', '#FEB019'],
      s.total_pats, 'total'
    );

    // 2. Repository Access
    var allAccess = s.all_repo_access_pats + s.all_repo_access_apps;
    var selectedAccess = (s.total_pats - s.all_repo_access_pats) + (s.total_apps - s.all_repo_access_apps);
    makeChart('chart-repo-access',
      ['All Repos', 'Selected'],
      [allAccess, selectedAccess],
      ['#FF4560', '#00E396'],
      allAccess + selectedAccess, 'PATs + Apps'
    );

    // 3. Credential Landscape
    makeChart('chart-credentials',
      ['PATs', 'Apps', 'SSO Creds', 'Secrets', 'Deploy Keys'],
      [s.total_pats, s.total_apps, s.sso_credentials, s.total_secrets, s.total_deploy_keys],
      ['#2D7FF9', '#775DD0', '#00B4D8', '#FEB019', '#00E396'],
      s.total_pats + s.total_apps + s.sso_credentials + s.total_secrets + s.total_deploy_keys, 'credentials'
    );

    // 4. Security Posture
    var highRisk = s.all_repo_access_pats + s.all_repo_access_apps + s.write_deploy_keys + s.write_all_workflows + s.high_risk_apps;
    var medRisk = s.expiring_soon + s.unpinned_action_repos + s.org_wide_secrets;
    var totalIssues = highRisk + medRisk;
    var clean = Math.max(0, s.total_repos_scanned - s.write_all_workflows - s.unpinned_action_repos);
    makeChart('chart-posture',
      ['High Risk', 'Medium Risk', 'Clean'],
      [highRisk, medRisk, clean],
      ['#FF4560', '#FEB019', '#00E396'],
      totalIssues, 'issues'
    );
  }

  function renderSummary(s) {
    renderOverviewCharts(s);

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

  // --- PAT Risk Assessment Engine ---

  var HIGH_RISK_SCOPES = {
    administration: true, organization_administration: true, members: true,
    organization_secrets: true, secrets: true, security_events: true,
    actions: true, workflows: true, environments: true,
    organization_hooks: true, organization_plan: true
  };

  function daysBetween(a, b) { return Math.floor((b - a) / 86400000); }

  function timeAgo(dateStr) {
    if (!dateStr) return '';
    var diff = Date.now() - new Date(dateStr).getTime();
    var days = Math.floor(diff / 86400000);
    if (days < 1) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return days + ' day' + (days === 1 ? '' : 's') + ' ago';
    var months = Math.floor(days / 30);
    if (days < 365) return months + ' month' + (months === 1 ? '' : 's') + ' ago';
    var years = Math.floor(days / 365);
    return years + ' year' + (years === 1 ? '' : 's') + ' ago';
  }

  function timeUntil(dateStr) {
    if (!dateStr) return '';
    var diff = new Date(dateStr).getTime() - Date.now();
    var days = Math.floor(diff / 86400000);
    if (days < 0) { var abs = Math.abs(days); return abs + ' day' + (abs === 1 ? '' : 's') + ' ago'; }
    if (days === 0) return 'today';
    if (days === 1) return 'tomorrow';
    if (days < 30) return 'in ' + days + ' day' + (days === 1 ? '' : 's');
    var mo = Math.floor(days / 30);
    if (days < 365) return 'in ' + mo + ' month' + (mo === 1 ? '' : 's');
    var yr = Math.floor(days / 365);
    return 'in ' + yr + ' year' + (yr === 1 ? '' : 's');
  }

  // --- Supply Chain Cross-Reference Map ---
  var supplyChainMap = null;
  var cyInstance = null;
  var graphMode = 'explore';
  var graphEntityFilter = 'all';
  var graphRiskFilter = 'all';
  var graphBuilt = false;

  function buildSupplyChainMap(report) {
    var m = { repoToWorkflows: {}, repoToDeployKeys: {}, repoToSecrets: {}, orgSecrets: [], writeRepos: new Set(), totalRepos: 0 };
    m.totalRepos = (report.summary || {}).total_repos_scanned || 0;

    (report.workflow_files || []).forEach(function(wf) {
      if (!m.repoToWorkflows[wf.repo_name]) m.repoToWorkflows[wf.repo_name] = [];
      m.repoToWorkflows[wf.repo_name].push(wf);
      if (wf.permissions === 'write-all' || wf.permissions === 'not set') m.writeRepos.add(wf.repo_name);
    });

    (report.deploy_keys || []).forEach(function(dk) {
      if (!m.repoToDeployKeys[dk.repo_name]) m.repoToDeployKeys[dk.repo_name] = [];
      m.repoToDeployKeys[dk.repo_name].push(dk);
      if (!dk.read_only) m.writeRepos.add(dk.repo_name);
    });

    (report.secrets || []).forEach(function(s) {
      if (s.scope === 'org') {
        m.orgSecrets.push(s);
      } else {
        var key = s.repo_name || '__unknown__';
        if (!m.repoToSecrets[key]) m.repoToSecrets[key] = [];
        m.repoToSecrets[key].push(s);
      }
    });

    supplyChainMap = m;
  }

  // --- Risk Assessment Engines ---

  function assessPATRisk(pat) {
    var risks = [];
    var recs = [];
    var level = 'none';

    function bump(newLevel) {
      var w = { high: 3, medium: 2, low: 1, none: 0 };
      if ((w[newLevel] || 0) > (w[level] || 0)) level = newLevel;
    }

    if (pat.token_expired) return { level: 'none', risks: [], recommendations: [] };

    if (!pat.token_expires_at) {
      risks.push({ severity: 'high', message: 'No expiration date set' });
      recs.push({ action: 'Revoke', reason: 'Create a new token with a maximum 90-day expiry.', urgent: true });
      bump('high');
    }

    if (pat.repository_selection === 'all') {
      risks.push({ severity: 'high', message: 'Access to all organization repositories' });
      recs.push({ action: 'Reduce scope', reason: 'Limit access to only the repositories this token needs.', urgent: true });
      bump('high');
    }

    var hasAdmin = false;
    var highRiskWriteScopes = [];
    (pat.permissions || []).forEach(function(perm) {
      if (perm.level === 'admin') hasAdmin = true;
      if (perm.level === 'write' && HIGH_RISK_SCOPES[perm.name]) highRiskWriteScopes.push(perm.name);
    });

    if (hasAdmin) {
      risks.push({ severity: 'high', message: 'Has admin-level permissions' });
      recs.push({ action: 'Reduce permissions', reason: 'Admin access should be avoided unless absolutely necessary.', urgent: true });
      bump('high');
    }

    if (highRiskWriteScopes.length > 0 && !hasAdmin) {
      risks.push({ severity: 'medium', message: 'Write access on sensitive scopes: ' + highRiskWriteScopes.join(', ') });
      recs.push({ action: 'Review permissions', reason: 'Verify that write access to ' + highRiskWriteScopes.join(', ') + ' is required.', urgent: false });
      bump('medium');
    }

    if (!pat.token_last_used_at) {
      risks.push({ severity: 'medium', message: 'Token has never been used' });
      recs.push({ action: 'Revoke', reason: 'Unused tokens increase attack surface with no benefit.', urgent: false });
      bump('medium');
    } else {
      var inactiveDays = daysBetween(new Date(pat.token_last_used_at), new Date());
      if (inactiveDays > 90) {
        risks.push({ severity: 'medium', message: 'Inactive for ' + inactiveDays + ' days' });
        recs.push({ action: 'Revoke', reason: 'Token appears abandoned. Revoke if no longer needed.', urgent: false });
        bump('medium');
      } else if (inactiveDays > 30) {
        risks.push({ severity: 'low', message: 'Inactive for ' + inactiveDays + ' days' });
        recs.push({ action: 'Review', reason: 'Confirm this token is still actively needed.', urgent: false });
        bump('low');
      }
    }

    if (pat.token_expires_at) {
      var daysUntilExpiry = daysBetween(new Date(), new Date(pat.token_expires_at));
      if (daysUntilExpiry <= 7 && daysUntilExpiry > 0) {
        risks.push({ severity: 'medium', message: 'Expires in ' + daysUntilExpiry + ' days' });
        recs.push({ action: 'Rotate', reason: 'Create a replacement token before this one expires.', urgent: true });
        bump('medium');
      } else if (daysUntilExpiry > 90) {
        risks.push({ severity: 'low', message: 'Expiry set to ' + daysUntilExpiry + ' days from now' });
        recs.push({ action: 'Shorten expiry', reason: 'Best practice is to keep token expiry under 90 days.', urgent: false });
        bump('low');
      }
    }

    if (level === 'none') {
      recs.push({ action: 'No action needed', reason: 'This token follows security best practices.', urgent: false });
    }

    return { level: level, risks: risks, recommendations: recs };
  }

  function assessAppRisk(app) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (app.suspended) return { level: 'none', risks: [{ severity: 'low', message: 'App is currently suspended' }], recommendations: [{ action: 'No action needed', reason: 'This app is suspended and has no access.', urgent: false }] };

    if (app.repository_selection === 'all') {
      risks.push({ severity: 'high', message: 'Access to all organization repositories' });
      recs.push({ action: 'Restrict repos', reason: 'Limit to only required repositories to reduce blast radius.', urgent: true });
      bump('high');
    }

    var hasContentsWrite = false, hasWorkflowsWrite = false, hasSecretsAccess = false, hasOrgAdmin = false, hasAdmin = false;
    (app.permissions || []).forEach(function(p) {
      if (p.level === 'admin') hasAdmin = true;
      if (p.name === 'contents' && (p.level === 'write' || p.level === 'admin')) hasContentsWrite = true;
      if (p.name === 'workflows' && (p.level === 'write' || p.level === 'admin')) hasWorkflowsWrite = true;
      if ((p.name === 'organization_secrets' || p.name === 'secrets') && p.level !== 'none') hasSecretsAccess = true;
      if (p.name === 'organization_administration' && (p.level === 'write' || p.level === 'admin')) hasOrgAdmin = true;
    });

    if (hasContentsWrite) {
      risks.push({ severity: 'high', message: 'Can write to repository contents (code injection vector)' });
      recs.push({ action: 'Audit access', reason: 'Contents write allows pushing malicious code to repositories.', urgent: true });
      bump('high');
    }
    if (hasWorkflowsWrite) {
      risks.push({ severity: 'high', message: 'Can modify CI/CD workflows (pipeline hijacking)' });
      recs.push({ action: 'Review necessity', reason: 'Workflow write access enables build-time supply chain attacks.', urgent: true });
      bump('high');
    }
    if (hasSecretsAccess) {
      risks.push({ severity: 'high', message: 'Can access organization or repository secrets' });
      recs.push({ action: 'Limit scope', reason: 'Secrets access enables credential exfiltration.', urgent: true });
      bump('high');
    }
    if (hasOrgAdmin) {
      risks.push({ severity: 'high', message: 'Organization admin write access' });
      recs.push({ action: 'Reduce permissions', reason: 'Org admin can modify membership, billing, and security settings.', urgent: true });
      bump('high');
    }
    if (hasAdmin && !hasOrgAdmin) {
      risks.push({ severity: 'high', message: 'Has admin-level permissions' });
      recs.push({ action: 'Reduce permissions', reason: 'Admin access should only be granted when strictly necessary.', urgent: true });
      bump('high');
    }

    if (app.high_risk_count >= 3 && level !== 'high') {
      risks.push({ severity: 'high', message: 'Multiple high-risk permissions (' + app.high_risk_count + ')' });
      bump('high');
    }

    if (app.medium_risk_count > 0 && app.high_risk_count === 0) {
      risks.push({ severity: 'medium', message: app.medium_risk_count + ' medium-risk permission(s)' });
      bump('medium');
    }

    if (level === 'none') recs.push({ action: 'No action needed', reason: 'This app follows security best practices.', urgent: false });
    if (level === 'high' && !app.suspended) recs.push({ action: 'Suspend app', reason: 'Consider suspending until permissions are reviewed.', urgent: true });

    return { level: level, risks: risks, recommendations: recs };
  }

  var SENSITIVE_SECRET_PATTERNS = /^(AWS_|GH_|GITHUB_|SLACK_|DB_|DATABASE|PRIVATE_KEY|API_KEY|AUTH_|CREDENTIAL|DEPLOY_|NPM_TOKEN|DOCKER_|REGISTRY_|SSH_|SERVICE_ACCOUNT)/i;

  function assessSecretRisk(secret) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (secret.scope === 'org' && secret.visibility === 'all') {
      risks.push({ severity: 'high', message: 'Org-wide secret visible to ALL repositories' });
      recs.push({ action: 'Narrow visibility', reason: 'Limit to selected repos or move to environment-level.', urgent: true });
      bump('high');
    } else if (secret.scope === 'org' && secret.visibility === 'private') {
      risks.push({ severity: 'medium', message: 'Visible to all private repositories' });
      recs.push({ action: 'Review scope', reason: 'Consider limiting to selected repositories.', urgent: false });
      bump('medium');
    }

    if (secret.updated_at) {
      var staleDays = daysBetween(new Date(secret.updated_at), new Date());
      if (staleDays > 730) {
        risks.push({ severity: 'high', message: 'Not rotated in ' + Math.floor(staleDays / 365) + '+ years' });
        recs.push({ action: 'Rotate immediately', reason: 'Long-lived secrets are high-value targets for attackers.', urgent: true });
        bump('high');
      } else if (staleDays > 365) {
        risks.push({ severity: 'medium', message: 'Not rotated in over a year (' + staleDays + ' days)' });
        recs.push({ action: 'Rotate', reason: 'Best practice is to rotate secrets at least annually.', urgent: false });
        bump('medium');
      }
    }

    if (SENSITIVE_SECRET_PATTERNS.test(secret.name)) {
      risks.push({ severity: 'medium', message: 'Name suggests high-value credential (' + secret.name + ')' });
      if (level !== 'high') recs.push({ action: 'Use OIDC', reason: 'Replace long-lived secrets with short-lived OIDC tokens where possible.', urgent: false });
      bump('medium');
    }

    if (secret.scope === 'environment') {
      if (level === 'none') risks.push({ severity: 'low', message: 'Scoped to a specific environment (narrowest blast radius)' });
    }

    if (level === 'none') recs.push({ action: 'No action needed', reason: 'This secret follows best practices.', urgent: false });

    return { level: level, risks: risks, recommendations: recs };
  }

  function assessDeployKeyRisk(key) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (!key.read_only) {
      risks.push({ severity: 'high', message: 'Write access — can push code to ' + key.repo_name });
      recs.push({ action: 'Convert to read-only', reason: 'Write deploy keys can be used to inject malicious commits.', urgent: true });
      bump('high');
    }

    if (!key.last_used) {
      risks.push({ severity: 'medium', message: 'Deploy key has never been used' });
      recs.push({ action: 'Remove', reason: 'Unused deploy keys increase attack surface with no benefit.', urgent: false });
      bump('medium');
    } else {
      var inactiveDays = daysBetween(new Date(key.last_used), new Date());
      if (inactiveDays > 180) {
        risks.push({ severity: 'medium', message: 'Inactive for ' + inactiveDays + ' days' });
        recs.push({ action: 'Review', reason: 'Consider removing if this key is no longer needed.', urgent: false });
        bump('medium');
      }
    }

    if (!key.added_by) {
      risks.push({ severity: 'low', message: 'Creator unknown — cannot attribute access' });
      bump('low');
    }

    if (level === 'none') recs.push({ action: 'No action needed', reason: 'This deploy key follows best practices.', urgent: false });

    return { level: level, risks: risks, recommendations: recs };
  }

  function assessWorkflowRisk(file) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (file.permissions === 'write-all') {
      risks.push({ severity: 'high', message: 'Workflow has write-all permissions' });
      recs.push({ action: 'Set explicit permissions', reason: 'write-all grants the workflow token full repo access including code push.', urgent: true });
      bump('high');
    } else if (file.permissions === 'not set') {
      risks.push({ severity: 'medium', message: 'No explicit permissions block — inherits repo defaults' });
      recs.push({ action: 'Add permissions block', reason: 'Explicit permissions prevent privilege escalation if repo defaults change.', urgent: false });
      bump('medium');
    }

    if (file.unpinned_actions && file.unpinned_actions.length > 0) {
      risks.push({ severity: 'high', message: file.unpinned_actions.length + ' unpinned action(s) — supply chain injection vector' });
      recs.push({ action: 'Pin to SHA', reason: 'Tag-referenced actions can be hijacked by overwriting the tag.', urgent: true });
      bump('high');
    }

    if (level === 'none') {
      risks.push({ severity: 'low', message: 'Explicit permissions and all actions pinned' });
      recs.push({ action: 'No action needed', reason: 'This workflow follows supply chain security best practices.', urgent: false });
    }

    return { level: level, risks: risks, recommendations: recs };
  }

  function assessWorkflowPermRisk(perm) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (perm.default_permission === 'write') {
      risks.push({ severity: 'high', message: 'Default GITHUB_TOKEN permission is write' });
      recs.push({ action: 'Change to read', reason: 'Write default means any workflow can push code, create releases, and modify other workflows.', urgent: true });
      bump('high');
    }

    if (perm.can_approve_pull_requests) {
      risks.push({ severity: 'medium', message: 'Workflows can approve pull requests' });
      recs.push({ action: 'Disable', reason: 'Automated PR approval can bypass code review requirements.', urgent: false });
      bump('medium');
    }

    if (level === 'none') recs.push({ action: 'No action needed', reason: 'Repository workflow settings follow best practices.', urgent: false });

    return { level: level, risks: risks, recommendations: recs };
  }

  var HIGH_RISK_SSO_SCOPES = { 'admin:org': true, 'repo': true, 'write:packages': true, 'delete_repo': true, 'admin:repo_hook': true, 'admin:org_hook': true, 'gist': true, 'workflow': true };

  function assessSSORisk(cred) {
    var risks = [], recs = [], level = 'none';
    function bump(l) { var w = { high: 3, medium: 2, low: 1, none: 0 }; if ((w[l]||0) > (w[level]||0)) level = l; }

    if (cred.credential_type === 'personal access token') {
      risks.push({ severity: 'high', message: 'Classic PAT — not fine-grained, broad scope by design' });
      recs.push({ action: 'Migrate to fine-grained', reason: 'Classic PATs cannot be scoped to specific repos or permissions.', urgent: true });
      bump('high');
    }

    var broadScopes = [];
    (cred.scopes || []).forEach(function(s) {
      if (HIGH_RISK_SSO_SCOPES[s]) broadScopes.push(s);
    });
    if (broadScopes.length > 0) {
      risks.push({ severity: 'high', message: 'Broad scopes: ' + broadScopes.join(', ') });
      recs.push({ action: 'Reduce scopes', reason: 'These scopes grant excessive access to org resources.', urgent: true });
      bump('high');
    }

    if (!cred.authorized_credential_expires_at) {
      risks.push({ severity: 'high', message: 'No expiration set' });
      recs.push({ action: 'Set expiry', reason: 'Non-expiring credentials are persistent attack vectors.', urgent: true });
      bump('high');
    }

    if (!cred.credential_accessed_at) {
      risks.push({ severity: 'medium', message: 'Never accessed since SSO authorization' });
      recs.push({ action: 'Revoke SSO authorization', reason: 'Unused SSO-authorized credentials increase attack surface.', urgent: false });
      bump('medium');
    } else {
      var inactiveDays = daysBetween(new Date(cred.credential_accessed_at), new Date());
      if (inactiveDays > 90) {
        risks.push({ severity: 'medium', message: 'Inactive for ' + inactiveDays + ' days' });
        recs.push({ action: 'Review', reason: 'Consider revoking SSO authorization if no longer needed.', urgent: false });
        bump('medium');
      }
    }

    if (level === 'none') recs.push({ action: 'No action needed', reason: 'This credential follows best practices.', urgent: false });

    return { level: level, risks: risks, recommendations: recs };
  }

  // --- PATs Table ---

  function renderPATDetailPanel(tr, p, assessment) {
    var detailRow = document.createElement('tr');
    detailRow.className = 'pat-detail-row';
    var dc = document.createElement('td');
    dc.colSpan = 9;
    dc.className = 'pat-detail-cell';

    // Section 1: Risk Assessment
    var riskSection = document.createElement('div');
    riskSection.className = 'pat-detail-section';
    var riskTitle = document.createElement('div');
    riskTitle.className = 'pat-detail-section-title';
    riskTitle.textContent = assessment.risks.length > 0
      ? 'Risk Assessment (' + assessment.risks.length + ' issue' + (assessment.risks.length > 1 ? 's' : '') + ')'
      : 'Risk Assessment';
    riskSection.appendChild(riskTitle);

    if (assessment.risks.length === 0) {
      var clean = document.createElement('div');
      clean.className = 'pat-clean-state';
      clean.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 8l2 2 3.5-3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> No issues found';
      riskSection.appendChild(clean);
    } else {
      assessment.risks.forEach(function(risk) {
        var item = document.createElement('div');
        item.className = 'pat-risk-item';
        var dot = document.createElement('span');
        dot.className = 'pat-risk-dot ' + risk.severity;
        item.appendChild(dot);
        var msg = document.createElement('span');
        msg.textContent = risk.message;
        item.appendChild(msg);
        riskSection.appendChild(item);
      });
    }
    dc.appendChild(riskSection);

    // Section 2: Recommendations
    var recSection = document.createElement('div');
    recSection.className = 'pat-detail-section';
    var recTitle = document.createElement('div');
    recTitle.className = 'pat-detail-section-title';
    recTitle.textContent = 'Recommendations';
    recSection.appendChild(recTitle);

    assessment.recommendations.forEach(function(rec) {
      var item = document.createElement('div');
      item.className = 'pat-recommendation ' + (rec.urgent ? 'urgent' : (rec.action === 'No action needed' ? 'info' : 'warn'));
      var action = document.createElement('span');
      action.className = 'rec-action';
      action.textContent = rec.action + ':';
      var reason = document.createElement('span');
      reason.className = 'rec-reason';
      reason.textContent = ' ' + rec.reason;
      item.appendChild(action);
      item.appendChild(reason);
      recSection.appendChild(item);
    });
    dc.appendChild(recSection);

    // Section 3: Token Details
    var metaSection = document.createElement('div');
    metaSection.className = 'pat-detail-section';
    var metaTitle = document.createElement('div');
    metaTitle.className = 'pat-detail-section-title';
    metaTitle.textContent = 'Token Details';
    metaSection.appendChild(metaTitle);

    var metaGrid = document.createElement('div');
    metaGrid.className = 'pat-token-meta';

    var metaItems = [
      {
        label: 'Created',
        value: timeAgo(p.access_granted_at),
        sub: new Date(p.access_granted_at).toLocaleDateString(),
        cls: ''
      },
      {
        label: 'Last Used',
        value: p.token_last_used_at ? timeAgo(p.token_last_used_at) : 'Never used',
        sub: p.token_last_used_at ? new Date(p.token_last_used_at).toLocaleDateString() : '',
        cls: !p.token_last_used_at ? 'warn' : ''
      },
      {
        label: 'Expires',
        value: p.token_expires_at ? timeUntil(p.token_expires_at) : 'Never',
        sub: p.token_expires_at ? new Date(p.token_expires_at).toLocaleDateString() : '',
        cls: !p.token_expires_at ? 'danger' : ''
      },
      {
        label: 'Permissions',
        value: '',
        permSummary: true,
        cls: ''
      }
    ];

    metaItems.forEach(function(m) {
      var item = document.createElement('div');
      item.className = 'pat-meta-item';
      var label = document.createElement('div');
      label.className = 'pat-meta-label';
      label.textContent = m.label;
      item.appendChild(label);

      if (m.permSummary) {
        var permDiv = document.createElement('div');
        permDiv.className = 'pat-perm-summary';
        var counts = { high: 0, medium: 0, low: 0 };
        (p.permissions || []).forEach(function(perm) { counts[perm.risk] = (counts[perm.risk] || 0) + 1; });
        ['high', 'medium', 'low'].forEach(function(risk) {
          if (counts[risk] > 0) {
            var span = document.createElement('span');
            span.className = 'pat-perm-count ' + risk;
            span.textContent = counts[risk] + ' ' + risk;
            permDiv.appendChild(span);
          }
        });
        if (!counts.high && !counts.medium && !counts.low) permDiv.textContent = 'None';
        item.appendChild(permDiv);
      } else {
        var val = document.createElement('div');
        val.className = 'pat-meta-value' + (m.cls ? ' ' + m.cls : '');
        val.textContent = m.value;
        item.appendChild(val);
        if (m.sub) {
          var sub = document.createElement('div');
          sub.className = 'pat-meta-sub';
          sub.textContent = m.sub;
          item.appendChild(sub);
        }
      }
      metaGrid.appendChild(item);
    });
    metaSection.appendChild(metaGrid);
    dc.appendChild(metaSection);

    // Section 4: Repositories
    var repoSection = document.createElement('div');
    repoSection.className = 'pat-detail-section pat-repo-section';
    var repoTitle = document.createElement('div');
    repoTitle.className = 'pat-detail-section-title';
    repoTitle.textContent = 'Repositories';
    repoSection.appendChild(repoTitle);

    if (p.repository_selection === 'all') {
      var allWarn = document.createElement('div');
      allWarn.className = 'pat-repo-all-warning';
      allWarn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2L2 13h12L8 2z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M8 6v4M8 11.5v.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/></svg> Access to all organization repositories';
      repoSection.appendChild(allWarn);
    } else {
      var repoContent = document.createElement('div');
      repoContent.className = 'pat-repo-list';
      repoContent.textContent = 'Loading repositories...';
      repoSection.appendChild(repoContent);

      function loadRepos() {
        repoContent.textContent = 'Loading repositories...';
        fetchJSON('/api/pats/' + p.id + '/repos').then(function(repos) {
          repoContent.textContent = '';
          if (!repos || repos.length === 0) {
            repoContent.textContent = 'No specific repositories listed';
          } else {
            var ul = document.createElement('ul');
            repos.forEach(function(r) {
              var li = document.createElement('li');
              li.textContent = r.full_name;
              if (r.private) li.className = 'private';
              ul.appendChild(li);
            });
            repoContent.appendChild(ul);
          }
        }).catch(function() {
          repoContent.textContent = '';
          var errDiv = document.createElement('div');
          errDiv.className = 'pat-repo-error';
          errDiv.textContent = 'Could not load repositories. The GitHub API may be rate-limited. ';
          var retryBtn = document.createElement('button');
          retryBtn.className = 'pat-repo-retry';
          retryBtn.textContent = 'Retry';
          retryBtn.addEventListener('click', function(e) { e.stopPropagation(); loadRepos(); });
          errDiv.appendChild(retryBtn);
          repoContent.appendChild(errDiv);
        });
      }
      loadRepos();
    }

    dc.appendChild(repoSection);
    detailRow.appendChild(dc);
    tr.parentNode.insertBefore(detailRow, tr.nextSibling);
    return detailRow;
  }

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
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, patSort, function() { renderPATs(report.pats); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(p) {
      var assessment = assessPATRisk(p);
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

      // Risk badge column
      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      if (assessment.level === 'none') {
        riskBadge.innerHTML = '<svg width="10" height="10" viewBox="0 0 16 16" fill="none"><path d="M5.5 8l2 2 3.5-3.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> OK';
      } else {
        riskBadge.textContent = assessment.level;
      }
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      // Actions column
      var actCell = document.createElement('td');
      actCell.style.whiteSpace = 'nowrap';
      if (!p.token_expired) {
        var revokeBtn = document.createElement('button');
        revokeBtn.className = 'action-btn revoke';
        revokeBtn.textContent = 'Revoke';
        revokeBtn.addEventListener('click', function(e) {
          e.stopPropagation();
          if (!confirm('Revoke token \'' + p.token_name + '\' owned by ' + p.owner_login + '?\n\nThis will immediately remove the token\'s access to your organization. This action cannot be undone.')) return;
          revokeBtn.disabled = true;
          revokeBtn.textContent = '...';
          fetch('/api/pats/' + p.id + '/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
          }).then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            tr.style.opacity = '0.4';
            revokeBtn.textContent = 'Revoked';
            setTimeout(function() {
              fetchJSON('/api/summary').then(function(data) {
                report = data;
                renderPATs(report.pats);
              });
            }, 1000);
          }).catch(function(err) {
            revokeBtn.disabled = false;
            revokeBtn.textContent = 'Revoke';
            alert('Revoke failed: ' + (err.message || 'unknown error'));
          });
        });
        actCell.appendChild(revokeBtn);
      }
      tr.appendChild(actCell);

      // Expand/collapse detail panel on row click
      var detailRow = null;
      tr.addEventListener('click', function() {
        if (detailRow) { detailRow.remove(); detailRow = null; return; }
        detailRow = renderPATDetailPanel(tr, p, assessment);
      });

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Pagination helper ---

  function buildPagination(containerId, totalItems, currentPage, onPageChange) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';
    var totalPages = Math.ceil(totalItems / PAGE_SIZE);
    if (totalPages <= 1) return;

    function btn(label, page, active, disabled) {
      var b = document.createElement('button');
      b.textContent = label;
      if (active) b.classList.add('active');
      if (disabled) b.disabled = true;
      b.addEventListener('click', function() { onPageChange(page); });
      return b;
    }

    container.appendChild(btn('‹', currentPage - 1, false, currentPage === 1));

    // Always show first, last, and a window around the current page
    var pages = [];
    for (var i = 1; i <= totalPages; i++) {
      if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
        pages.push(i);
      }
    }
    var prev = 0;
    pages.forEach(function(p) {
      if (prev && p - prev > 1) {
        var ellipsis = document.createElement('button');
        ellipsis.textContent = '…';
        ellipsis.disabled = true;
        container.appendChild(ellipsis);
      }
      container.appendChild(btn(String(p), p, p === currentPage, false));
      prev = p;
    });

    container.appendChild(btn('›', currentPage + 1, false, currentPage === totalPages));

    var info = document.createElement('span');
    info.className = 'page-info';
    var start = (currentPage - 1) * PAGE_SIZE + 1;
    var end   = Math.min(currentPage * PAGE_SIZE, totalItems);
    info.textContent = start + '–' + end + ' of ' + totalItems;
    container.appendChild(info);
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
      { key: 'high_risk_count', label: 'Permissions' },
      { key: 'created_at', label: 'Installed' },
      { key: 'suspended', label: 'Status' },
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, appSort, function() { appPage = 1; renderApps(report.apps); }));

    var page = sorted.slice((appPage - 1) * PAGE_SIZE, appPage * PAGE_SIZE);
    buildPagination('apps-pagination', sorted.length, appPage, function(p) {
      appPage = p; renderApps(apps);
    });

    var tbody = document.createElement('tbody');
    page.forEach(function(a) {
      var assessment = assessAppRisk(a);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      if (isNewItem(a.id, 'app')) tr.classList.add('diff-new');

      var nameCell = document.createElement('td');
      var nameLink = document.createElement('span');
      nameLink.className = 'app-name-link';
      nameLink.textContent = a.app_name;
      nameCell.appendChild(nameLink);
      tr.appendChild(nameCell);

      var repoCell = document.createElement('td');
      var repoBadge = document.createElement('span');
      repoBadge.className = 'badge ' + (a.repository_selection === 'all' ? 'high' : 'low');
      repoBadge.textContent = a.repository_selection;
      repoCell.appendChild(repoBadge);
      tr.appendChild(repoCell);

      var permCell = document.createElement('td');
      var permSummary = document.createElement('div');
      permSummary.className = 'detail-perm-summary';
      [['high', a.high_risk_count], ['medium', a.medium_risk_count], ['low', a.low_risk_count]].forEach(function(pair) {
        if (pair[1] > 0) {
          var span = document.createElement('span');
          span.className = 'detail-perm-count ' + pair[0];
          span.textContent = pair[1] + ' ' + pair[0];
          permSummary.appendChild(span);
        }
      });
      if (!a.high_risk_count && !a.medium_risk_count && !a.low_risk_count) permSummary.textContent = 'None';
      permCell.appendChild(permSummary);
      tr.appendChild(permCell);

      addCell(tr, new Date(a.created_at).toLocaleDateString());

      var statusCell = document.createElement('td');
      var statusSpan = document.createElement('span');
      statusSpan.textContent = a.suspended ? 'Suspended' : 'Active';
      statusSpan.className = a.suspended ? 'status-suspended' : 'status-active';
      statusCell.appendChild(statusSpan);
      tr.appendChild(statusCell);

      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      var actionsCell = document.createElement('td');
      actionsCell.addEventListener('click', function(e) { e.stopPropagation(); });
      var actionLink = document.createElement('a');
      actionLink.className = 'action-btn ' + (a.suspended ? 'unsuspend' : 'suspend');
      actionLink.textContent = a.suspended ? 'Unsuspend' : 'Suspend';
      actionLink.href = 'https://github.com/organizations/' + orgName + '/settings/installations/' + a.id;
      actionLink.target = '_blank';
      actionLink.rel = 'noopener noreferrer';
      actionsCell.appendChild(actionLink);
      tr.appendChild(actionsCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderAppDetailPanel(a, 7); });
      });

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Pending Requests ---

  function renderRequests(requests) {
    var table = document.getElementById('requests-table');
    var section = document.getElementById('pending-section');
    var countEl = document.getElementById('count-requests');
    if (!requests || requests.length === 0) {
      table.innerHTML = '';
      if (countEl) countEl.textContent = '0';
      if (section) section.style.display = 'none';
      return;
    }
    if (section) section.style.display = 'block';
    if (countEl) countEl.textContent = String(requests.length);
    table.innerHTML = '';

    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    ['Owner', 'Token Name', 'Repo Access', 'Permissions', 'Expiry', 'Requested', 'Actions'].forEach(function(label) {
      var th = document.createElement('th'); th.textContent = label; headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    requests.forEach(function(r) {
      var tr = document.createElement('tr');
      addCell(tr, r.owner_login);
      addCell(tr, r.token_name);

      var repoCell = document.createElement('td');
      var rb = document.createElement('span');
      rb.className = 'badge ' + (r.repository_selection === 'all' ? 'high' : 'low');
      rb.textContent = r.repository_selection;
      repoCell.appendChild(rb);
      tr.appendChild(repoCell);

      var permCell = document.createElement('td');
      permCell.className = 'cell-wrap';
      renderPermBadges(permCell, r.permissions);
      tr.appendChild(permCell);

      addCell(tr, r.token_expires_at ? new Date(r.token_expires_at).toLocaleDateString() : 'Never');
      addCell(tr, new Date(r.created_at).toLocaleDateString());

      // Approve / Deny action buttons
      var actCell = document.createElement('td');
      actCell.style.whiteSpace = 'nowrap';

      var approveBtn = document.createElement('button');
      approveBtn.className = 'action-btn approve';
      approveBtn.textContent = 'Approve';
      function doReview(action, reason, btn, otherBtn, doneText) {
        btn.disabled = true;
        otherBtn.disabled = true;
        btn.textContent = '…';
        fetch('/api/pats/requests/' + r.id + '/review', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: action, reason: reason }),
        }).then(function(resp) {
          if (!resp.ok) return resp.json().then(function(d) { throw new Error(d.error || 'HTTP ' + resp.status); });
          btn.textContent = doneText;
          tr.style.opacity = '0.4';
          setTimeout(function() {
            if (report && report.pending_requests) {
              report.pending_requests = report.pending_requests.filter(function(x) { return x.id !== r.id; });
              renderRequests(report.pending_requests);
            }
          }, 600);
        }).catch(function(err) {
          btn.textContent = action === 'approve' ? 'Approve' : 'Deny';
          btn.disabled = false;
          otherBtn.disabled = false;
          alert(doneText.replace('d', '') + ' failed: ' + (err.message || 'unknown error'));
        });
      }

      approveBtn.addEventListener('click', function() {
        doReview('approve', '', approveBtn, denyBtn, 'Approved');
      });

      var denyBtn = document.createElement('button');
      denyBtn.className = 'action-btn deny';
      denyBtn.textContent = 'Deny';
      denyBtn.style.marginLeft = '6px';
      denyBtn.addEventListener('click', function() {
        var reason = prompt('Reason for denying (optional):') || '';
        doReview('deny', reason, denyBtn, approveBtn, 'Denied');
      });

      actCell.appendChild(approveBtn);
      actCell.appendChild(denyBtn);
      tr.appendChild(actCell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- SSO Credentials ---

  function renderSSOCredentials(creds) {
    if (!creds) creds = [];

    // Apply type filter
    var filtered = ssoTypeFilter
      ? creds.filter(function(c) { return c.credential_type === ssoTypeFilter; })
      : creds;

    var sorted = sortData(filtered, ssoSort);
    var table = document.getElementById('sso-table');
    table.innerHTML = '';

    if (sorted.length === 0) {
      var empty = document.createElement('tbody');
      var row = document.createElement('tr');
      var cell = document.createElement('td');
      cell.colSpan = 10;
      cell.className = 'empty-state';
      cell.textContent = 'No credentials match the current filter.';
      row.appendChild(cell);
      empty.appendChild(row);
      table.appendChild(empty);
      document.getElementById('sso-pagination').innerHTML = '';
      return;
    }

    var cols = [
      { key: 'login', label: 'Owner' },
      { key: 'credential_type', label: 'Type' },
      { key: 'authorized_credential_title', label: 'Title' },
      { key: '', label: 'Scopes' },
      { key: 'credential_authorized_at', label: 'Authorized' },
      { key: 'credential_accessed_at', label: 'Last Accessed' },
      { key: 'authorized_credential_expires_at', label: 'Expires' },
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, ssoSort, function() { ssoPage = 1; renderSSOCredentials(report.sso_credentials); }));

    var page = sorted.slice((ssoPage - 1) * PAGE_SIZE, ssoPage * PAGE_SIZE);
    buildPagination('sso-pagination', sorted.length, ssoPage, function(p) {
      ssoPage = p; renderSSOCredentials(creds);
    });

    var tbody = document.createElement('tbody');
    page.forEach(function(c) {
      var assessment = assessSSORisk(c);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      addCell(tr, c.login);
      var typeCell = document.createElement('td');
      var typeBadge = document.createElement('span');
      typeBadge.className = 'badge ' + (c.credential_type === 'personal access token' ? 'medium' : 'low');
      typeBadge.textContent = c.credential_type;
      typeCell.appendChild(typeBadge);
      tr.appendChild(typeCell);
      addCell(tr, c.authorized_credential_title || '-');
      var scopeCell = document.createElement('td');
      scopeCell.className = 'cell-wrap';
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
      var riskCell = document.createElement('td');
      var riskBadge = document.createElement('span');
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      // Revoke button
      var actCell = document.createElement('td');
      actCell.style.whiteSpace = 'nowrap';
      var revokeBtn = document.createElement('button');
      revokeBtn.className = 'action-btn revoke';
      revokeBtn.textContent = 'Revoke';
      revokeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var label = c.authorized_credential_title || c.token_last_eight || c.fingerprint || String(c.credential_id);
        var what = c.credential_type === 'personal access token' ? 'classic PAT' : 'SSH key';
        if (!confirm('Revoke ' + what + ' "' + label + '" for ' + c.login + '?\n\nThis will immediately deauthorize the credential from your organization. The user will need to re-authorize via SSO to regain access. This cannot be undone.')) return;
        revokeBtn.disabled = true;
        revokeBtn.textContent = '...';
        fetch('/api/sso-credentials/' + c.credential_id + '/revoke', {
          method: 'DELETE',
        }).then(function(resp) {
          if (!resp.ok) return resp.json().then(function(d) { throw new Error(d.error || 'HTTP ' + resp.status); });
          tr.style.opacity = '0.4';
          revokeBtn.textContent = 'Revoked';
          setTimeout(function() {
            report.sso_credentials = report.sso_credentials.filter(function(x) { return x.credential_id !== c.credential_id; });
            renderSSOCredentials(report.sso_credentials);
          }, 800);
        }).catch(function(err) {
          revokeBtn.disabled = false;
          revokeBtn.textContent = 'Revoke';
          alert('Revoke failed: ' + (err.message || 'unknown error'));
        });
      });
      actCell.appendChild(revokeBtn);
      tr.appendChild(actCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderSSODetailPanel(c, 10); });
      });

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
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, secretSort, function() { renderSecrets(report.secrets); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(s) {
      var assessment = assessSecretRisk(s);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
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
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      // Delete button
      var actCell = document.createElement('td');
      actCell.style.whiteSpace = 'nowrap';
      var deleteBtn = document.createElement('button');
      deleteBtn.className = 'action-btn deny';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var where = s.scope === 'org' ? 'org-level' : (s.scope === 'environment' ? s.repo_name + '/' + s.env_name : s.repo_name);
        if (!confirm('Permanently delete secret "' + s.name + '" (' + where + ')?\n\nAny workflow or action that references this secret will BREAK immediately. This cannot be undone.')) return;
        deleteBtn.disabled = true;
        deleteBtn.textContent = '…';
        fetch('/api/secrets', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scope: s.scope, name: s.name, repo_name: s.repo_name || '', env_name: s.env_name || '' }),
        }).then(function(resp) {
          if (!resp.ok) return resp.json().then(function(d) { throw new Error(d.error || 'HTTP ' + resp.status); });
          deleteBtn.textContent = 'Deleted';
          tr.style.opacity = '0.4';
          setTimeout(function() {
            report.secrets = report.secrets.filter(function(x) {
              return !(x.name === s.name && x.scope === s.scope && x.repo_name === s.repo_name && x.env_name === s.env_name);
            });
            renderSecrets(report.secrets);
          }, 600);
        }).catch(function(err) {
          deleteBtn.disabled = false;
          deleteBtn.textContent = 'Delete';
          alert('Delete failed: ' + (err.message || 'unknown error'));
        });
      });
      actCell.appendChild(deleteBtn);
      tr.appendChild(actCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderSecretDetailPanel(s, 8); });
      });

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
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, dkSort, function() { renderDeployKeys(report.deploy_keys); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(k) {
      var assessment = assessDeployKeyRisk(k);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
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
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      var actCell = document.createElement('td');
      actCell.style.whiteSpace = 'nowrap';
      var deleteBtn = document.createElement('button');
      deleteBtn.className = 'action-btn deny';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var access = k.read_only ? 'read-only' : 'read-write';
        if (!confirm('Permanently delete deploy key "' + k.title + '" (' + access + ') from ' + k.repo_name + '?\n\nAny service using this key will lose access immediately. This cannot be undone.')) return;
        deleteBtn.disabled = true;
        deleteBtn.textContent = '…';
        fetch('/api/deploy-keys/' + k.id + '?repo=' + encodeURIComponent(k.repo_name), {
          method: 'DELETE',
        }).then(function(resp) {
          if (!resp.ok) return resp.json().then(function(d) { throw new Error(d.error || 'HTTP ' + resp.status); });
          deleteBtn.textContent = 'Deleted';
          tr.style.opacity = '0.4';
          setTimeout(function() {
            report.deploy_keys = report.deploy_keys.filter(function(x) { return x.id !== k.id; });
            renderDeployKeys(report.deploy_keys);
          }, 600);
        }).catch(function(err) {
          deleteBtn.disabled = false;
          deleteBtn.textContent = 'Delete';
          alert('Delete failed: ' + (err.message || 'unknown error'));
        });
      });
      actCell.appendChild(deleteBtn);
      tr.appendChild(actCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderDeployKeyDetailPanel(k, 8); });
      });

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
      { key: '', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, wpSort, function() { renderWorkflowPerms(report.workflow_permissions); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(wp) {
      var assessment = assessWorkflowPermRisk(wp);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
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
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderWorkflowPermDetailPanel(wp, 4); });
      });

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
      { key: '', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, wfSort, function() { renderWorkflowFiles(report.workflow_files); }));

    var tbody = document.createElement('tbody');
    sorted.forEach(function(wf) {
      var assessment = assessWorkflowRisk(wf);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
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
      riskBadge.className = 'risk-badge-inline ' + assessment.level;
      riskBadge.textContent = assessment.level;
      riskCell.appendChild(riskBadge);
      tr.appendChild(riskCell);

      tr.addEventListener('click', function() {
        toggleDetailRow(tr, function() { return renderWorkflowFileDetailPanel(wf, 6); });
      });

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- Violations ---

  var RULE_META = {
    'pat.deny_no_expiry':          { label: 'PAT: No expiry date',              fix: 'Set an expiration date on the token. Use 90 days or less per policy.', tab: 'tab-pats' },
    'pat.max_expiry_days':         { label: 'PAT: Expiry too far out',           fix: 'Shorten the token lifetime to within 90 days. Rotate regularly.', tab: 'tab-pats' },
    'pat.deny_all_repo_access':    { label: 'PAT: All-repo access',              fix: 'Limit the token to only the specific repositories it needs.', tab: 'tab-pats' },
    'pat.deny_admin_permissions':  { label: 'PAT: Admin-level permission',       fix: 'Remove admin permissions. Use the minimum required access level.', tab: 'tab-pats' },
    'pat.max_inactive_days':       { label: 'PAT: Inactive token',               fix: 'Revoke unused tokens. If still needed, rotate and document the use case.', tab: 'tab-pats' },
    'app.deny_all_repo_access':    { label: 'App: All-repo access',              fix: 'Change app installation scope to selected repositories only.', tab: 'tab-apps' },
    'app.max_high_risk_permissions': { label: 'App: Excessive permissions',      fix: 'Review and remove high-risk permissions not required for the app\'s function. Consider suspending the app.', tab: 'tab-apps' },
    'sso.deny_classic_pats':       { label: 'SSO: Classic PAT authorized',       fix: 'Migrate to fine-grained PATs. Classic PATs cannot be scoped to specific repos or permissions.', tab: 'tab-sso' },
    'secrets.deny_org_wide_visibility': { label: 'Secret: Org-wide visibility',  fix: 'Change visibility from "all" to "selected" and restrict to only repos that need this secret.', tab: 'tab-secrets' },
    'secrets.max_stale_days':      { label: 'Secret: Not rotated in 365+ days',  fix: 'Rotate the secret value. Update all consumers before deleting the old value.', tab: 'tab-secrets' },
    'deploy_keys.deny_write_access': { label: 'Deploy Key: Write access',        fix: 'Convert to read-only if the key only needs to clone. If write is needed, use a GitHub App instead.', tab: 'tab-deploy-keys' },
    'workflows.deny_write_all_default': { label: 'Workflow: write-all default',  fix: 'Go to repo Settings → Actions → General → set GITHUB_TOKEN to "Read repository contents and packages".', tab: 'tab-workflow-perms' },
    'workflows.deny_can_approve_prs': { label: 'Workflow: Can approve PRs',      fix: 'Disable "Allow GitHub Actions to create and approve pull requests" in repo Actions settings.', tab: 'tab-workflow-perms' },
    'workflows.deny_unpinned_actions': { label: 'Workflow: Unpinned action ref', fix: 'Pin each action to a full commit SHA (e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683). Use a tool like pin-github-action.', tab: 'tab-workflow-perms' },
  };

  var RULE_CATEGORIES = {
    'PATs':       ['pat.deny_no_expiry', 'pat.max_expiry_days', 'pat.deny_all_repo_access', 'pat.deny_admin_permissions', 'pat.max_inactive_days'],
    'Apps':       ['app.deny_all_repo_access', 'app.max_high_risk_permissions'],
    'SSO Credentials': ['sso.deny_classic_pats'],
    'Secrets':    ['secrets.deny_org_wide_visibility', 'secrets.max_stale_days'],
    'Deploy Keys':['deploy_keys.deny_write_access'],
    'Workflows':  ['workflows.deny_write_all_default', 'workflows.deny_can_approve_prs', 'workflows.deny_unpinned_actions'],
  };

  var violSevFilter = '';

  function renderViolations(violations) {
    var summaryEl = document.getElementById('violations-summary');
    var groupsEl  = document.getElementById('violations-groups');
    if (!violations || violations.length === 0) {
      summaryEl.style.display = 'none';
      groupsEl.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-muted);font-size:14px">No policy violations found — org is compliant.</div>';
      return;
    }

    // Apply filters
    var query = (document.getElementById('violations-filter').value || '').toLowerCase();
    var filtered = violations.filter(function(v) {
      if (violSevFilter && v.severity !== violSevFilter) return false;
      if (query) {
        var hay = (v.rule + v.resource + v.message + (RULE_META[v.rule] ? RULE_META[v.rule].label : '')).toLowerCase();
        if (hay.indexOf(query) === -1) return false;
      }
      return true;
    });

    // Summary bar
    var counts = { high: 0, medium: 0, low: 0 };
    violations.forEach(function(v) { if (counts[v.severity] !== undefined) counts[v.severity]++; });
    summaryEl.style.display = 'flex';
    summaryEl.innerHTML =
      '<div class="vsummary-card high"><div><div class="vsummary-count">' + counts.high + '</div><div class="vsummary-label">High</div></div></div>' +
      '<div class="vsummary-card medium"><div><div class="vsummary-count">' + counts.medium + '</div><div class="vsummary-label">Medium</div></div></div>' +
      '<div class="vsummary-card low"><div><div class="vsummary-count">' + counts.low + '</div><div class="vsummary-label">Low</div></div></div>' +
      '<div class="vsummary-card" style="border-left:3px solid var(--accent)"><div><div class="vsummary-count" style="color:var(--accent)">' + violations.length + '</div><div class="vsummary-label">Total</div></div></div>';

    // Render groups
    groupsEl.innerHTML = '';
    Object.keys(RULE_CATEGORIES).forEach(function(catName) {
      var ruleIds = RULE_CATEGORIES[catName];
      var catViolations = filtered.filter(function(v) { return ruleIds.indexOf(v.rule) !== -1; });
      if (catViolations.length === 0) return;

      var group = document.createElement('div');
      group.className = 'vgroup';

      var header = document.createElement('div');
      header.className = 'vgroup-header';
      var highCount = catViolations.filter(function(v) { return v.severity === 'high'; }).length;
      header.innerHTML =
        '<span class="vgroup-title">' + catName + '</span>' +
        (highCount > 0 ? '<span class="badge high">' + highCount + ' HIGH</span>' : '') +
        '<span class="vgroup-count">' + catViolations.length + ' violation' + (catViolations.length !== 1 ? 's' : '') + '</span>' +
        '<span class="vgroup-chevron open">▶</span>';
      group.appendChild(header);

      var body = document.createElement('div');
      body.className = 'vgroup-body';

      catViolations.forEach(function(v) {
        var meta = RULE_META[v.rule] || { label: v.rule, fix: null, tab: null };

        var row = document.createElement('div');
        row.className = 'vrow';

        // Severity badge
        var sevDiv = document.createElement('div');
        sevDiv.innerHTML = '<span class="badge ' + v.severity + '">' + v.severity.toUpperCase() + '</span>';
        row.appendChild(sevDiv);

        // Rule human name
        var ruleDiv = document.createElement('div');
        ruleDiv.className = 'vrule-name';
        ruleDiv.textContent = meta.label;
        row.appendChild(ruleDiv);

        // Resource (full, monospace)
        var resDiv = document.createElement('div');
        resDiv.className = 'vresource';
        resDiv.textContent = v.resource;
        row.appendChild(resDiv);

        // Message (full, no truncation)
        var msgDiv = document.createElement('div');
        msgDiv.className = 'vmessage';
        msgDiv.textContent = v.message;
        row.appendChild(msgDiv);

        // Expandable detail row
        var detail = document.createElement('div');
        detail.className = 'vrow-detail';

        var detailGrid = document.createElement('div');
        detailGrid.className = 'vrow-detail-grid';

        if (meta.fix) {
          var fixCard = document.createElement('div');
          fixCard.className = 'vfix-card';
          fixCard.innerHTML = '<div class="vfix-label">Remediation</div><div class="vfix-text">' + meta.fix + '</div>';
          detailGrid.appendChild(fixCard);
        }

        var infoCard = document.createElement('div');
        infoCard.className = 'vfix-card';
        infoCard.style.borderLeftColor = 'var(--info)';
        infoCard.innerHTML = '<div class="vfix-label" style="color:var(--info)">Rule ID</div><div class="vfix-text" style="font-family:monospace">' + v.rule + '</div>';
        detailGrid.appendChild(infoCard);

        detail.appendChild(detailGrid);

        if (meta.tab) {
          var navBtn = document.createElement('button');
          navBtn.className = 'vnav-link';
          navBtn.innerHTML = '→ Go to ' + catName + ' tab';
          navBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            var navItem = document.querySelector('.nav-item[data-tab="' + meta.tab + '"]');
            if (navItem) navItem.click();
          });
          detail.appendChild(navBtn);
        }

        row.appendChild(detail);

        row.addEventListener('click', function() {
          var isExpanded = detail.classList.contains('visible');
          detail.classList.toggle('visible', !isExpanded);
          row.classList.toggle('expanded', !isExpanded);
        });

        body.appendChild(row);
      });

      header.addEventListener('click', function() {
        var chevron = header.querySelector('.vgroup-chevron');
        body.classList.toggle('collapsed');
        chevron.classList.toggle('open');
      });

      group.appendChild(body);
      groupsEl.appendChild(group);
    });

    if (groupsEl.innerHTML === '') {
      groupsEl.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-muted);font-size:14px">No violations match the current filter.</div>';
    }
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

  // SSO type filter chips
  document.querySelectorAll('#sso-type-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#sso-type-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      ssoTypeFilter = btn.dataset.type;
      ssoPage = 1;
      if (report) renderSSOCredentials(report.sso_credentials);
    });
  });

  setupFilter('pats-filter', renderPATs, 'pats');
  setupFilter('apps-filter', function(apps) { appPage = 1; renderApps(apps); }, 'apps');
  setupFilter('sso-filter', function(creds) { ssoPage = 1; renderSSOCredentials(creds); }, 'sso_credentials');
  setupFilter('secrets-filter', renderSecrets, 'secrets');
  setupFilter('deploy-keys-filter', renderDeployKeys, 'deploy_keys');
  setupFilter('workflow-perms-filter', renderWorkflowPerms, 'workflow_permissions');
  setupFilter('workflow-files-filter', renderWorkflowFiles, 'workflow_files');

  document.getElementById('violations-filter').addEventListener('input', function() {
    if (report && report.violations) renderViolations(report.violations);
  });

  document.querySelectorAll('#violations-sev-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#violations-sev-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      violSevFilter = btn.dataset.sev;
      if (report && report.violations) renderViolations(report.violations);
    });
  });

  // --- Rescan ---

  document.getElementById('rescan-btn').addEventListener('click', function() {
    setScanningState(true);

    // POST /api/scan returns 202 immediately — scan runs in background.
    // Poll /api/report every 5s until scanned_at advances, then reload.
    fetch('/api/scan', { method: 'POST', headers: { 'Accept': 'application/json' } }).then(function(resp) {
      if (resp.status === 401) { window.location.href = '/login'; return; }
      if (resp.status !== 202 && !resp.ok) throw new Error(resp.statusText);
      var prevScannedAt = report && report.scanned_at ? report.scanned_at : null;
      pollForScanComplete(prevScannedAt, 0);
    }).catch(function(err) {
      alert('Scan failed: ' + err.message);
      setScanningState(false);
    });
  });

  function pollForScanComplete(prevScannedAt, attempts) {
    if (attempts > 72) { // 6 minutes max
      setScanningState(false);
      alert('Scan is taking longer than expected. Check back shortly.');
      return;
    }
    setTimeout(function() {
      fetchJSON('/api/report').then(function(data) {
        // Scan complete when scanned_at advances
        if (data.scanned_at && data.scanned_at !== prevScannedAt) {
          report = data;
          renderSummary(data.summary);
          renderPATs(data.pats);
          appPage = 1; renderApps(data.apps);
          renderRequests(data.pending_requests);
          ssoPage = 1; renderSSOCredentials(data.sso_credentials);
          renderSecrets(data.secrets);
          renderDeployKeys(data.deploy_keys);
          renderWorkflowPerms(data.workflow_permissions);
          renderWorkflowFiles(data.workflow_files);
          document.getElementById('scan-time').textContent =
            'Last scan\n' + new Date(data.scanned_at).toLocaleString();
          updateTabCounts();
          graphBuilt = false;
          if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
          fetchJSON('/api/violations').then(function(v) { if (report) report.violations = v; renderViolations(v); updateViolationCount(v.length); });
          fetchJSON('/api/diff').then(function(d) { diffData = d; renderDiff(d); });
          setScanningState(false);
        } else {
          pollForScanComplete(prevScannedAt, attempts + 1);
        }
      }).catch(function() {
        pollForScanComplete(prevScannedAt, attempts + 1);
      });
    }, 5000);
  }

  // --- Compliance ---

  function loadCompliance() {
    fetchJSON('/api/compliance').then(function(checks) {
      renderCompliance(checks);
    }).catch(function() {});
  }

  var COMPLIANCE_FIX_TEXT = {
    'classic_pats_blocked':       'Restrict classic PATs → Settings › Personal access tokens',
    'pat_approval_required':      'Enable PAT approval → Settings › Personal access tokens',
    'saml_sso_enabled':           'Enable SAML SSO → Settings › Authentication security',
    'github_token_least_privilege': 'Set GITHUB_TOKEN to read-only → Settings › Actions › General',
    'deploy_keys_read_only':      'Convert or remove write deploy keys → repo Settings › Deploy keys',
    'secrets_scoped':             'Restrict secret visibility → Settings › Secrets and variables',
    'actions_pinned':             'Pin actions to full SHAs → update workflow YAML files',
    'pat_expiry_enforced':        'Set expiry on all active PATs → PATs tab → Revoke & re-issue',
  };

  var COMPLIANCE_VERIFY_TEXT = {
    'classic_pats_blocked':       'Go to Settings › Personal access tokens and check if classic PATs are blocked for this org.',
    'pat_approval_required':      'Go to Settings › Personal access tokens and verify "Require approval" is enabled.',
    'saml_sso_enabled':           'Go to Settings › Authentication security and verify SAML SSO is configured and enforced.',
    'github_token_least_privilege': 'No repos were scanned — enable repo scanning to verify.',
    'deploy_keys_read_only':      'No deploy keys found — verify by checking repos manually.',
    'secrets_scoped':             'No org secrets found — verify by checking Settings › Secrets.',
    'actions_pinned':             'No workflow files scanned — enable workflow scanning to verify.',
    'pat_expiry_enforced':        'No PATs found — verify by checking the PATs tab after a scan.',
  };

  function renderCompliance(checks) {
    var container  = document.getElementById('compliance-cards');
    var postureEl  = document.getElementById('compliance-posture');
    var scoreEl    = document.getElementById('compliance-score');
    container.innerHTML = '';

    var counts = { fail: 0, warn: 0, unknown: 0, pass: 0 };
    checks.forEach(function(c) { if (counts[c.status] !== undefined) counts[c.status]++; });
    var total = checks.length;

    // Score badge (top right)
    var failCount = counts.fail + counts.warn;
    scoreEl.textContent = counts.pass + '/' + total + ' passing';
    scoreEl.className = 'compliance-score ' + (failCount === 0 ? 'all-pass' : failCount > 3 ? 'many-fail' : 'some-fail');

    // Sidebar count
    var countEl = document.getElementById('count-compliance');
    if (countEl) {
      if (failCount > 0) { countEl.textContent = failCount; countEl.className = 'nav-badge warn'; }
      else { countEl.textContent = counts.pass + '/' + total; countEl.className = 'nav-badge'; }
    }

    // Posture bar
    postureEl.style.display = 'block';
    var pct = function(n) { return total ? Math.round(n / total * 100) : 0; };
    postureEl.innerHTML =
      '<div class="cp-counts">' +
        '<div class="cp-count-item fail"><div class="cp-count-num">' + counts.fail + '</div><div class="cp-count-label">Failed</div></div>' +
        '<div class="cp-count-item warn"><div class="cp-count-num">' + counts.warn + '</div><div class="cp-count-label">Warning</div></div>' +
        '<div class="cp-count-item unknown"><div class="cp-count-num">' + counts.unknown + '</div><div class="cp-count-label">Unknown</div></div>' +
        '<div class="cp-count-item pass"><div class="cp-count-num">' + counts.pass + '</div><div class="cp-count-label">Passed</div></div>' +
      '</div>' +
      '<div class="cp-bar-wrap">' +
        '<div class="cp-bar-seg fail"    style="width:' + pct(counts.fail)    + '%"></div>' +
        '<div class="cp-bar-seg warn"    style="width:' + pct(counts.warn)    + '%"></div>' +
        '<div class="cp-bar-seg unknown" style="width:' + pct(counts.unknown) + '%"></div>' +
        '<div class="cp-bar-seg pass"    style="width:' + pct(counts.pass)    + '%"></div>' +
      '</div>';

    // Sort: fail → warn → unknown → pass
    var ORDER = { fail: 0, warn: 1, unknown: 2, pass: 3 };
    var sorted = checks.slice().sort(function(a, b) {
      return (ORDER[a.status] || 0) - (ORDER[b.status] || 0);
    });

    sorted.forEach(function(c) {
      var card = document.createElement('div');
      card.className = 'compliance-card status-' + c.status;

      // Header
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

      // Description
      var desc = document.createElement('div');
      desc.className = 'cc-desc';
      desc.textContent = c.description;
      card.appendChild(desc);

      // Detail
      var detail = document.createElement('div');
      detail.className = 'cc-detail';
      detail.textContent = c.detail;
      card.appendChild(detail);

      // Fix link (fail/warn) with specific text
      if (c.fix_url && (c.status === 'fail' || c.status === 'warn')) {
        var fix = document.createElement('a');
        fix.className = 'cc-fix';
        fix.href = c.fix_url;
        fix.target = '_blank';
        fix.rel = 'noopener';
        fix.textContent = (COMPLIANCE_FIX_TEXT[c.id] || 'Fix in GitHub Settings') + ' →';
        card.appendChild(fix);
      }

      // Verify guidance (unknown)
      if (c.status === 'unknown') {
        var verify = document.createElement('div');
        verify.className = 'cc-verify';
        verify.textContent = '⚠ Cannot auto-verify — ' + (COMPLIANCE_VERIFY_TEXT[c.id] || 'Check org settings manually.');
        card.appendChild(verify);
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
    if (tabId === 'tab-attack-surface' && !graphBuilt && report) initAttackSurfaceGraph();
  });

  function updateTabCounts() {
    if (!report) return;
    setCount('count-pats', (report.pats || []).length);
    setCount('count-apps', (report.apps || []).length);

    var reqCount = (report.pending_requests || []).length;
    var pendingSection = document.getElementById('pending-section');
    if (pendingSection) pendingSection.style.display = reqCount > 0 ? 'block' : 'none';
    var countReqEl = document.getElementById('count-requests');
    if (countReqEl) countReqEl.textContent = String(reqCount);

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


  // --- Generic Detail Panel Helpers ---

  function buildRiskSection(assessment) {
    var section = document.createElement('div');
    section.className = 'detail-section';
    var title = document.createElement('div');
    title.className = 'detail-section-title';
    var issueCount = assessment.level === 'none' ? 0 : assessment.risks.length;
    title.textContent = issueCount > 0
      ? 'Risk Assessment (' + issueCount + ' issue' + (issueCount > 1 ? 's' : '') + ')'
      : 'Risk Assessment';
    section.appendChild(title);

    if (assessment.risks.length === 0) {
      var clean = document.createElement('div');
      clean.className = 'detail-clean-state';
      clean.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 8l2 2 3.5-3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> No issues found';
      section.appendChild(clean);
    } else {
      assessment.risks.forEach(function(risk) {
        var item = document.createElement('div');
        item.className = 'detail-risk-item';
        var dot = document.createElement('span');
        dot.className = 'detail-risk-dot ' + risk.severity;
        item.appendChild(dot);
        var msg = document.createElement('span');
        msg.textContent = risk.message;
        item.appendChild(msg);
        section.appendChild(item);
      });
    }
    return section;
  }

  function buildRecommendationsSection(assessment) {
    var section = document.createElement('div');
    section.className = 'detail-section';
    var title = document.createElement('div');
    title.className = 'detail-section-title';
    title.textContent = 'Recommendations';
    section.appendChild(title);

    assessment.recommendations.forEach(function(rec) {
      var recDiv = document.createElement('div');
      recDiv.className = 'detail-recommendation ' + (rec.urgent ? 'urgent' : (rec.action === 'No action needed' ? 'info' : 'warn'));
      recDiv.innerHTML = '<span class="rec-action">' + rec.action + ':</span><span class="rec-reason">' + rec.reason + '</span>';
      section.appendChild(recDiv);
    });
    return section;
  }

  function buildMetaSection(title, items) {
    var section = document.createElement('div');
    section.className = 'detail-section';
    var titleEl = document.createElement('div');
    titleEl.className = 'detail-section-title';
    titleEl.textContent = title;
    section.appendChild(titleEl);

    var grid = document.createElement('div');
    grid.className = 'detail-meta';
    items.forEach(function(item) {
      var metaItem = document.createElement('div');
      metaItem.className = 'detail-meta-item';
      var label = document.createElement('div');
      label.className = 'detail-meta-label';
      label.textContent = item.label;
      metaItem.appendChild(label);
      var value = document.createElement('div');
      value.className = 'detail-meta-value' + (item.cls ? ' ' + item.cls : '');
      value.textContent = item.value;
      metaItem.appendChild(value);
      if (item.sub) {
        var sub = document.createElement('div');
        sub.className = 'detail-meta-sub';
        sub.textContent = item.sub;
        metaItem.appendChild(sub);
      }
      grid.appendChild(metaItem);
    });
    section.appendChild(grid);
    return section;
  }

  function buildSupplyChainSection(scenarios) {
    var section = document.createElement('div');
    section.className = 'detail-section detail-full-width supply-chain-card';
    var title = document.createElement('div');
    title.className = 'detail-section-title';
    title.innerHTML = '&#9888; Supply Chain Impact';
    section.appendChild(title);

    scenarios.forEach(function(s) {
      var path = document.createElement('div');
      path.className = 'supply-chain-path';
      var icon = document.createElement('span');
      icon.className = 'supply-chain-icon';
      icon.textContent = s.icon || '⚠';
      path.appendChild(icon);
      var text = document.createElement('span');
      text.innerHTML = '<span class="supply-chain-label">' + s.label + '</span> ' + s.detail;
      path.appendChild(text);
      section.appendChild(path);
    });

    return section;
  }

  function buildDetailPanel(colSpan, sections) {
    var detailRow = document.createElement('tr');
    detailRow.className = 'detail-row';
    var dc = document.createElement('td');
    dc.colSpan = colSpan;
    dc.className = 'detail-cell';
    sections.forEach(function(s) { if (s) dc.appendChild(s); });
    detailRow.appendChild(dc);
    return detailRow;
  }

  function toggleDetailRow(tr, builder) {
    var existing = tr._detailRow;
    if (existing) {
      existing.remove();
      tr._detailRow = null;
      return;
    }
    var detailRow = builder();
    tr._detailRow = detailRow;
    tr.parentNode.insertBefore(detailRow, tr.nextSibling);
  }

  // --- App Detail Panel ---

  function renderAppDetailPanel(app, colSpan) {
    var assessment = assessAppRisk(app);
    var perms = app.permissions || [];

    var scenarios = [];
    var hasContentsWrite = false, hasWorkflowsWrite = false, hasSecretsAccess = false;
    perms.forEach(function(p) {
      if (p.name === 'contents' && (p.level === 'write' || p.level === 'admin')) hasContentsWrite = true;
      if (p.name === 'workflows' && (p.level === 'write' || p.level === 'admin')) hasWorkflowsWrite = true;
      if ((p.name === 'organization_secrets' || p.name === 'secrets') && p.level !== 'none') hasSecretsAccess = true;
    });

    if (hasContentsWrite && app.repository_selection === 'all') {
      scenarios.push({ icon: '💣', label: 'Code Injection:', detail: 'Can push malicious code to <strong>all ' + (supplyChainMap ? supplyChainMap.totalRepos : 'N') + ' repositories</strong>, compromising builds and deployments.' });
    } else if (hasContentsWrite) {
      scenarios.push({ icon: '💣', label: 'Code Injection:', detail: 'Can push malicious code to selected repositories.' });
    }
    if (hasWorkflowsWrite) {
      scenarios.push({ icon: '⚙', label: 'Pipeline Hijack:', detail: 'Can modify CI/CD workflows to inject build-time backdoors, steal secrets, or tamper with artifacts.' });
    }
    if (hasSecretsAccess) {
      scenarios.push({ icon: '🔑', label: 'Credential Theft:', detail: 'Can read organization secrets including API keys, tokens, and service credentials.' });
    }
    if (app.repository_selection === 'all' && !hasContentsWrite) {
      scenarios.push({ icon: '🌐', label: 'Broad Access:', detail: 'Has access to all ' + (supplyChainMap ? supplyChainMap.totalRepos : 'N') + ' repositories — increases blast radius of any compromise.' });
    }

    var metaItems = [
      { label: 'App Name', value: app.app_name },
      { label: 'Slug', value: app.app_slug },
      { label: 'Installed', value: new Date(app.created_at).toLocaleDateString(), sub: timeAgo(app.created_at) },
      { label: 'Last Updated', value: new Date(app.updated_at).toLocaleDateString(), sub: timeAgo(app.updated_at) },
      { label: 'Status', value: app.suspended ? 'Suspended' : 'Active', cls: app.suspended ? 'warn' : '' },
      { label: 'Repo Access', value: app.repository_selection, cls: app.repository_selection === 'all' ? 'danger' : '' },
      { label: 'Events', value: (app.events || []).join(', ') || 'None' },
      { label: 'Permissions', value: app.high_risk_count + ' high, ' + app.medium_risk_count + ' medium, ' + app.low_risk_count + ' low' },
    ];

    var sections = [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
    ];
    if (scenarios.length > 0) sections.push(buildSupplyChainSection(scenarios));
    sections.push(buildMetaSection('Installation Details', metaItems));

    return buildDetailPanel(colSpan, sections);
  }

  // --- Secret Detail Panel ---

  function renderSecretDetailPanel(secret, colSpan) {
    var assessment = assessSecretRisk(secret);

    var scenarios = [];
    var m = supplyChainMap;
    if (secret.scope === 'org') {
      var repoCount = m ? m.totalRepos : '?';
      var wfCount = 0;
      if (m) { Object.keys(m.repoToWorkflows).forEach(function(r) { wfCount += m.repoToWorkflows[r].length; }); }
      if (secret.visibility === 'all') {
        scenarios.push({ icon: '💣', label: 'Full Blast Radius:', detail: 'Accessible by workflows in <strong>all ' + repoCount + ' repositories</strong>. Any compromised workflow can exfiltrate this secret.' });
      } else if (secret.visibility === 'private') {
        scenarios.push({ icon: '⚠', label: 'Wide Exposure:', detail: 'Accessible by all private repository workflows. Compromising any private repo workflow leaks this secret.' });
      } else {
        scenarios.push({ icon: '🔒', label: 'Scoped Access:', detail: 'Limited to selected repositories only.' });
      }
      if (wfCount > 0) {
        scenarios.push({ icon: '⚙', label: 'Workflow Exposure:', detail: wfCount + ' workflow(s) across ' + Object.keys(m.repoToWorkflows).length + ' repositories could access this secret at runtime.' });
      }
    } else if (secret.scope === 'repo') {
      var repoWfs = m && m.repoToWorkflows[secret.repo_name] ? m.repoToWorkflows[secret.repo_name].length : 0;
      scenarios.push({ icon: '🔒', label: 'Repo-scoped:', detail: 'Only accessible within <strong>' + secret.repo_name + '</strong>' + (repoWfs > 0 ? ' (' + repoWfs + ' workflow' + (repoWfs > 1 ? 's' : '') + ')' : '') + '.' });
    } else if (secret.scope === 'environment') {
      scenarios.push({ icon: '✅', label: 'Environment-scoped:', detail: 'Narrowest blast radius — only accessible in <strong>' + secret.env_name + '</strong> environment of <strong>' + (secret.repo_name || 'unknown') + '</strong>.' });
    }

    if (SENSITIVE_SECRET_PATTERNS.test(secret.name)) {
      scenarios.push({ icon: '🔑', label: 'High-Value Target:', detail: 'Name pattern suggests this is a credential (API key, token, or password). Exfiltration enables lateral movement.' });
    }

    var metaItems = [
      { label: 'Name', value: secret.name },
      { label: 'Scope', value: secret.scope },
      { label: 'Visibility', value: secret.visibility || 'N/A', cls: secret.visibility === 'all' ? 'danger' : (secret.visibility === 'private' ? 'warn' : '') },
      { label: 'Repository', value: secret.repo_name || 'N/A (org-level)' },
      { label: 'Environment', value: secret.env_name || 'N/A' },
      { label: 'Created', value: secret.created_at ? new Date(secret.created_at).toLocaleDateString() : 'Unknown', sub: secret.created_at ? timeAgo(secret.created_at) : '' },
      { label: 'Last Updated', value: secret.updated_at ? new Date(secret.updated_at).toLocaleDateString() : 'Unknown', sub: secret.updated_at ? timeAgo(secret.updated_at) : '' },
      { label: 'Risk Level', value: secret.risk || 'low', cls: secret.risk === 'high' ? 'danger' : (secret.risk === 'medium' ? 'warn' : '') },
    ];

    var sections = [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
    ];
    if (scenarios.length > 0) sections.push(buildSupplyChainSection(scenarios));
    sections.push(buildMetaSection('Secret Details', metaItems));

    return buildDetailPanel(colSpan, sections);
  }

  // --- Deploy Key Detail Panel ---

  var DEPLOY_KEY_LOCATION_HINTS = [
    { pattern: /jenkins/i,       host: 'Jenkins CI server',          tip: 'Private key is likely stored on disk in the Jenkins agent home directory or as a Jenkins credential. Compromise of the Jenkins server exposes this key.' },
    { pattern: /buildkite/i,     host: 'Buildkite agent machine',    tip: 'Private key lives on the Buildkite agent host. If the agent runs on EC2 or a shared build machine, disk access is sufficient to steal it.' },
    { pattern: /github.action/i, host: 'GitHub Actions secret',      tip: 'Private key is stored as a repository or org Actions secret. Workflows that access secrets can exfiltrate the key during a run.' },
    { pattern: /aws|ec2/i,       host: 'AWS EC2 instance',           tip: 'Private key is likely on an EC2 instance. Instance compromise (SSRF, RCE, leaked IAM role) gives attacker access to this key file.' },
    { pattern: /grafana/i,       host: 'Grafana server',             tip: 'Read access used by Grafana for config sync. Grafana RCE or plugin exploit could expose the private key file.' },
    { pattern: /datadog/i,       host: 'Datadog agent',              tip: 'Used by Datadog for APM/release tracking. Datadog agent compromise or misconfigured API token could expose the key.' },
    { pattern: /sentry/i,        host: 'Sentry release worker',      tip: 'Used to tag Sentry releases. Sentry DSN leak or worker compromise could expose the private key.' },
    { pattern: /laptop|macbook|local|dev/i, host: 'Developer laptop', tip: 'Private key lives on a personal machine. Laptop theft, disk image, or malware gives full access.' },
    { pattern: /deploy.key|ssh.key|id_rsa|id_ed/i, host: 'Unknown host', tip: 'Generic name — cannot determine where the private key lives. Audit who added this and whether the machine is still in use.' },
  ];

  function getDeployKeyLocationHint(title) {
    for (var i = 0; i < DEPLOY_KEY_LOCATION_HINTS.length; i++) {
      if (DEPLOY_KEY_LOCATION_HINTS[i].pattern.test(title)) return DEPLOY_KEY_LOCATION_HINTS[i];
    }
    return null;
  }

  function renderDeployKeyDetailPanel(key, colSpan) {
    var assessment = assessDeployKeyRisk(key);
    var repoWfs = supplyChainMap && supplyChainMap.repoToWorkflows[key.repo_name] ? supplyChainMap.repoToWorkflows[key.repo_name].length : 0;
    var repoSecs = supplyChainMap && supplyChainMap.repoToSecrets[key.repo_name] ? supplyChainMap.repoToSecrets[key.repo_name].length : 0;

    // Supply chain scenarios
    var scenarios = [];
    if (!key.read_only) {
      scenarios.push({ icon: '💣', label: 'Code Injection:', detail: 'Write access to <strong>' + key.repo_name + '</strong> — attacker can push malicious commits, modify workflow YAML, and backdoor releases without opening a PR.' });
      if (repoWfs > 0) {
        scenarios.push({ icon: '⚙', label: 'Pipeline Hijack:', detail: 'Repo has <strong>' + repoWfs + ' workflow(s)</strong> — a malicious commit can modify workflow YAML to exfiltrate secrets or deploy to production.' });
      }
      if (repoSecs > 0) {
        scenarios.push({ icon: '🔑', label: 'Secret Exfiltration:', detail: 'Repo has <strong>' + repoSecs + ' Actions secret(s)</strong> — modified workflow can print them to logs or POST them to an attacker-controlled endpoint.' });
      }
    } else {
      scenarios.push({ icon: '🔒', label: 'Read Only:', detail: 'Can clone/pull <strong>' + key.repo_name + '</strong> but cannot push. Source code exfiltration is still possible if the repo contains credentials, tokens, or business logic.' });
      if (repoSecs > 0) {
        scenarios.push({ icon: '⚠', label: 'Source Exposure:', detail: 'Repo has <strong>' + repoSecs + ' Actions secret(s)</strong> — even read-only access to source may expose hardcoded secrets or API keys in code.' });
      }
    }

    // Location hint section
    var locationHint = getDeployKeyLocationHint(key.title);
    var locationItems = [];
    if (locationHint) {
      locationItems = [
        { label: 'Likely Host', value: locationHint.host },
        { label: 'Exposure Path', value: locationHint.tip },
      ];
    } else {
      locationItems = [{ label: 'Likely Host', value: 'Unknown — review key title and who added it' }];
    }

    // Stale analysis
    var staleNote = '';
    if (!key.last_used) {
      staleNote = 'Never used since creation. The private key holder may have lost it or the service was decommissioned — but the key still grants access.';
    } else {
      var days = daysBetween(new Date(key.last_used), new Date());
      if (days > 180) staleNote = 'Not used in ' + days + ' days. The service or machine using this key may be decommissioned, but the key still grants ' + (key.read_only ? 'read' : 'write') + ' access.';
    }

    var metaItems = [
      { label: 'Title', value: key.title },
      { label: 'Repository', value: key.repo_name },
      { label: 'Access', value: key.read_only ? 'Read-only' : 'Read-write', cls: key.read_only ? '' : 'danger' },
      { label: 'Added By', value: key.added_by || 'Unknown — cannot attribute', cls: key.added_by ? '' : 'warn' },
      { label: 'Created', value: new Date(key.created_at).toLocaleDateString(), sub: timeAgo(key.created_at) },
      { label: 'Last Used', value: key.last_used ? new Date(key.last_used).toLocaleDateString() : 'Never', cls: key.last_used ? '' : 'warn', sub: key.last_used ? timeAgo(key.last_used) : '' },
      { label: 'Workflows in Repo', value: repoWfs > 0 ? repoWfs + ' workflow(s)' : 'None found' },
      { label: 'Secrets in Repo', value: repoSecs > 0 ? repoSecs + ' secret(s)' : 'None found' },
    ];

    var sections = [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
      buildSupplyChainSection(scenarios),
      buildMetaSection('Private Key Location', locationItems),
    ];

    if (staleNote) {
      var staleSection = buildMetaSection('Stale Key Warning', [{ label: 'Analysis', value: staleNote, cls: 'warn' }]);
      sections.push(staleSection);
    }

    sections.push(buildMetaSection('Key Details', metaItems));

    return buildDetailPanel(colSpan, sections);
  }

  // --- Workflow File Detail Panel ---

  function renderWorkflowFileDetailPanel(file, colSpan) {
    var assessment = assessWorkflowRisk(file);

    var scenarios = [];
    if (file.permissions === 'write-all' || file.permissions === 'not set') {
      scenarios.push({ icon: '💣', label: 'Token Abuse:', detail: 'GITHUB_TOKEN has write access — workflow can push code, create releases, modify branch protections in <strong>' + file.repo_name + '</strong>.' });
    }
    if (file.unpinned_actions && file.unpinned_actions.length > 0) {
      file.unpinned_actions.forEach(function(action) {
        scenarios.push({ icon: '⛔', label: 'Action Hijack:', detail: '<code>' + action + '</code> is referenced by tag. An attacker who compromises the action repo can overwrite the tag to inject malicious code into your builds.' });
      });
    }
    if (scenarios.length === 0) {
      scenarios.push({ icon: '✅', label: 'Secure:', detail: 'This workflow has explicit permissions and all actions are pinned to SHA — minimal supply chain risk.' });
    }

    var metaItems = [
      { label: 'Repository', value: file.repo_name },
      { label: 'Workflow', value: file.file_name },
      { label: 'Path', value: file.path },
      { label: 'Permissions', value: file.permissions || 'not set', cls: (file.permissions === 'write-all' || file.permissions === 'not set') ? 'danger' : '' },
      { label: 'Actions Pinned', value: file.has_pinned_actions ? 'Yes' : 'No' },
      { label: 'Unpinned Actions', value: (file.unpinned_actions || []).length + '' },
    ];

    return buildDetailPanel(colSpan, [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
      buildSupplyChainSection(scenarios),
      buildMetaSection('Workflow Details', metaItems),
    ]);
  }

  // --- Workflow Perm Detail Panel ---

  function renderWorkflowPermDetailPanel(perm, colSpan) {
    var assessment = assessWorkflowPermRisk(perm);

    var scenarios = [];
    if (perm.default_permission === 'write') {
      scenarios.push({ icon: '💣', label: 'Privilege Escalation:', detail: 'Every workflow in <strong>' + perm.repo_name + '</strong> gets a write token by default — can push code, create tags, and modify other workflows.' });
    }
    if (perm.can_approve_pull_requests) {
      scenarios.push({ icon: '⚠', label: 'Review Bypass:', detail: 'Workflows can auto-approve PRs — an attacker can create a PR and merge it without human review.' });
    }
    if (scenarios.length === 0) {
      scenarios.push({ icon: '✅', label: 'Secure:', detail: 'Read-only default token and no PR auto-approval — minimal supply chain risk.' });
    }

    return buildDetailPanel(colSpan, [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
      buildSupplyChainSection(scenarios),
    ]);
  }

  // --- SSO Credential Detail Panel ---

  function renderSSODetailPanel(cred, colSpan) {
    var assessment = assessSSORisk(cred);

    var scenarios = [];
    var isClassic = cred.credential_type === 'personal access token';
    var broadScopes = [];
    (cred.scopes || []).forEach(function(s) { if (HIGH_RISK_SSO_SCOPES[s]) broadScopes.push(s); });

    if (isClassic && broadScopes.indexOf('repo') >= 0) {
      scenarios.push({ icon: '💣', label: 'Full Repo Access:', detail: 'Classic PAT with <code>repo</code> scope — can read/write code, secrets, and settings in all accessible repositories.' });
    }
    if (broadScopes.indexOf('admin:org') >= 0) {
      scenarios.push({ icon: '💣', label: 'Org Admin:', detail: '<code>admin:org</code> scope grants full organization control — membership, teams, billing, and security settings.' });
    }
    if (broadScopes.indexOf('workflow') >= 0) {
      scenarios.push({ icon: '⚙', label: 'Workflow Control:', detail: '<code>workflow</code> scope allows modifying GitHub Actions workflows — supply chain injection vector.' });
    }
    if (broadScopes.indexOf('write:packages') >= 0) {
      scenarios.push({ icon: '📦', label: 'Package Tampering:', detail: '<code>write:packages</code> scope allows publishing malicious packages to the org registry.' });
    }
    if (isClassic && broadScopes.length === 0) {
      scenarios.push({ icon: '⚠', label: 'Classic PAT:', detail: 'Classic PATs cannot be scoped to specific repos — always have access based on user permissions.' });
    }
    if (!isClassic) {
      scenarios.push({ icon: '🔑', label: 'SSH Key:', detail: 'SSH keys grant Git push/pull access to all repos the user can access.' });
    }

    var metaItems = [
      { label: 'Owner', value: cred.login },
      { label: 'Credential Type', value: cred.credential_type },
      { label: 'Title', value: cred.authorized_credential_title || 'N/A' },
      { label: 'Identifier', value: cred.token_last_eight || cred.credential_id || 'N/A' },
      { label: 'SSO Authorized', value: cred.credential_authorized_at ? new Date(cred.credential_authorized_at).toLocaleDateString() : 'Unknown', sub: cred.credential_authorized_at ? timeAgo(cred.credential_authorized_at) : '' },
      { label: 'Last Accessed', value: cred.credential_accessed_at ? new Date(cred.credential_accessed_at).toLocaleDateString() : 'Never', cls: cred.credential_accessed_at ? '' : 'warn', sub: cred.credential_accessed_at ? timeAgo(cred.credential_accessed_at) : '' },
      { label: 'Expires', value: cred.authorized_credential_expires_at ? new Date(cred.authorized_credential_expires_at).toLocaleDateString() : 'Never', cls: cred.authorized_credential_expires_at ? '' : 'danger' },
      { label: 'Scopes', value: (cred.scopes || []).join(', ') || 'N/A' },
    ];

    return buildDetailPanel(colSpan, [
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
      buildSupplyChainSection(scenarios),
      buildMetaSection('Credential Details', metaItems),
    ]);
  }

  // === Secret Impact Heuristics ===

  var SECRET_IMPACT_MAP = [
    { pattern: /AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION/i, provider: 'AWS', icon: '☁',
      impact: 'Full AWS account access — EC2 instances, S3 buckets, IAM roles, Lambda functions, RDS databases',
      chain: 'Attacker can provision infrastructure, exfiltrate data from S3, escalate IAM privileges, pivot to internal networks via EC2' },
    { pattern: /GCP_|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_SERVICE_ACCOUNT|GCLOUD/i, provider: 'Google Cloud', icon: '☁',
      impact: 'Google Cloud project access — Compute Engine, Cloud Storage, BigQuery, Cloud Functions',
      chain: 'Attacker can access stored data, deploy workloads, escalate via service account impersonation' },
    { pattern: /AZURE_|ARM_CLIENT|ARM_TENANT|AZURE_CREDENTIALS/i, provider: 'Azure', icon: '☁',
      impact: 'Azure subscription access — VMs, Blob Storage, Key Vault, Azure AD',
      chain: 'Attacker can access Key Vault secrets, pivot across subscriptions, compromise Azure AD identities' },
    { pattern: /DOCKER_PASSWORD|DOCKER_TOKEN|DOCKERHUB|REGISTRY_PASSWORD/i, provider: 'Container Registry', icon: '📦',
      impact: 'Container registry push access — can overwrite production images',
      chain: 'Attacker pushes backdoored images that deploy to all environments pulling from this registry (supply chain)' },
    { pattern: /NPM_TOKEN|NPM_AUTH/i, provider: 'npm', icon: '📦',
      impact: 'npm package publishing access — can publish malicious package versions',
      chain: 'Attacker publishes trojanized package update, compromising all downstream consumers (supply chain attack)' },
    { pattern: /PYPI_|TWINE_PASSWORD/i, provider: 'PyPI', icon: '📦',
      impact: 'PyPI package publishing access — can publish malicious Python packages',
      chain: 'Attacker publishes backdoored package version affecting all pip install consumers' },
    { pattern: /DATABASE_URL|DB_PASSWORD|DB_HOST|MYSQL_|POSTGRES_|MONGO_URI|REDIS_URL/i, provider: 'Database', icon: '🗄',
      impact: 'Direct database access — read/write/delete production data',
      chain: 'Attacker can exfiltrate PII/financial data, drop tables, inject records, pivot via stored credentials' },
    { pattern: /STRIPE_SECRET|STRIPE_KEY|PAYMENT_|RAZORPAY_SECRET/i, provider: 'Payment', icon: '💳',
      impact: 'Payment processing access — can issue refunds, read transaction data, modify payment flows',
      chain: 'Attacker can steal payment data, issue fraudulent refunds, redirect payment flows' },
    { pattern: /SLACK_TOKEN|SLACK_BOT|SLACK_WEBHOOK/i, provider: 'Slack', icon: '💬',
      impact: 'Slack workspace access — read messages, post as bot, access shared files',
      chain: 'Attacker can phish employees via trusted bot identity, exfiltrate messages containing credentials' },
    { pattern: /SSH_PRIVATE_KEY|SSH_KEY|DEPLOY_KEY/i, provider: 'SSH', icon: '🔑',
      impact: 'SSH access to servers — remote shell access to production infrastructure',
      chain: 'Attacker can access production servers, move laterally, install persistent backdoors' },
    { pattern: /JWT_SECRET|SECRET_KEY|ENCRYPTION_KEY|SIGNING_KEY/i, provider: 'Cryptographic', icon: '🔐',
      impact: 'Cryptographic key — can forge tokens, decrypt data, bypass authentication',
      chain: 'Attacker can forge admin JWT tokens, impersonate any user, decrypt stored secrets' },
    { pattern: /TERRAFORM_|TF_TOKEN|TF_VAR/i, provider: 'Terraform', icon: '🏗',
      impact: 'Infrastructure-as-Code access — can modify cloud infrastructure definitions',
      chain: 'Attacker can modify Terraform state/plans to provision backdoored infrastructure on next apply' },
    { pattern: /SENTRY_DSN|SENTRY_AUTH|DATADOG_API|DD_API_KEY|NEWRELIC/i, provider: 'Monitoring', icon: '📊',
      impact: 'Monitoring platform access — can read error logs, PII in stack traces, application telemetry',
      chain: 'Attacker can extract credentials from error logs, suppress alerts to hide ongoing attack' },
    { pattern: /GITHUB_TOKEN|GH_TOKEN|GH_PAT/i, provider: 'GitHub', icon: '🐙',
      impact: 'GitHub API access — can read/write repos, manage issues, trigger workflows',
      chain: 'Attacker can push malicious code, modify CI workflows, access private repos' },
  ];

  function getSecretImpact(secretName) {
    for (var i = 0; i < SECRET_IMPACT_MAP.length; i++) {
      if (SECRET_IMPACT_MAP[i].pattern.test(secretName)) return SECRET_IMPACT_MAP[i];
    }
    return null;
  }

  // === Attack Surface Graph ===

  function sanitizeGraphId(str) {
    return str.replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  function buildAttackGraph(data) {
    var nodes = [], edges = [], nodeMap = {}, edgeMap = {};
    var repoSet = {};

    function addNode(id, type, label, entity, risk) {
      if (nodeMap[id]) return;
      nodeMap[id] = true;
      nodes.push({ data: { id: id, type: type, label: label, entity: entity, risk: risk || 'none' } });
    }

    var EDGE_LABELS = { can_modify: 'CAN_WRITE', has_access: 'CAN_READ', can_hijack: 'USES',
      can_trigger: 'HAS_WORKFLOW', exposes_secret: 'HAS_SECRET', includes: 'VISIBLE_TO' };

    function addEdge(source, target, type) {
      if (!nodeMap[source] && source !== 'allrepos') return;
      var key = source + '|' + target + '|' + type;
      if (edgeMap[key]) return;
      edgeMap[key] = true;
      edges.push({ data: { id: 'e-' + edges.length, source: source, target: target, edgeType: type, label: EDGE_LABELS[type] || type } });
    }

    // Collect known repos from workflow, deploy key, and secret data
    (data.workflow_files || []).forEach(function(wf) { repoSet[wf.repo_name] = true; });
    (data.deploy_keys || []).forEach(function(dk) { repoSet[dk.repo_name] = true; });
    (data.secrets || []).forEach(function(s) { if (s.repo_name) repoSet[s.repo_name] = true; });
    var knownRepos = Object.keys(repoSet);
    var needAllRepos = false;

    // --- Entry Points (top tier) ---

    (data.pats || []).forEach(function(p) {
      if (p.token_expired) return;
      var a = assessPATRisk(p);
      var id = 'pat-' + p.id;
      var keyPerm = '';
      (p.permissions || []).forEach(function(perm) { if (perm.level === 'admin') keyPerm = perm.name + ':admin'; });
      if (!keyPerm) (p.permissions || []).forEach(function(perm) { if (perm.level === 'write' && !keyPerm) keyPerm = perm.name + ':write'; });
      var patLabel = 'PAT ' + (p.owner_login || p.token_name);
      if (keyPerm) patLabel += '\n(' + keyPerm + ')';
      addNode(id, 'pat', patLabel, p, a.level);
      var hasWrite = (p.permissions || []).some(function(perm) { return perm.level === 'write' || perm.level === 'admin'; });
      if (p.repository_selection === 'all') {
        needAllRepos = true;
        addEdge(id, 'allrepos', hasWrite ? 'can_modify' : 'has_access');
      }
    });

    (data.apps || []).forEach(function(app) {
      if (app.suspended) return;
      var a = assessAppRisk(app);
      var id = 'app-' + app.id;
      var appKeyPerm = '';
      (app.permissions || []).forEach(function(perm) { if ((perm.level === 'write' || perm.level === 'admin') && !appKeyPerm) appKeyPerm = perm.name; });
      var appLabel = 'App ' + app.app_name;
      if (app.repository_selection || appKeyPerm) appLabel += '\n(' + (app.repository_selection || '') + (appKeyPerm ? ' · ' + appKeyPerm : '') + ')';
      addNode(id, 'app', appLabel, app, a.level);
      var hasWrite = (app.permissions || []).some(function(perm) { return perm.level === 'write' || perm.level === 'admin'; });
      if (app.repository_selection === 'all') {
        needAllRepos = true;
        addEdge(id, 'allrepos', hasWrite ? 'can_modify' : 'has_access');
      }
    });

    (data.sso_credentials || []).forEach(function(c) {
      var a = assessSSORisk(c);
      var id = 'sso-' + sanitizeGraphId(c.login + '-' + (c.credential_id || c.token_last_eight || ''));
      addNode(id, 'sso', c.login, c, a.level);
      var hasWrite = (c.scopes || []).some(function(s) {
        return s === 'repo' || s === 'admin:org' || s === 'write:packages' || s === 'delete_repo' || s === 'workflow';
      });
      needAllRepos = true;
      addEdge(id, 'allrepos', hasWrite ? 'can_modify' : 'has_access');
    });

    (data.deploy_keys || []).forEach(function(dk) {
      var a = assessDeployKeyRisk(dk);
      var id = 'dk-' + dk.id;
      addNode(id, 'deploy_key', dk.title || 'Key', dk, a.level);
      var repoId = 'repo-' + sanitizeGraphId(dk.repo_name);
      addNode(repoId, 'repo', dk.repo_name.split('/').pop(), { repo_name: dk.repo_name }, 'none');
      addEdge(id, repoId, dk.read_only ? 'has_access' : 'can_modify');
    });

    // --- Synthetic "All Repos" hub ---

    if (needAllRepos) {
      var totalRepos = (data.summary || {}).total_repos_scanned || knownRepos.length;
      addNode('allrepos', 'allrepos', '⚠ ~' + totalRepos + ' REPOS\n(visibility=all)', { total: totalRepos }, 'high');
      knownRepos.forEach(function(rn) {
        var repoId = 'repo-' + sanitizeGraphId(rn);
        addNode(repoId, 'repo', rn.split('/').pop(), { repo_name: rn }, 'none');
        addEdge('allrepos', repoId, 'includes');
      });
    }

    // --- Resources (middle tier) ---

    var wfCap = (data.workflow_files || []).slice(0, 200);
    wfCap.forEach(function(wf) {
      var a = assessWorkflowRisk(wf);
      var id = 'wf-' + sanitizeGraphId(wf.repo_name + '-' + wf.file_name);
      addNode(id, 'workflow', wf.file_name.replace(/\.ya?ml$/, ''), wf, a.level);
      var repoId = 'repo-' + sanitizeGraphId(wf.repo_name);
      addNode(repoId, 'repo', wf.repo_name.split('/').pop(), { repo_name: wf.repo_name }, 'none');
      addEdge(repoId, id, 'can_trigger');

      (wf.unpinned_actions || []).forEach(function(action, i) {
        var actionId = 'action-' + sanitizeGraphId(wf.repo_name + '-' + wf.file_name + '-' + i);
        addNode(actionId, 'action', action + '\n(unpinned)', { name: action, workflow: wf.file_name, repo: wf.repo_name }, 'high');
        addEdge(actionId, id, 'can_hijack');
      });
    });

    // --- Infrastructure (bottom tier) ---

    var secCap = (data.secrets || []).slice(0, 100);
    secCap.forEach(function(s) {
      var a = assessSecretRisk(s);
      var id = 'secret-' + sanitizeGraphId(s.scope + '-' + s.name + '-' + (s.repo_name || 'org'));
      addNode(id, 'secret', s.name, s, a.level);

      if (s.scope === 'org') {
        if (nodeMap['allrepos']) {
          addEdge('allrepos', id, 'exposes_secret');
        } else {
          knownRepos.forEach(function(rn) { addEdge('repo-' + sanitizeGraphId(rn), id, 'exposes_secret'); });
        }
      } else if (s.repo_name) {
        var repoId = 'repo-' + sanitizeGraphId(s.repo_name);
        addNode(repoId, 'repo', s.repo_name.split('/').pop(), { repo_name: s.repo_name }, 'none');
        addEdge(repoId, id, 'exposes_secret');
      }
    });

    // Compute repo risk from connected entities
    var rw = { high: 3, medium: 2, low: 1, none: 0 };
    nodes.forEach(function(n) {
      if (n.data.type !== 'repo') return;
      var rn = n.data.entity.repo_name;
      var worst = 'none';
      (supplyChainMap.repoToWorkflows[rn] || []).forEach(function(wf) {
        var a = assessWorkflowRisk(wf); if ((rw[a.level] || 0) > (rw[worst] || 0)) worst = a.level;
      });
      if (supplyChainMap.writeRepos.has(rn) && worst === 'none') worst = 'medium';
      n.data.risk = worst;
    });

    return { nodes: nodes, edges: edges };
  }

  function getCytoscapeStylesheet() {
    return [
      // ── Base node ──────────────────────────────────────────────
      { selector: 'node', style: {
        'shape': 'ellipse',
        'label': 'data(label)',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'font-size': '11px',
        'font-weight': '600',
        'color': '#0f172a',
        'text-margin-y': 7,
        'text-max-width': '120px',
        'text-wrap': 'wrap',
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.85,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
        'border-width': 2,
        'border-color': '#2d3748',
        'border-opacity': 0.6,
        'width': 44, 'height': 44,
      }},

      // ── Node types ─────────────────────────────────────────────
      { selector: 'node[type="pat"]', style: {
        'background-color': '#F97316',
        'border-color': '#FB923C', 'border-width': 2.5, 'border-opacity': 1,
        'width': 56, 'height': 56,
        'shadow-blur': 14, 'shadow-color': '#F97316', 'shadow-opacity': 0.5, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="app"]', style: {
        'background-color': '#F97316',
        'border-color': '#FB923C', 'border-width': 2.5, 'border-opacity': 1,
        'width': 56, 'height': 56,
        'shadow-blur': 14, 'shadow-color': '#F97316', 'shadow-opacity': 0.5, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="sso"]', style: {
        'background-color': '#EC4899',
        'border-color': '#F472B6', 'border-width': 2, 'border-opacity': 1,
        'width': 48, 'height': 48,
        'shadow-blur': 12, 'shadow-color': '#EC4899', 'shadow-opacity': 0.4, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="deploy_key"]', style: {
        'background-color': '#D97706',
        'border-color': '#F59E0B', 'border-width': 2, 'border-opacity': 1,
        'width': 46, 'height': 46,
        'shadow-blur': 10, 'shadow-color': '#D97706', 'shadow-opacity': 0.4, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="allrepos"]', style: {
        'background-color': '#1D4ED8',
        'border-color': '#60A5FA', 'border-width': 3, 'border-opacity': 1,
        'width': 96, 'height': 96,
        'font-size': '12px', 'font-weight': 'bold', 'color': '#0f172a',
        'text-background-color': '#dbeafe', 'text-background-opacity': 0.95,
        'shadow-blur': 22, 'shadow-color': '#3B82F6', 'shadow-opacity': 0.6, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="repo"]', style: {
        'background-color': '#2563EB',
        'border-color': '#60A5FA', 'border-width': 2, 'border-opacity': 0.8,
        'width': 50, 'height': 50,
        'shadow-blur': 10, 'shadow-color': '#3B82F6', 'shadow-opacity': 0.35, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="workflow"]', style: {
        'background-color': '#16A34A',
        'border-color': '#4ADE80', 'border-width': 2, 'border-opacity': 0.8,
        'width': 42, 'height': 42,
        'shadow-blur': 8, 'shadow-color': '#22C55E', 'shadow-opacity': 0.3, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="action"]', style: {
        'background-color': '#7C3AED',
        'border-color': '#A78BFA', 'border-width': 2, 'border-opacity': 0.8,
        'width': 36, 'height': 36,
        'shadow-blur': 8, 'shadow-color': '#8B5CF6', 'shadow-opacity': 0.3, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: 'node[type="secret"]', style: {
        'background-color': '#DC2626',
        'border-color': '#F87171', 'border-width': 2.5, 'border-opacity': 1,
        'width': 54, 'height': 54,
        'shadow-blur': 16, 'shadow-color': '#EF4444', 'shadow-opacity': 0.55, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},

      // ── Risk border overlays ───────────────────────────────────
      { selector: 'node[risk="high"]', style: {
        'border-width': 3.5, 'border-color': '#FCA5A5', 'border-opacity': 1,
      }},
      { selector: 'node[risk="medium"]', style: {
        'border-width': 2.5, 'border-color': '#FCD34D', 'border-opacity': 0.9,
      }},

      // ── Edges ──────────────────────────────────────────────────
      { selector: 'edge', style: {
        'width': 1.5,
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'target-arrow-color': '#64748b',
        'line-color': '#334155',
        'arrow-scale': 0.9,
        'opacity': 0.75,
        'label': 'data(label)',
        'font-size': '8.5px',
        'font-weight': '500',
        'color': '#334155',
        'text-rotation': 'autorotate',
        'text-margin-y': -9,
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.92,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
      }},
      { selector: 'edge[edgeType="can_modify"]', style: {
        'line-color': '#f87171', 'target-arrow-color': '#f87171',
        'width': 2, 'opacity': 0.85,
      }},
      { selector: 'edge[edgeType="has_access"]', style: {
        'line-color': '#60a5fa', 'target-arrow-color': '#60a5fa',
        'opacity': 0.7,
      }},
      { selector: 'edge[edgeType="exposes_secret"]', style: {
        'line-color': '#fb923c', 'target-arrow-color': '#fb923c',
        'width': 2, 'opacity': 0.8,
        'line-style': 'dashed',
      }},
      { selector: 'edge[edgeType="can_hijack"]', style: {
        'line-color': '#c084fc', 'target-arrow-color': '#c084fc',
        'line-style': 'dashed', 'opacity': 0.75,
      }},
      { selector: 'edge[edgeType="can_trigger"]', style: {
        'line-color': '#4ade80', 'target-arrow-color': '#4ade80',
        'opacity': 0.65,
      }},
      { selector: 'edge[edgeType="includes"]', style: {
        'line-style': 'dotted', 'opacity': 0.25, 'label': '',
      }},

      // ── Interaction states ─────────────────────────────────────
      { selector: '.dimmed', style: { 'opacity': 0.07 }},
      { selector: '.highlighted', style: {
        'opacity': 1,
        'border-width': 4, 'border-color': '#ffffff', 'border-opacity': 1,
        'shadow-blur': 20, 'shadow-color': '#ffffff', 'shadow-opacity': 0.4,
        'shadow-offset-x': 0, 'shadow-offset-y': 0,
      }},
      { selector: '.blast-source', style: {
        'opacity': 1,
        'border-width': 5, 'border-color': '#ffffff',
        'shadow-blur': 28, 'shadow-color': '#ffffff', 'shadow-opacity': 0.6,
        'shadow-offset-x': 0, 'shadow-offset-y': 0,
        'color': '#ffffff', 'font-weight': 'bold',
      }},
      { selector: 'edge.highlighted', style: {
        'opacity': 1, 'width': 2.5,
        'line-color': '#e2e8f0', 'target-arrow-color': '#e2e8f0',
      }},
      { selector: '.filtered-out', style: { 'display': 'none' }},
    ];
  }

  function initAttackSurfaceGraph() {
    if (!report || graphBuilt) return;
    var container = document.getElementById('cy-container');
    if (!container) return;

    var graphData = buildAttackGraph(report);
    if (graphData.nodes.length === 0) {
      container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#8899aa;font-size:14px">No data to visualize. Run a scan first.</div>';
      graphBuilt = true;
      return;
    }

    cyInstance = cytoscape({
      container: container,
      elements: { nodes: graphData.nodes, edges: graphData.edges },
      style: getCytoscapeStylesheet(),
      layout: {
        name: 'cose',
        idealEdgeLength: 220,
        nodeOverlap: 40,
        fit: true,
        padding: 60,
        randomize: false,
        componentSpacing: 200,
        nodeRepulsion: 45000,
        edgeElasticity: 80,
        nestingFactor: 5,
        gravity: 0.25,
        numIter: 2000,
        initialTemp: 300,
        coolingFactor: 0.97,
        minTemp: 1.0
      },
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.3
    });

    var statsEl = document.getElementById('graph-stats');
    if (statsEl) statsEl.textContent = graphData.nodes.length + ' nodes, ' + graphData.edges.length + ' edges';

    // Node tap events
    cyInstance.on('tap', 'node', function(evt) {
      var node = evt.target;
      if (graphMode === 'blast') {
        showBlastRadius(node);
      } else {
        showNodeInfoPanel(node);
      }
    });

    // Background tap clears selection
    cyInstance.on('tap', function(evt) {
      if (evt.target === cyInstance) {
        clearGraphSelection();
        closeGraphInfoPanel();
      }
    });

    graphBuilt = true;
  }

  function clearGraphSelection() {
    if (!cyInstance) return;
    cyInstance.batch(function() {
      cyInstance.elements().removeClass('dimmed highlighted blast-source');
    });
  }

  function closeGraphInfoPanel() {
    var panel = document.getElementById('graph-info-panel');
    if (panel) panel.style.display = 'none';
  }

  function showBlastRadius(sourceNode) {
    if (!cyInstance) return;
    var visited = {};
    var queue = [sourceNode];
    visited[sourceNode.id()] = true;
    var reachable = cyInstance.collection().merge(sourceNode);

    // BFS following outgoing edges
    while (queue.length > 0) {
      var current = queue.shift();
      var outgoing = current.outgoers('node');
      outgoing.forEach(function(neighbor) {
        if (!visited[neighbor.id()]) {
          visited[neighbor.id()] = true;
          queue.push(neighbor);
          reachable = reachable.merge(neighbor);
        }
      });
    }

    // Also collect edges between reachable nodes
    var reachableEdges = cyInstance.collection();
    reachable.forEach(function(n) {
      n.connectedEdges().forEach(function(e) {
        if (reachable.contains(e.source()) && reachable.contains(e.target())) {
          reachableEdges = reachableEdges.merge(e);
        }
      });
    });

    cyInstance.batch(function() {
      cyInstance.elements().addClass('dimmed').removeClass('highlighted blast-source');
      reachable.removeClass('dimmed').addClass('highlighted');
      reachableEdges.removeClass('dimmed').addClass('highlighted');
      sourceNode.removeClass('highlighted').addClass('blast-source');
    });

    // Compute stats
    var stats = { repos: 0, workflows: 0, secrets: 0, actions: 0, total: reachable.size() - 1 };
    var secretNames = [];
    reachable.forEach(function(n) {
      if (n.id() === sourceNode.id()) return;
      var t = n.data('type');
      if (t === 'repo' || t === 'allrepos') stats.repos++;
      else if (t === 'workflow') stats.workflows++;
      else if (t === 'secret') { stats.secrets++; secretNames.push(n.data('label')); }
      else if (t === 'action') stats.actions++;
    });

    showBlastRadiusPanel(sourceNode.data(), stats, secretNames);
  }

  var GRAPH_TYPE_META = {
    secret:     { label: 'Secret',            color: '#FF6B6B', icon: '🔑' },
    allrepos:   { label: 'All Repositories',  color: '#4A9FF5', icon: '📂' },
    repo:       { label: 'Repository',        color: '#4A9FF5', icon: '📦' },
    workflow:   { label: 'Workflow',           color: '#4CAF50', icon: '⚙' },
    action:     { label: 'Action (3rd-party)', color: '#B39DDB', icon: '🔌' },
    pat:        { label: 'PAT / App (reads secrets)', color: '#FFA726', icon: '🔑' },
    app:        { label: 'PAT / App (reads secrets)', color: '#FFA726', icon: '🔑' },
    sso:        { label: 'User (SSO credential)',     color: '#F48FB1', icon: '👤' },
    deploy_key: { label: 'Deploy Key',        color: '#FFA726', icon: '🗝' }
  };

  function buildGraphLegend() {
    var seen = {};
    var html = '';
    var order = ['secret', 'repo', 'workflow', 'action', 'sso', 'pat', 'deploy_key'];
    order.forEach(function(t) {
      var m = GRAPH_TYPE_META[t];
      if (!m || seen[m.label]) return;
      seen[m.label] = true;
      html += '<div style="display:flex;align-items:center;gap:8px;padding:2px 0"><span style="width:10px;height:10px;border-radius:50%;background:' + m.color + ';flex-shrink:0"></span><span style="font-size:12px;color:#d1d5db">' + m.label + '</span></div>';
    });
    return html;
  }

  function showNodeInfoPanel(node) {
    var d = node.data();
    var panel = document.getElementById('graph-info-panel');
    var titleEl = document.getElementById('gip-title');
    var bodyEl = document.getElementById('gip-body');
    var meta = GRAPH_TYPE_META[d.type] || { label: d.type, color: '#888', icon: '●' };

    titleEl.innerHTML = meta.icon + ' Access Map';
    bodyEl.innerHTML = '';

    // Entity subtitle + metadata
    var header = document.createElement('div');
    header.className = 'gip-entity-header';
    var entityName = d.entity.token_name || d.entity.app_name || d.entity.name || d.entity.login || d.entity.title || d.entity.repo_name || d.label;
    header.innerHTML = '<div class="gip-entity-type">' + meta.label + ': <code>' + entityName + '</code></div>';
    var metaLine = '';
    if (d.type === 'secret') { metaLine = (d.entity.scope || '') + '-level · visibility=' + (d.entity.visibility || 'n/a'); }
    else if (d.type === 'pat') { metaLine = 'repos=' + (d.entity.repository_selection || 'n/a'); }
    else if (d.type === 'app') { metaLine = 'repos=' + (d.entity.repository_selection || 'n/a') + (d.entity.suspended ? ' · suspended' : ''); }
    else if (d.type === 'repo') { metaLine = d.entity.repo_name; }
    else if (d.type === 'allrepos') { metaLine = d.entity.total + ' repositories in org'; }
    else if (d.type === 'deploy_key') { metaLine = (d.entity.read_only ? 'read-only' : 'read-write') + ' · ' + (d.entity.repo_name || ''); }
    else if (d.type === 'workflow') { metaLine = d.entity.repo_name + ' · perms=' + (d.entity.permissions || 'n/a'); }
    else if (d.type === 'action') { metaLine = d.entity.repo + ' · ' + d.entity.workflow; }
    if (metaLine) header.innerHTML += '<div class="gip-entity-meta">' + metaLine + ' · risk=<strong>' + d.risk + '</strong></div>';
    bodyEl.appendChild(header);

    // Legend
    var legend = document.createElement('div');
    legend.className = 'gip-legend-section';
    legend.innerHTML = buildGraphLegend();
    bodyEl.appendChild(legend);

    // Instruction
    var instr = document.createElement('div');
    instr.className = 'gip-instruction';
    instr.textContent = 'Click any node to see why it can reach this entity.';
    bodyEl.appendChild(instr);

    // Risk "Why" section
    var entity = d.entity;
    var assessment = null;
    var assessors = { pat: assessPATRisk, app: assessAppRisk, sso: assessSSORisk, deploy_key: assessDeployKeyRisk, workflow: assessWorkflowRisk, secret: assessSecretRisk };
    if (assessors[d.type]) assessment = assessors[d.type](entity);

    if (assessment && assessment.risks.length > 0 && assessment.level !== 'none') {
      var whyDiv = document.createElement('div');
      whyDiv.className = 'gip-why-section';
      var whyLabel = '<span class="gip-why-label">Why ' + assessment.level + ':</span> ';
      var whyText = assessment.risks.map(function(r) { return r.message; }).join('. ') + '.';
      // For secrets, add impact heuristic
      if (d.type === 'secret') {
        var imp = getSecretImpact(entity.name);
        if (imp) whyText += ' ' + imp.impact + '.';
      }
      whyDiv.innerHTML = whyLabel + whyText;
      bodyEl.appendChild(whyDiv);
    }

    // Fix section
    if (assessment && assessment.recommendations.length > 0 && assessment.recommendations[0].action !== 'No action needed') {
      var fixDiv = document.createElement('div');
      fixDiv.className = 'gip-fix-section';
      var fixParts = assessment.recommendations.filter(function(r) { return r.action !== 'No action needed'; });
      fixDiv.innerHTML = '<span class="gip-fix-label">Fix:</span> ' + fixParts.map(function(r) {
        return '<strong>' + r.action + '</strong> — ' + r.reason;
      }).join(' ');
      bodyEl.appendChild(fixDiv);
    }

    // Action-specific warning
    if (d.type === 'action') {
      var warn = document.createElement('div');
      warn.className = 'gip-why-section';
      warn.innerHTML = '<span class="gip-why-label">Why high:</span> Unpinned action <code>' + entity.name + '</code> in <code>' + entity.workflow + '</code> can be hijacked by overwriting the tag.';
      bodyEl.appendChild(warn);
      var fix = document.createElement('div');
      fix.className = 'gip-fix-section';
      fix.innerHTML = '<span class="gip-fix-label">Fix:</span> Pin to a full commit SHA instead of a tag reference.';
      bodyEl.appendChild(fix);
    }

    // Allrepos info
    if (d.type === 'allrepos') {
      var arWhy = document.createElement('div');
      arWhy.className = 'gip-why-section';
      arWhy.innerHTML = '<span class="gip-why-label">Why high:</span> visibility <code>all</code> fans access to <strong>~' + entity.total + ' repos</strong> — every workflow, every secret, every 3rd-party action. Multiple attack paths converge here.';
      bodyEl.appendChild(arWhy);
      var arFix = document.createElement('div');
      arFix.className = 'gip-fix-section';
      arFix.innerHTML = '<span class="gip-fix-label">Fix:</span> change scope from <code>all</code> → <code>selected</code>, limit to only required repositories. Collapses the graph from ~' + entity.total + ' repos to a handful.';
      bodyEl.appendChild(arFix);
    }

    // Repo details
    if (d.type === 'repo') {
      var wfs = supplyChainMap.repoToWorkflows[entity.repo_name] || [];
      var dks = supplyChainMap.repoToDeployKeys[entity.repo_name] || [];
      var secs = supplyChainMap.repoToSecrets[entity.repo_name] || [];
      if (wfs.length || dks.length || secs.length || supplyChainMap.writeRepos.has(entity.repo_name)) {
        var repoWhy = document.createElement('div');
        repoWhy.className = 'gip-why-section';
        var parts = [];
        if (wfs.length) parts.push(wfs.length + ' workflow(s)');
        if (dks.length) parts.push(dks.length + ' deploy key(s)');
        if (secs.length) parts.push(secs.length + ' secret(s)');
        if (supplyChainMap.writeRepos.has(entity.repo_name)) parts.push('write access granted');
        repoWhy.innerHTML = '<span class="gip-why-label">Contains:</span> ' + parts.join(' · ');
        bodyEl.appendChild(repoWhy);
      }
    }

    panel.style.display = 'flex';
  }

  function showBlastRadiusPanel(sourceData, stats, secretNames) {
    var panel = document.getElementById('graph-info-panel');
    var titleEl = document.getElementById('gip-title');
    var bodyEl = document.getElementById('gip-body');
    var meta = GRAPH_TYPE_META[sourceData.type] || { icon: '●' };

    titleEl.innerHTML = meta.icon + ' Blast Radius';
    bodyEl.innerHTML = '';

    // Entity header
    var header = document.createElement('div');
    header.className = 'gip-entity-header';
    header.innerHTML = '<div class="gip-entity-type">Source: <code>' + sourceData.label + '</code></div>' +
      '<div class="gip-entity-meta">' + (sourceData.type || '') + ' · if compromised, the following are reachable</div>';
    bodyEl.appendChild(header);

    // Summary stats grid
    var summary = document.createElement('div');
    summary.className = 'blast-summary';
    var items = [
      { label: 'Repos', value: stats.repos },
      { label: 'Workflows', value: stats.workflows },
      { label: 'Secrets', value: stats.secrets },
      { label: 'Total', value: stats.total }
    ];
    items.forEach(function(item) {
      var stat = document.createElement('div');
      stat.className = 'blast-stat';
      stat.innerHTML = '<div class="blast-stat-value">' + item.value + '</div>' +
        '<div class="blast-stat-label">' + item.label + '</div>';
      summary.appendChild(stat);
    });
    bodyEl.appendChild(summary);

    // Why section — attack chain narrative
    var typeLabel = { pat: 'PAT', app: 'App', sso: 'SSO credential', deploy_key: 'Deploy key', action: 'Unpinned action' };
    var srcType = typeLabel[sourceData.type] || sourceData.type;
    var whyParts = [];
    if (stats.repos > 0) whyParts.push(stats.repos + ' repositor' + (stats.repos === 1 ? 'y' : 'ies') + ' accessible');
    if (stats.workflows > 0) whyParts.push(stats.workflows + ' workflow' + (stats.workflows === 1 ? '' : 's') + ' can be triggered/modified');
    if (stats.secrets > 0) {
      var secPart = stats.secrets + ' secret' + (stats.secrets === 1 ? '' : 's') + ' exposed';
      if (secretNames.length > 0) {
        secPart += ': <code>' + secretNames.slice(0, 5).join('</code>, <code>') + '</code>';
        if (secretNames.length > 5) secPart += ' +' + (secretNames.length - 5) + ' more';
      }
      whyParts.push(secPart);
    }
    if (whyParts.length > 0) {
      var whyDiv = document.createElement('div');
      whyDiv.className = 'gip-why-section';
      whyDiv.innerHTML = '<span class="gip-why-label">Why ' + srcType + ' is dangerous:</span> ' + whyParts.join('. ') + '.';
      bodyEl.appendChild(whyDiv);
    }

    if (stats.total === 0) {
      var safe = document.createElement('div');
      safe.className = 'gip-fix-section';
      safe.innerHTML = '<span class="gip-fix-label">Result:</span> No downstream entities at risk from this node.';
      bodyEl.appendChild(safe);
    }

    // Impact cards for exposed secrets
    secretNames.forEach(function(sn) {
      var imp = getSecretImpact(sn);
      if (!imp) return;
      var card = document.createElement('div');
      card.className = 'gip-fix-section';
      card.innerHTML = '<span class="gip-fix-label">' + imp.icon + ' ' + sn + ':</span> ' + imp.impact + ' — ' + imp.chain;
      bodyEl.appendChild(card);
    });

    panel.style.display = 'flex';
  }

  function applyGraphFilters() {
    if (!cyInstance) return;
    cyInstance.batch(function() {
      cyInstance.elements().removeClass('filtered-out');

      // Entity type filter
      if (graphEntityFilter !== 'all') {
        cyInstance.nodes().forEach(function(n) {
          var t = n.data('type');
          if (t !== graphEntityFilter && t !== 'allrepos') {
            n.addClass('filtered-out');
          }
        });
        // Also filter edges where either endpoint is hidden
        cyInstance.edges().forEach(function(e) {
          if (e.source().hasClass('filtered-out') || e.target().hasClass('filtered-out')) {
            e.addClass('filtered-out');
          }
        });
      }

      // Risk level filter
      if (graphRiskFilter !== 'all') {
        var minWeight = graphRiskFilter === 'high' ? 3 : 2;
        var rw = { high: 3, medium: 2, low: 1, none: 0 };
        cyInstance.nodes().forEach(function(n) {
          if (n.hasClass('filtered-out')) return;
          var r = n.data('risk') || 'none';
          if ((rw[r] || 0) < minWeight && n.data('type') !== 'allrepos') {
            n.addClass('filtered-out');
          }
        });
        cyInstance.edges().forEach(function(e) {
          if (e.source().hasClass('filtered-out') || e.target().hasClass('filtered-out')) {
            e.addClass('filtered-out');
          }
        });
      }
    });

    var visible = cyInstance.nodes().not('.filtered-out');
    var visibleEdges = cyInstance.edges().not('.filtered-out');
    var statsEl = document.getElementById('graph-stats');
    if (statsEl) statsEl.textContent = visible.size() + ' nodes, ' + visibleEdges.size() + ' edges';
  }

  // --- Graph Toolbar Handlers ---

  document.getElementById('graph-mode-explore').addEventListener('click', function() {
    graphMode = 'explore';
    this.classList.add('active');
    document.getElementById('graph-mode-blast').classList.remove('active');
    clearGraphSelection();
    closeGraphInfoPanel();
  });

  document.getElementById('graph-mode-blast').addEventListener('click', function() {
    graphMode = 'blast';
    this.classList.add('active');
    document.getElementById('graph-mode-explore').classList.remove('active');
    clearGraphSelection();
    closeGraphInfoPanel();
  });

  document.getElementById('graph-entity-filters').addEventListener('click', function(e) {
    var chip = e.target.closest('.graph-filter-chip');
    if (!chip) return;
    this.querySelectorAll('.graph-filter-chip').forEach(function(c) { c.classList.remove('active'); });
    chip.classList.add('active');
    graphEntityFilter = chip.getAttribute('data-entity');
    clearGraphSelection();
    closeGraphInfoPanel();
    applyGraphFilters();
  });

  document.getElementById('graph-risk-filters').addEventListener('click', function(e) {
    var chip = e.target.closest('.graph-filter-chip');
    if (!chip) return;
    this.querySelectorAll('.graph-filter-chip').forEach(function(c) { c.classList.remove('active'); });
    chip.classList.add('active');
    graphRiskFilter = chip.getAttribute('data-risk');
    clearGraphSelection();
    closeGraphInfoPanel();
    applyGraphFilters();
  });

  document.getElementById('graph-fit-btn').addEventListener('click', function() {
    if (cyInstance) cyInstance.fit(undefined, 30);
  });

  document.getElementById('graph-reset-btn').addEventListener('click', function() {
    graphEntityFilter = 'all';
    graphRiskFilter = 'all';
    document.querySelectorAll('#graph-entity-filters .graph-filter-chip').forEach(function(c) {
      c.classList.toggle('active', c.getAttribute('data-entity') === 'all');
    });
    document.querySelectorAll('#graph-risk-filters .graph-filter-chip').forEach(function(c) {
      c.classList.toggle('active', c.getAttribute('data-risk') === 'all');
    });
    clearGraphSelection();
    closeGraphInfoPanel();
    if (cyInstance) {
      cyInstance.elements().removeClass('filtered-out');
      cyInstance.fit(undefined, 30);
      var statsEl = document.getElementById('graph-stats');
      if (statsEl) statsEl.textContent = cyInstance.nodes().size() + ' nodes, ' + cyInstance.edges().size() + ' edges';
    }
  });

  document.getElementById('gip-close').addEventListener('click', function() {
    closeGraphInfoPanel();
    clearGraphSelection();
  });

  // --- Init ---
  loadAll();

})();
