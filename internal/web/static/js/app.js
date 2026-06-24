(function() {
  'use strict';

  let report = null;
  let diffData = null;
  let orgName = '';

  // Default sorts: risk-first for risk-bearing tables
  let patSort  = { col: 'owner_login', asc: true };
  let appSort  = { col: 'high_risk_count', asc: false };
  let ssoSort  = { col: 'login', asc: true };

  var PAGE_SIZE = 10;    // 10 results per page across all paginated tables
  var WF_PAGE_SIZE = 10; // findings list paginates 10 per page
  var appPage   = 1;
  var ssoPage   = 1;
  var wfFindingsPage = 1;
  var actionsInvPage = 1;
  var actionsInventoryData = []; // org-wide actions inventory (own global; not on report, to avoid a fetch race)
  var actionUsages = [];         // usages of the currently-open action (detail page)
  var actionVerFilter = '';
  var actionUsagePage = 1;
  var ACTION_USAGE_PAGE_SIZE = 15;
  var secretPage = 1;
  var wpPage = 1;
  var WP_PAGE_SIZE = 15; // GITHUB_TOKEN permissions paginate 15 per page
  var ssoTypeFilter = '';   // '' = all, 'personal access token', 'ssh key'
  var ssoExpiryFilter = ''; // '' = all, 'never', 'soon', 'has'
  var drillSsoTypeFilter = ''; // type filter applied inside metric-drill when tab=sso
  var drillSsoExpiryFilter = ''; // expiry filter applied inside metric-drill when tab=sso
  var actionsTrustFilter = ''; // '' = all, 'first_party', 'verified', 'third_party'
  var secretScopeFilter = ''; // '' = all, 'org', 'repo', 'environment'
  var patsView = 'pats';      // 'pats' | 'requests'
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

  // --- Theme toggle (light / dark) ---

  (function() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function() {
      var dark = document.documentElement.getAttribute('data-theme') === 'dark';
      var next = dark ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  })();

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
      document.querySelectorAll('#pats-view-toggle .filter-chip').forEach(function(b) { b.classList.toggle('active', b.dataset.view === 'pats'); });
      setPatsView('pats');
      ssoPage = 1; renderSSOCredentials(data.sso_credentials);
      secretPage = 1; renderSecrets(data.secrets);
      renderDeployKeys(data.deploy_keys);
      wpPage = 1; renderWorkflowPerms(data.workflow_permissions);
      wfFindingsPage = 1; renderWorkflowFiles(data.workflow_files);
      document.getElementById('scan-time').textContent =
        'Last scan\n' + new Date(data.scanned_at).toLocaleString();
      updateTabCounts();
      renderInsightStrips(data);
      renderOverview();
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
    loadActionsInventory();
    loadOverviewInsights();
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

      var cs = getComputedStyle(document.documentElement);
      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '600 22px Inter, sans-serif';
      ctx.fillStyle = (cs.getPropertyValue('--text') || '#0f172a').trim();
      ctx.fillText(text, centerX, sub ? centerY - 8 : centerY);
      if (sub) {
        ctx.font = '400 10px Inter, sans-serif';
        ctx.fillStyle = (cs.getPropertyValue('--text-muted') || '#475569').trim();
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
    // Per-entity totals now live on each tab's insight strip; the Overview
    // keeps only the cross-cutting visual breakdown (charts) + compliance + diff.
    renderOverviewCharts(s);
  }

  // --- CISO Overview: posture score + risk KPIs + exposures + fix-first ---
  // These render from three async sources (report summary, /api/compliance,
  // /api/attack-graph/findings). Each source caches its result and calls
  // renderOverview(), which redraws with whatever is currently available.

  var overviewFindings = null;   // { paths:[], actions:[] } from /api/attack-graph/findings
  var complianceChecks = null;   // [] from /api/compliance

  // Drill columns for the "critical paths" KPI tile / table.
  var PATH_DRILL_COLS = [
    { h: 'Severity', c: function(p) { return '<span class="sev-chip sev-' + gEsc(p.severity || 'medium') + '">' + gEsc(p.severity || 'medium') + '</span>'; } },
    { h: 'Workflow', c: function(p) { return gEsc((p.repo || '') + ' / ' + (p.workflow || '')); } },
    { h: 'Reaches', c: function(p) { return gEsc(p.boundary || p.boundary_type || '—'); } },
    { h: 'Trigger', c: function(p) { return gEsc(p.trigger || '—'); } },
  ];

  // computePostureScore — transparent, tunable 0–100 composite. Weights are
  // capped per category so no single dimension dominates.
  function computePostureScore(s, checks, findings) {
    s = s || {}; checks = checks || []; findings = findings || {};
    var paths = findings.paths || [];
    var score = 100;

    var cf = 0, cw = 0, cu = 0;
    checks.forEach(function(c) {
      if (c.status === 'fail') cf++;
      else if (c.status === 'warn') cw++;
      else if (c.status === 'unknown') cu++;
    });
    score -= Math.min(45, cf * 9 + cw * 4 + cu * 1);

    var crit = paths.filter(function(p) { return p.severity === 'critical'; }).length;
    var high = paths.filter(function(p) { return p.severity === 'high'; }).length;
    score -= Math.min(24, crit * 8);
    score -= Math.min(15, high * 3);

    var exp = 0;
    if (s.all_repo_access_pats > 0) exp += 4;
    if (s.all_repo_access_apps > 0) exp += 3;
    if (s.org_wide_secrets > 0)     exp += 3;
    if (s.write_deploy_keys > 0)    exp += 2;
    if (s.high_risk_apps > 0)       exp += 2;
    if (s.write_all_workflows > 0)  exp += 2;
    if (s.expired_pats > 0)         exp += 1;
    score -= Math.min(16, exp);

    score = Math.max(0, Math.min(100, Math.round(score)));
    var grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    var cls = (grade === 'A' || grade === 'B') ? 'good' : (grade === 'C') ? 'warn' : 'bad';
    return { score: score, grade: grade, cls: cls, crit: crit, high: high, failing: cf + cw };
  }

  function renderPostureHero(s, checks, findings) {
    var el = document.getElementById('posture-hero');
    if (!el) return;
    var r = computePostureScore(s, checks, findings);
    var repos = (s && s.total_repos_scanned) || 0;
    var when = (report && report.scanned_at) ? timeAgo(report.scanned_at) : '—';
    var sub = [
      repos + ' repo' + (repos === 1 ? '' : 's') + ' scanned',
      'scanned ' + when,
      r.failing + ' control' + (r.failing === 1 ? '' : 's') + ' failing',
      r.crit + ' critical exposure' + (r.crit === 1 ? '' : 's'),
    ];
    el.className = 'posture-hero hero-' + r.cls;
    el.innerHTML =
      '<div class="ph-score">' +
        '<div class="ph-grade">' + r.grade + '</div>' +
        '<div class="ph-num">' + r.score + '<span class="ph-den">/100</span></div>' +
      '</div>' +
      '<div class="ph-body">' +
        '<div class="ph-title">Security posture</div>' +
        '<div class="ph-sub">' + sub.map(gEsc).join(' · ') + '</div>' +
        '<div class="ph-bar"><div class="ph-bar-fill" style="width:' + r.score + '%"></div></div>' +
      '</div>';
  }

  function renderOverviewKpis(rep, findings) {
    var el = document.getElementById('overview-kpis');
    if (!el) return;
    var pats = rep.pats || [], apps = rep.apps || [], secrets = rep.secrets || [];
    var paths = (findings && findings.paths) || [];
    var crit    = paths.filter(function(p) { return p.severity === 'critical'; });
    var patAll  = pats.filter(function(p) { return p.repository_selection === 'all'; });
    var appHigh = apps.filter(function(a) { return (a.high_risk_count || 0) > 0; });
    var secAll  = secrets.filter(function(s) { return s.scope === 'org' && s.visibility === 'all'; });

    var boxes = [
      { v: crit.length,    l: 'critical paths → prod', sev: crit.length    ? 'high' : '',
        drill: registerDrill('ov-crit', 'attack-surface', 'Critical attack paths to production', crit,
          { cols: PATH_DRILL_COLS, onRow: function(p) { navTo('tab-attack-surface'); focusNode(p.workflow_id); } }) },
      { v: patAll.length,  l: 'all-repo PATs',         sev: patAll.length  ? 'high' : '',
        drill: registerDrill('ov-allrepo-pat', 'pats', 'PATs with all-repository access', patAll) },
      { v: appHigh.length, l: 'high-risk apps',        sev: appHigh.length ? 'high' : '',
        drill: registerDrill('ov-high-app', 'apps', 'Apps with high-risk permissions', appHigh) },
      { v: secAll.length,  l: 'org-wide secrets',      sev: secAll.length  ? 'high' : '',
        drill: registerDrill('ov-orgwide-sec', 'secrets', 'Org secrets visible to all repositories', secAll) },
    ];
    el.innerHTML = boxes.map(function(b) { return statBox(b.v, b.l, b.sev, b.drill); }).join('');
  }

  function renderTopExposures(findings) {
    var el = document.getElementById('overview-exposures');
    if (!el) return;
    var paths = ((findings && findings.paths) || []).slice(0, 5);
    var head = '<div class="overview-panel-head"><h3>Top exposures — attack paths to production</h3>' +
      '<span class="ov-seeall" data-tab="tab-attack-surface">View attack surface →</span></div>';
    if (!paths.length) {
      el.innerHTML = head + '<div class="ov-empty ok">✓ No attack paths to production detected.</div>';
      return;
    }
    var rows = paths.map(function(p) {
      var sub = p.trigger_risk || (p.factors || []).join(' · ') || p.why || '';
      return '<div class="exposure-row" data-wfid="' + gEsc(p.workflow_id || '') + '">' +
        '<span class="sev-chip sev-' + gEsc(p.severity || 'medium') + '">' + gEsc(p.severity || 'medium') + '</span>' +
        '<div class="exposure-main">' +
          '<div class="exposure-title">' + gEsc((p.repo || '') + ' / ' + (p.workflow || '')) +
            ' <span class="exposure-arrow">→</span> ' + gEsc(p.boundary || p.boundary_type || 'production') + '</div>' +
          (sub ? '<div class="exposure-sub">' + gEsc(sub) + '</div>' : '') +
        '</div></div>';
    }).join('');
    el.innerHTML = head + '<div class="exposure-list">' + rows + '</div>';
  }

  function renderFixFirst(findings) {
    var el = document.getElementById('overview-fixfirst');
    if (!el) return;
    var actions = ((findings && findings.actions) || []).slice(0, 5);
    var head = '<div class="overview-panel-head"><h3>Fix first</h3></div>';
    if (!actions.length) {
      el.innerHTML = head + '<div class="ov-empty ok">✓ No prioritized actions outstanding.</div>';
      return;
    }
    var rows = actions.map(function(a, i) {
      return '<div class="fixfirst-row">' +
        '<span class="fixfirst-num">' + (i + 1) + '</span>' +
        '<span class="sev-chip sev-' + gEsc(a.severity || 'medium') + '">' + gEsc(a.severity || 'medium') + '</span>' +
        '<div class="fixfirst-main">' +
          '<div class="fixfirst-title">' + gEsc(a.title || '') + '</div>' +
          '<div class="fixfirst-fix">' + gEsc(a.fix || a.detail || '') + '</div>' +
        '</div></div>';
    }).join('');
    el.innerHTML = head + '<div class="fixfirst-list">' + rows + '</div>';
  }

  function renderComplianceFailing(checks) {
    var el = document.getElementById('compliance-failing');
    if (!el) return;
    var ORDER = { fail: 0, warn: 1 };
    var bad = (checks || []).filter(function(c) { return c.status === 'fail' || c.status === 'warn'; })
      .sort(function(a, b) { return (ORDER[a.status] || 0) - (ORDER[b.status] || 0); });
    if (!bad.length) {
      el.innerHTML = '<div class="ov-empty ok">✓ All security controls passing.</div>';
      return;
    }
    el.innerHTML = bad.map(function(c) {
      var fix = c.fix_url ? '<a class="cf-fix" href="' + gEsc(c.fix_url) + '" target="_blank" rel="noopener">Fix →</a>' : '';
      return '<div class="cf-row status-' + gEsc(c.status) + '">' +
        '<span class="cc-status ' + gEsc(c.status) + '"></span>' +
        '<span class="cf-name">' + gEsc(c.name) + '</span>' + fix + '</div>';
    }).join('');
  }

  // renderOverview redraws the executive sections from whatever data is cached.
  function renderOverview() {
    if (!report) return;
    var s = report.summary || {};
    renderPostureHero(s, complianceChecks || [], overviewFindings || {});
    renderOverviewKpis(report, overviewFindings || {});
    renderTopExposures(overviewFindings || {});
    renderFixFirst(overviewFindings || {});
  }

  // loadOverviewInsights fetches the attack-path findings used by the Overview
  // hero, KPIs, exposures, and fix-first sections.
  function loadOverviewInsights() {
    fetchJSON('/api/attack-graph/findings').then(function(f) {
      overviewFindings = f || { paths: [], actions: [] };
      renderOverview();
    }).catch(function() {});
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

      addLinkCell(tr, ghUserUrl(p.owner_login), p.owner_login);
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

  function buildPagination(containerId, totalItems, currentPage, onPageChange, pageSize) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';
    var ps = pageSize || PAGE_SIZE;
    var totalPages = Math.ceil(totalItems / ps);
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
    var start = (currentPage - 1) * ps + 1;
    var end   = Math.min(currentPage * ps, totalItems);
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
      // App name links to its canonical GitHub App page (github.com/apps/<slug>),
      // which resolves reliably and forwards to the Marketplace listing when one
      // exists. The Marketplace listing slug itself is not exposed by the API.
      nameCell.innerHTML = a.app_slug
        ? '<a href="' + ghAppUrl(a.app_slug) + '" target="_blank" rel="noopener" class="gh-link app-name-link">' + gEsc(a.app_name) + '</a>'
        : '<span class="app-name-link">' + gEsc(a.app_name) + '</span>';
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

  // setPatsView toggles the PATs tab between the fine-grained PAT table and the
  // pending-requests table, swapping which is shown and adjusting the header.
  function setPatsView(view) {
    patsView = view === 'requests' ? 'requests' : 'pats';
    var isReq = patsView === 'requests';
    var pv = document.getElementById('pats-view');
    var rv = document.getElementById('requests-view');
    var actions = document.getElementById('pats-actions');
    var title = document.getElementById('pats-section-title');
    if (pv) pv.style.display = isReq ? 'none' : '';
    if (rv) rv.style.display = isReq ? '' : 'none';
    if (actions) actions.style.display = isReq ? 'none' : ''; // search/export apply to PATs only
    if (title) title.textContent = isReq ? 'Pending PAT Requests' : 'Fine-Grained Personal Access Tokens';
  }

  // --- Per-tab insight strips + click-through drill-down ---

  var drillData = {};   // key -> { tab, title, rows }
  var drillKey = null;
  var drillPage = 1;

  function statBox(value, label, sev, drill) {
    return '<div class="zsum-box ' + (sev ? 'zsum-' + sev : '') + '"' + (drill ? ' data-drill="' + drill + '"' : '') + '>' +
      '<div class="zsum-value">' + value + '</div>' +
      '<div class="zsum-label">' + gEsc(label) + '</div></div>';
  }

  function renderStatStrip(id, boxes) {
    var el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = boxes.map(function(b) { return statBox(b.v, b.l, b.sev, b.drill); }).join('');
  }

  function dateCell(v) { return v ? new Date(v).toLocaleDateString() : '—'; }

  // Columns for each tab's drill-down table (keyed by tab-id suffix).
  var DRILL_COLUMNS = {
    'pats': [
      { h: 'Owner', c: function(p) { return ghLinkHTML(ghUserUrl(p.owner_login), p.owner_login); } },
      { h: 'Token', c: function(p) { return gEsc(p.token_name); } },
      { h: 'Repo access', c: function(p) { return gEsc(p.repository_selection); } },
      { h: 'Expires', c: function(p) { return p.token_expires_at ? dateCell(p.token_expires_at) : 'Never'; } },
      { h: 'Last used', c: function(p) { return p.token_last_used_at ? dateCell(p.token_last_used_at) : 'Never'; } },
    ],
    'apps': [
      { h: 'App', c: function(a) { return ghLinkHTML(ghAppUrl(a.app_slug), a.app_name); } },
      { h: 'Repo access', c: function(a) { return gEsc(a.repository_selection); } },
      { h: 'High-risk perms', c: function(a) { return a.high_risk_count || 0; } },
      { h: 'Suspended', c: function(a) { return a.suspended ? 'Yes' : 'No'; } },
    ],
    'sso': [
      { h: 'Login', c: function(c) { return ghLinkHTML(ghUserUrl(c.login), c.login); } },
      { h: 'Type', c: function(c) { return gEsc(c.credential_type || '—'); } },
      { h: 'Scopes', c: function(c) { return (c.scopes || []).length; } },
      { h: 'Authorized', c: function(c) { return dateCell(c.credential_authorized_at); } },
      { h: 'Expires', c: function(c) { return c.authorized_credential_expires_at ? dateCell(c.authorized_credential_expires_at) : 'Never'; } },
    ],
    'secrets': [
      { h: 'Name', c: function(s) { return gEsc(s.name); } },
      { h: 'Scope', c: function(s) { return gEsc(s.scope); } },
      { h: 'Repository', c: function(s) { return s.repo_name ? ghLinkHTML(ghRepoUrl(s.repo_name), s.repo_name) : '—'; } },
      { h: 'Visibility', c: function(s) { return gEsc(s.visibility || '—'); } },
      { h: 'Updated', c: function(s) { return dateCell(s.updated_at); } },
    ],
    'deploy-keys': [
      { h: 'Repository', c: function(k) { return ghLinkHTML(ghRepoSettingsUrl(k.repo_name, 'keys'), k.repo_name); } },
      { h: 'Title', c: function(k) { return gEsc(k.title || '—'); } },
      { h: 'Access', c: function(k) { return k.read_only ? 'read-only' : 'read-write'; } },
      { h: 'Added by', c: function(k) { return gEsc(k.added_by || '—'); } },
    ],
    'workflow-perms': [
      { h: 'Repository', c: function(w) { return ghLinkHTML(ghRepoSettingsUrl(w.repo_name, 'actions'), w.repo_name); } },
      { h: 'Default permission', c: function(w) { return gEsc(w.default_permission); } },
      { h: 'Can approve PRs', c: function(w) { return w.can_approve_pull_requests ? 'Yes' : 'No'; } },
    ],
  };

  // registerDrill stores a metric's subset and returns its key (used as the
  // box's data-drill attribute). Keys are stable across re-renders.
  function registerDrill(key, tab, title, rows, opts) {
    drillData[key] = {
      tab: tab, title: title, rows: rows,
      cols: opts && opts.cols,     // optional per-dataset columns (overrides DRILL_COLUMNS[tab])
      onRow: opts && opts.onRow,   // optional per-dataset row-click handler (overrides openItemDetail)
    };
    return key;
  }

  // navTo activates a sidebar tab programmatically (sets active states + title)
  // so a detail view opened from elsewhere — e.g. a metric drill row — lands on
  // the correct, visible tab before swapping in its inner detail panel.
  function navTo(tabId) {
    var nav = document.querySelector('.nav-item[data-tab="' + tabId + '"]');
    if (nav) nav.click();
  }

  // renderInsightStrips computes each tab's headline metrics AND the row subset
  // behind each box, so clicking a box opens that exact list.
  function renderInsightStrips(r) {
    if (!r) return;
    var now = Date.now(), in30 = now + 30 * 864e5;

    // PATs
    var pats = r.pats || [];
    var patActive = pats.filter(function(p) { return !p.token_expired; });
    var patExpired = pats.filter(function(p) { return p.token_expired; });
    var patExpiring = pats.filter(function(p) {
      if (p.token_expired || !p.token_expires_at) return false;
      var t = new Date(p.token_expires_at).getTime();
      return t >= now && t <= in30;
    });
    var patAllRepo = pats.filter(function(p) { return p.repository_selection === 'all'; });
    renderStatStrip('pats-stats', [
      { v: pats.length, l: 'total', drill: registerDrill('pat-total', 'pats', 'Fine-grained PATs', pats) },
      { v: patActive.length, l: 'active', drill: registerDrill('pat-active', 'pats', 'Active PATs', patActive) },
      { v: patExpiring.length, l: 'expiring ≤30d', sev: patExpiring.length ? 'medium' : '', drill: registerDrill('pat-exp', 'pats', 'PATs expiring within 30 days', patExpiring) },
      { v: patExpired.length, l: 'expired', sev: patExpired.length ? 'medium' : '', drill: registerDrill('pat-expired', 'pats', 'Expired PATs', patExpired) },
      { v: patAllRepo.length, l: 'all-repo access', sev: patAllRepo.length ? 'high' : '', drill: registerDrill('pat-allrepo', 'pats', 'PATs with all-repository access', patAllRepo) },
    ]);

    // Apps
    var apps = r.apps || [];
    var appHigh = apps.filter(function(a) { return a.high_risk_count > 0; });
    var appAll = apps.filter(function(a) { return a.repository_selection === 'all'; });
    var appSusp = apps.filter(function(a) { return a.suspended; });
    renderStatStrip('apps-stats', [
      { v: apps.length, l: 'total', drill: registerDrill('app-total', 'apps', 'Installed GitHub Apps', apps) },
      { v: appHigh.length, l: 'high-risk', sev: appHigh.length ? 'high' : '', drill: registerDrill('app-high', 'apps', 'Apps with high-risk permissions', appHigh) },
      { v: appAll.length, l: 'all-repo access', sev: appAll.length ? 'high' : '', drill: registerDrill('app-all', 'apps', 'Apps with all-repository access', appAll) },
      { v: appSusp.length, l: 'suspended', drill: registerDrill('app-susp', 'apps', 'Suspended apps', appSusp) },
    ]);

    // SSO credentials
    var sso = r.sso_credentials || [];
    var ssoPat = sso.filter(function(c) { return c.credential_type === 'personal access token'; });
    var ssoSsh = sso.filter(function(c) { return c.credential_type === 'SSH key'; });
    var ssoNoExp = sso.filter(function(c) { return !c.authorized_credential_expires_at; });
    renderStatStrip('sso-stats', [
      { v: sso.length, l: 'total', drill: registerDrill('sso-total', 'sso', 'SSO authorized credentials', sso) },
      { v: ssoPat.length, l: 'classic PATs', sev: ssoPat.length ? 'medium' : '', drill: registerDrill('sso-pat', 'sso', 'SSO classic PATs', ssoPat) },
      { v: ssoSsh.length, l: 'SSH keys', drill: registerDrill('sso-ssh', 'sso', 'SSO SSH keys', ssoSsh) },
      { v: ssoNoExp.length, l: 'no expiry', sev: ssoNoExp.length ? 'medium' : '', drill: registerDrill('sso-noexp', 'sso', 'SSO credentials with no expiry', ssoNoExp) },
    ]);

    // Secrets
    var secrets = r.secrets || [];
    var secOrg = secrets.filter(function(s) { return s.scope === 'org'; });
    var secRepo = secrets.filter(function(s) { return s.scope === 'repo'; });
    var secEnv = secrets.filter(function(s) { return s.scope === 'environment'; });
    var secAll = secrets.filter(function(s) { return s.scope === 'org' && s.visibility === 'all'; });
    renderStatStrip('secrets-stats', [
      { v: secrets.length, l: 'total', drill: registerDrill('sec-total', 'secrets', 'Actions secrets', secrets) },
      { v: secOrg.length, l: 'org', drill: registerDrill('sec-org', 'secrets', 'Org-level secrets', secOrg) },
      { v: secRepo.length, l: 'repo', drill: registerDrill('sec-repo', 'secrets', 'Repository secrets', secRepo) },
      { v: secEnv.length, l: 'environment', drill: registerDrill('sec-env', 'secrets', 'Environment secrets', secEnv) },
      { v: secAll.length, l: 'org-wide (all)', sev: secAll.length ? 'high' : '', drill: registerDrill('sec-all', 'secrets', 'Org secrets visible to all repos', secAll) },
    ]);

    // Deploy keys
    var dks = r.deploy_keys || [];
    var dkWrite = dks.filter(function(k) { return !k.read_only; });
    var dkRead = dks.filter(function(k) { return k.read_only; });
    renderStatStrip('deploy-keys-stats', [
      { v: dks.length, l: 'total', drill: registerDrill('dk-total', 'deploy-keys', 'Deploy keys', dks) },
      { v: dkWrite.length, l: 'read-write', sev: dkWrite.length ? 'high' : '', drill: registerDrill('dk-write', 'deploy-keys', 'Read-write deploy keys', dkWrite) },
      { v: dkRead.length, l: 'read-only', drill: registerDrill('dk-read', 'deploy-keys', 'Read-only deploy keys', dkRead) },
    ]);

    // GITHUB_TOKEN default permissions
    var wp = r.workflow_permissions || [];
    var wpWrite = wp.filter(function(x) { return x.default_permission === 'write'; });
    var wpApprove = wp.filter(function(x) { return x.can_approve_pull_requests; });
    var wpRead = wp.filter(function(x) { return x.default_permission !== 'write'; });
    renderStatStrip('workflow-perms-stats', [
      { v: wp.length, l: 'repositories', drill: registerDrill('wp-total', 'workflow-perms', 'GITHUB_TOKEN default permissions', wp) },
      { v: wpWrite.length, l: 'write default', sev: wpWrite.length ? 'high' : '', drill: registerDrill('wp-write', 'workflow-perms', 'Repos with write-default GITHUB_TOKEN', wpWrite) },
      { v: wpApprove.length, l: 'can approve PRs', sev: wpApprove.length ? 'medium' : '', drill: registerDrill('wp-approve', 'workflow-perms', 'Repos where GITHUB_TOKEN can approve PRs', wpApprove) },
      { v: wpRead.length, l: 'read default', drill: registerDrill('wp-read', 'workflow-perms', 'Repos with read-default GITHUB_TOKEN', wpRead) },
    ]);
  }

  // --- Stat-box drill-down (shared table page, 15 / page) ---

  function showDrillTab() {
    var d = drillData[drillKey];
    if (!d) return;
    document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
    document.getElementById('tab-metric-drill').classList.add('active');
    document.getElementById('metric-drill-title').textContent = d.title + ' (' + d.rows.length + ')';
    document.getElementById('page-title').textContent = d.title;
    // Show SSO filters only for SSO drill-downs
    var ssoFilters = document.getElementById('drill-sso-filters');
    if (ssoFilters) {
      ssoFilters.style.display = d.tab === 'sso' ? '' : 'none';
      if (d.tab !== 'sso') {
        drillSsoTypeFilter = '';
        drillSsoExpiryFilter = '';
        document.querySelectorAll('#drill-sso-type-chips .filter-chip').forEach(function(b) {
          b.classList.toggle('active', b.dataset.type === '');
        });
        document.querySelectorAll('#drill-sso-expiry-chips .filter-chip').forEach(function(b) {
          b.classList.toggle('active', b.dataset.expiry === '');
        });
      }
    }
    renderDrillTable();
    var content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
  }

  function openMetricDrill(key) {
    if (!drillData[key]) return;
    drillKey = key;
    drillPage = 1;
    showDrillTab();
  }

  function renderDrillTable() {
    var d = drillData[drillKey];
    if (!d) return;
    var cols = d.cols || DRILL_COLUMNS[d.tab] || [];
    var table = document.getElementById('metric-drill-table');
    var pager = document.getElementById('metric-drill-pagination');
    if (!table) return;
    // Apply SSO type + expiry filters within drill-down
    var rows = d.rows;
    if (d.tab === 'sso') {
      if (drillSsoTypeFilter) {
        rows = rows.filter(function(r) { return r.credential_type === drillSsoTypeFilter; });
      }
      rows = applySsoExpiryFilter(rows, drillSsoExpiryFilter);
    }
    if (!rows.length) {
      table.innerHTML = '<tbody><tr><td class="empty-cell">No items match the filter.</td></tr></tbody>';
      if (pager) pager.innerHTML = '';
      return;
    }
    var totalPages = Math.max(1, Math.ceil(rows.length / 15));
    if (drillPage > totalPages) drillPage = totalPages;
    if (drillPage < 1) drillPage = 1;
    var pageRows = rows.slice((drillPage - 1) * 15, drillPage * 15);
    table.innerHTML =
      '<thead><tr>' + cols.map(function(c) { return '<th>' + gEsc(c.h) + '</th>'; }).join('') + '</tr></thead>' +
      '<tbody>' + pageRows.map(function(it) {
        return '<tr>' + cols.map(function(c) { return '<td>' + c.c(it) + '</td>'; }).join('') + '</tr>';
      }).join('') + '</tbody>';
    // Rows drill one level deeper — into a per-item risk page, or a dataset's
    // own handler (e.g. workflow / action detail views) when provided.
    var rowFn = d.onRow || function(item) { openItemDetail(d.tab, item); };
    Array.prototype.forEach.call(table.querySelectorAll('tbody tr'), function(tr, i) {
      if (!pageRows[i]) return;
      tr.classList.add('expandable');
      tr.addEventListener('click', (function(item) {
        return function() { rowFn(item); };
      })(pageRows[i]));
    });
    buildPagination('metric-drill-pagination', rows.length, drillPage, function(p) { drillPage = p; renderDrillTable(); }, 15);
  }

  function closeMetricDrill() {
    document.getElementById('tab-metric-drill').classList.remove('active');
    var d = drillData[drillKey];
    var nav = document.querySelector('.nav-item[data-tab="tab-' + (d ? d.tab : 'overview') + '"]');
    if (nav) nav.click(); else { var ov = document.querySelector('.nav-item[data-tab="tab-overview"]'); if (ov) ov.click(); }
  }

  // --- Per-item detail page (risks + recommendations), reached from a drill row ---

  var ASSESS_FN = {
    'pats': function(p) { return assessPATRisk(p); },
    'apps': function(a) { return assessAppRisk(a); },
    'sso': function(c) { return assessSSORisk(c); },
    'secrets': function(s) { return assessSecretRisk(s); },
    'deploy-keys': function(k) { return assessDeployKeyRisk(k); },
    'workflow-perms': function(w) { return assessWorkflowPermRisk(w); },
  };

  function itemName(tab, it) {
    switch (tab) {
      case 'apps': return it.app_name;
      case 'pats': return it.token_name + ' · ' + it.owner_login;
      case 'sso': return it.login;
      case 'secrets': return it.name;
      case 'deploy-keys': return (it.title || 'Deploy key') + ' · ' + it.repo_name;
      case 'workflow-perms': return it.repo_name;
    }
    return 'Details';
  }

  function itemMeta(tab, it) {
    switch (tab) {
      case 'apps': return [
        { label: 'GitHub App', html: it.app_slug ? ghLinkHTML(ghAppUrl(it.app_slug), '@' + it.app_slug) : '—' },
        { label: 'Repo access', value: it.repository_selection, cls: it.repository_selection === 'all' ? 'danger' : '' },
        { label: 'Permissions', value: it.high_risk_count + ' high · ' + it.medium_risk_count + ' medium · ' + it.low_risk_count + ' low' },
        { label: 'Status', value: it.suspended ? 'Suspended' : 'Active' },
      ];
      case 'pats': return [
        { label: 'Owner', html: ghLinkHTML(ghUserUrl(it.owner_login), it.owner_login) },
        { label: 'Repo access', value: it.repository_selection, cls: it.repository_selection === 'all' ? 'danger' : '' },
        { label: 'Expires', value: it.token_expires_at ? new Date(it.token_expires_at).toLocaleDateString() : 'Never' },
        { label: 'Last used', value: it.token_last_used_at ? new Date(it.token_last_used_at).toLocaleDateString() : 'Never' },
      ];
      case 'sso': return [
        { label: 'Type', value: it.credential_type || '—' },
        { label: 'Scopes', value: (it.scopes || []).join(', ') || '—' },
        { label: 'Authorized', value: it.credential_authorized_at ? new Date(it.credential_authorized_at).toLocaleDateString() : '—' },
        { label: 'Expires', value: it.authorized_credential_expires_at ? new Date(it.authorized_credential_expires_at).toLocaleDateString() : 'Never' },
      ];
      case 'secrets': return [
        { label: 'Scope', value: it.scope },
        { label: 'Repository', html: it.repo_name ? ghLinkHTML(ghRepoUrl(it.repo_name), it.repo_name) : '—' },
        { label: 'Visibility', value: it.visibility || '—' },
        { label: 'Updated', value: it.updated_at ? new Date(it.updated_at).toLocaleDateString() : '—' },
      ];
      case 'deploy-keys': return [
        { label: 'Repository', html: ghLinkHTML(ghRepoSettingsUrl(it.repo_name, 'keys'), it.repo_name) },
        { label: 'Access', value: it.read_only ? 'read-only' : 'read-write', cls: it.read_only ? '' : 'danger' },
        { label: 'Added by', value: it.added_by || '—' },
      ];
      case 'workflow-perms': return [
        { label: 'Repository', html: ghLinkHTML(ghRepoSettingsUrl(it.repo_name, 'actions'), it.repo_name) },
        { label: 'Default permission', value: it.default_permission, cls: it.default_permission === 'write' ? 'danger' : '' },
        { label: 'Can approve PRs', value: it.can_approve_pull_requests ? 'Yes' : 'No' },
      ];
    }
    return null;
  }

  function openItemDetail(tab, item) {
    var assess = ASSESS_FN[tab];
    if (!assess) return;
    var a = assess(item);
    var body = document.getElementById('item-detail-body');
    body.innerHTML = '';
    body.appendChild(buildRiskSection(a));
    body.appendChild(buildRecommendationsSection(a));
    var meta = itemMeta(tab, item);
    if (meta) body.appendChild(buildMetaSection('Details', meta));

    document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
    document.getElementById('tab-item-detail').classList.add('active');
    var name = itemName(tab, item);
    var lvl = a.level || 'none';
    var chip = lvl === 'none'
      ? '<span class="sev-chip sev-none">no issues</span>'
      : '<span class="sev-chip sev-' + gEsc(lvl) + '">' + gEsc(lvl) + ' risk</span>';
    document.getElementById('item-detail-title').innerHTML = gEsc(name) + ' ' + chip;
    document.getElementById('page-title').textContent = name;
    var content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
  }

  function closeItemDetail() { showDrillTab(); }

  function renderRequests(requests) {
    var table = document.getElementById('requests-table');
    var countEl = document.getElementById('count-requests');
    if (countEl) countEl.textContent = String((requests || []).length);
    if (!requests || requests.length === 0) {
      table.innerHTML = '<tbody><tr><td class="empty-cell">No pending PAT requests.</td></tr></tbody>';
      return;
    }
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
      addLinkCell(tr, ghUserUrl(r.owner_login), r.owner_login);
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

  function applySsoExpiryFilter(creds, expiryFilter) {
    if (!expiryFilter) return creds;
    var now = Date.now();
    var soon = now + 30 * 24 * 60 * 60 * 1000;
    return creds.filter(function(c) {
      var exp = c.authorized_credential_expires_at;
      if (expiryFilter === 'never') return !exp;
      if (expiryFilter === 'has')   return !!exp;
      if (expiryFilter === 'soon')  return exp && new Date(exp).getTime() <= soon;
      return true;
    });
  }

  function renderSSOCredentials(creds) {
    if (!creds) creds = [];

    // Apply type then expiry filters
    var filtered = ssoTypeFilter
      ? creds.filter(function(c) { return c.credential_type === ssoTypeFilter; })
      : creds;
    filtered = applySsoExpiryFilter(filtered, ssoExpiryFilter);

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
      addLinkCell(tr, ghUserUrl(c.login), c.login);
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
    secrets = secrets || [];
    var scoped = secretScopeFilter
      ? secrets.filter(function(s) { return s.scope === secretScopeFilter; })
      : secrets;
    var sorted = sortData(scoped, secretSort);
    var table = document.getElementById('secrets-table');
    if (!table) return;
    table.innerHTML = '';

    var cols = [
      { key: 'name', label: 'Secret Name' },
      { key: 'scope', label: 'Scope' },
      { key: 'repo_name', label: 'Repository' },
      { key: 'env_name', label: 'Environment' },
      { key: 'visibility', label: 'Visibility' },
      { key: 'updated_at', label: 'Last Updated' },
      { key: 'created_by', label: 'Created By' },
      { key: '', label: 'Risk' },
      { key: '', label: 'Actions' },
    ];

    table.appendChild(buildHeader(cols, secretSort, function() { renderSecrets(report.secrets); }));

    var pager = document.getElementById('secrets-pagination');
    if (sorted.length === 0) {
      var empty = document.createElement('tbody');
      empty.innerHTML = '<tr><td class="empty-cell">No ' +
        (secretScopeFilter || '') + ' secrets.</td></tr>';
      table.appendChild(empty);
      if (pager) pager.innerHTML = '';
      return;
    }

    // Paginate 10 per page (clamp so scope/search changes never land on an empty page).
    var totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
    if (secretPage > totalPages) secretPage = totalPages;
    if (secretPage < 1) secretPage = 1;
    var pageRows = sorted.slice((secretPage - 1) * PAGE_SIZE, secretPage * PAGE_SIZE);
    buildPagination('secrets-pagination', sorted.length, secretPage, function(p) {
      secretPage = p;
      renderSecrets(secrets);
    }, PAGE_SIZE);

    var tbody = document.createElement('tbody');
    pageRows.forEach(function(s) {
      var assessment = assessSecretRisk(s);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      if (isNewItem(s.name, 'secret')) tr.classList.add('diff-new');
      addCell(tr, s.name);
      var scopeCell = document.createElement('td');
      var scopeBadge = document.createElement('span');
      scopeBadge.className = 'badge neutral'; // scope is a category, not a risk level
      scopeBadge.textContent = s.scope;
      scopeCell.appendChild(scopeBadge);
      tr.appendChild(scopeCell);
      if (s.repo_name) addLinkCell(tr, ghRepoUrl(s.repo_name), s.repo_name); else addCell(tr, '-');
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

      // Created By — from audit log
      var creatorCell = document.createElement('td');
      if (s.created_by) {
        var creatorLink = document.createElement('a');
        creatorLink.href = 'https://github.com/' + s.created_by;
        creatorLink.target = '_blank';
        creatorLink.rel = 'noopener';
        creatorLink.style.cssText = 'color:var(--accent);font-size:12px;text-decoration:none';
        creatorLink.textContent = '@' + s.created_by;
        creatorCell.appendChild(creatorLink);
      } else {
        creatorCell.textContent = '—';
        creatorCell.style.color = 'var(--text-muted)';
        creatorCell.style.fontSize = '12px';
      }
      tr.appendChild(creatorCell);

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
        toggleDetailRow(tr, function() { return renderSecretDetailPanel(s, 9); });
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
      addLinkCell(tr, ghRepoSettingsUrl(k.repo_name, 'keys'), k.repo_name);
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
    perms = perms || [];

    var sorted = sortData(perms, wpSort);
    var table = document.getElementById('workflow-perms-table');
    if (!table) return;
    table.innerHTML = '';

    var cols = [
      { key: 'repo_name', label: 'Repository' },
      { key: 'default_permission', label: 'Default Permission' },
      { key: 'can_approve_pull_requests', label: 'Can Approve PRs' },
      { key: '', label: 'Risk' },
    ];

    table.appendChild(buildHeader(cols, wpSort, function() { renderWorkflowPerms(report.workflow_permissions); }));

    // Paginate 15 per page (clamp so filtering never lands on an empty page).
    var totalPages = Math.max(1, Math.ceil(sorted.length / WP_PAGE_SIZE));
    if (wpPage > totalPages) wpPage = totalPages;
    if (wpPage < 1) wpPage = 1;
    var pageRows = sorted.slice((wpPage - 1) * WP_PAGE_SIZE, wpPage * WP_PAGE_SIZE);
    buildPagination('workflow-perms-pagination', sorted.length, wpPage, function(p) {
      wpPage = p;
      renderWorkflowPerms(perms);
    }, WP_PAGE_SIZE);

    var tbody = document.createElement('tbody');
    pageRows.forEach(function(wp) {
      var assessment = assessWorkflowPermRisk(wp);
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      addLinkCell(tr, ghRepoSettingsUrl(wp.repo_name, 'actions'), wp.repo_name);
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

  var ZIZMOR_SEV_WEIGHT = { high: 3, medium: 2, low: 1, informational: 0.5 };

  // zizmorMaxSeverity returns the worst severity among a workflow's zizmor
  // findings ('' if none).
  function zizmorMaxSeverity(wf) {
    var best = '', bestW = 0;
    (wf.zizmor_findings || []).forEach(function(f) {
      var w = ZIZMOR_SEV_WEIGHT[f.severity] || 0;
      if (w > bestW) { bestW = w; best = f.severity; }
    });
    return best;
  }

  function zizmorSortWeight(wf) {
    var n = (wf.zizmor_findings || []).length;
    return (ZIZMOR_SEV_WEIGHT[zizmorMaxSeverity(wf)] || 0) * 1000 + n;
  }

  var ZIZMOR_SEV_ORDER = { high: 0, medium: 1, low: 2, informational: 3 };

  // showWorkflowDetailView swaps the audit tab from the list to a dedicated
  // detail "page" for one workflow's findings, with a Back button.
  function showWorkflowDetailView(wf) {
    var body = document.getElementById('workflow-detail-body');
    var listV = document.getElementById('workflow-list-view');
    var detV = document.getElementById('workflow-detail-view');
    if (!body || !listV || !detV) return;
    body.innerHTML = '';
    var section = buildFindingsSection(wf);
    if (section) body.appendChild(section);
    listV.style.display = 'none';
    detV.style.display = 'block';
    var content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
  }

  function showWorkflowListView() {
    var listV = document.getElementById('workflow-list-view');
    var detV = document.getElementById('workflow-detail-view');
    if (detV) detV.style.display = 'none';
    if (listV) listV.style.display = 'block';
  }

  // renderWorkflowFiles renders ONLY the security findings — one row per
  // finding, severity-ranked. `files` may be a filtered subset (from the search
  // box); the summary banner always reflects the full set. Clicking a row opens
  // the detail view (showWorkflowDetailView).
  function renderWorkflowFiles(files) {
    showWorkflowListView();
    renderZizmorSummary(report ? report.workflow_files : files);
    var table = document.getElementById('workflow-files-table');
    if (!table) return;
    table.innerHTML = '';

    var rows = [];
    (files || []).forEach(function(wf) {
      (wf.zizmor_findings || []).forEach(function(f) {
        rows.push({ f: f, repo: wf.repo_name, file: wf.file_name, wf: wf });
      });
    });

    if (rows.length === 0) {
      table.innerHTML = '<tbody><tr><td class="empty-cell clean">No security findings.</td></tr></tbody>';
      var pg = document.getElementById('workflow-files-pagination');
      if (pg) pg.innerHTML = '';
      return;
    }

    rows.sort(function(a, b) {
      var d = (ZIZMOR_SEV_ORDER[a.f.severity] != null ? ZIZMOR_SEV_ORDER[a.f.severity] : 9) -
              (ZIZMOR_SEV_ORDER[b.f.severity] != null ? ZIZMOR_SEV_ORDER[b.f.severity] : 9);
      if (d !== 0) return d;
      return (a.repo + a.file).localeCompare(b.repo + b.file);
    });

    // Paginate: 10 findings per page (clamp so filtering never lands on an empty page).
    var totalPages = Math.max(1, Math.ceil(rows.length / WF_PAGE_SIZE));
    if (wfFindingsPage > totalPages) wfFindingsPage = totalPages;
    if (wfFindingsPage < 1) wfFindingsPage = 1;
    var pageRows = rows.slice((wfFindingsPage - 1) * WF_PAGE_SIZE, wfFindingsPage * WF_PAGE_SIZE);
    buildPagination('workflow-files-pagination', rows.length, wfFindingsPage, function(p) {
      wfFindingsPage = p;
      renderWorkflowFiles(files);
    }, WF_PAGE_SIZE);

    var thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Severity</th><th>Rule</th><th>Workflow</th><th>Finding</th></tr>';
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    pageRows.forEach(function(r) {
      var f = r.f, sev = f.severity || 'low';
      var loc = f.line ? ':' + f.line : '';
      var rule = '<span class="zizmor-rule">' + gEsc(f.rule_id) + '</span>';
      // Link the workflow to the exact file + line on GitHub.
      var wfLabel = r.repo + ' / ' + r.file + loc;
      var wfCell = (r.wf && r.wf.path)
        ? ghLinkHTML(ghFileUrl(r.repo, r.wf.path, f.line), wfLabel)
        : '<span class="zizmor-wf">' + gEsc(wfLabel) + '</span>';
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      tr.innerHTML =
        '<td><span class="sev-chip sev-' + gEsc(sev) + '">' + gEsc(sev) + '</span></td>' +
        '<td>' + rule + '</td>' +
        '<td>' + wfCell + '</td>' +
        '<td class="zizmor-desc-cell">' + gEsc(f.desc) + '</td>';
      // Click → open the dedicated detail page for this workflow's findings.
      tr.addEventListener('click', (function(wf) {
        return function() { showWorkflowDetailView(wf); };
      })(r.wf));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  // --- GitHub Actions Inventory ---

  function loadActionsInventory() {
    fetchJSON('/api/actions-inventory').then(function(items) {
      actionsInventoryData = items || [];
      actionsInvPage = 1;
      renderActionsInventory(actionsInventoryData);
      setCount('count-actions-inventory', actionsInventoryData.length);
      showTab('tab-actions-inventory', actionsInventoryData.length > 0);
    }).catch(function() {});
  }

  function fmtActionVersion(v) {
    if (/^[0-9a-f]{40}$/i.test(v)) return v.slice(0, 7) + '… (sha)';
    return v;
  }

  function renderActionsInventorySummary(items) {
    var el = document.getElementById('actions-inventory-summary');
    if (!el) return;
    items = items || [];
    var unpinned = items.filter(function(i) { return !i.all_pinned; });
    var thirdParty = items.filter(function(i) { return i.trust === 'third_party'; });

    // Each tile drills into its matching subset, and rows open the action detail
    // view — matching the click-through on the other tabs.
    var ACOLS = [
      { h: 'Action', c: function(it) { return ghLinkHTML(ghActionUrl(it.identifier), it.identifier); } },
      { h: 'Trust', c: function(it) { return gEsc(it.trust_label || it.trust || '—'); } },
      { h: 'Pinned', c: function(it) { return it.all_pinned ? 'Yes' : 'No'; } },
      { h: 'Workflows', c: function(it) { return it.workflows; } },
      { h: 'Repos', c: function(it) { return it.repos; } },
    ];
    function onAction(it) { navTo('tab-actions-inventory'); showActionDetailView(it.identifier); }
    var aOpts = { cols: ACOLS, onRow: onAction };

    var boxes = [
      { v: items.length,      l: 'distinct actions', sev: '',       drill: registerDrill('ab-total', 'actions-inventory', 'Actions in use', items, aOpts) },
      { v: unpinned.length,   l: 'unpinned',         sev: 'high',   drill: registerDrill('ab-unpinned', 'actions-inventory', 'Unpinned actions', unpinned, aOpts) },
      { v: thirdParty.length, l: 'third-party',      sev: 'medium', drill: registerDrill('ab-thirdparty', 'actions-inventory', 'Third-party actions', thirdParty, aOpts) },
    ];
    el.innerHTML = boxes.map(function(b) { return statBox(b.v, b.l, b.sev, b.drill); }).join('');
  }

  // renderActionsInventory lists every distinct action used across the org with
  // the versions in use, pinning status, and how widely it is used. `items` may
  // be a filtered subset (search box); the summary reflects the full set.
  function renderActionsInventory(items) {
    items = items || [];
    showActionListView();
    renderActionsInventorySummary(actionsInventoryData);
    // Apply trust filter
    if (actionsTrustFilter) {
      items = items.filter(function(it) { return it.trust === actionsTrustFilter; });
    }
    var table = document.getElementById('actions-inventory-table');
    if (!table) return;
    table.innerHTML = '';

    if (items.length === 0) {
      table.innerHTML = '<tbody><tr><td class="empty-cell">No actions found.</td></tr></tbody>';
      var pg = document.getElementById('actions-inventory-pagination');
      if (pg) pg.innerHTML = '';
      return;
    }

    var totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
    if (actionsInvPage > totalPages) actionsInvPage = totalPages;
    if (actionsInvPage < 1) actionsInvPage = 1;
    var pageItems = items.slice((actionsInvPage - 1) * PAGE_SIZE, actionsInvPage * PAGE_SIZE);
    buildPagination('actions-inventory-pagination', items.length, actionsInvPage, function(p) {
      actionsInvPage = p;
      renderActionsInventory(items);
    }, PAGE_SIZE);

    var thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Action</th><th>Trust</th><th>Versions in use</th><th>Pinned</th><th>Workflows</th><th>Repos</th></tr>';
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    pageItems.forEach(function(it) {
      var versions = (it.versions || []).map(function(v) {
        return '<span class="ver-badge">' + gEsc(fmtActionVersion(v)) + '</span>';
      }).join(' ');
      var trustCls = it.trust === 'third_party' ? 'high' : (it.trust === 'verified' ? 'medium' : 'low');
      var pinned = it.all_pinned ? '<span class="badge neutral">Yes</span>' : '<span class="badge neutral">No</span>';
      var kindTag = it.kind === 'reusable_workflow' ? ' <span class="kind-tag">reusable</span>' : '';
      var tr = document.createElement('tr');
      tr.classList.add('expandable');
      tr.innerHTML =
        '<td>' + ghLinkHTML(ghActionUrl(it.identifier), it.identifier) + kindTag + '</td>' +
        '<td><span class="badge ' + trustCls + '">' + gEsc(it.trust_label) + '</span></td>' +
        '<td>' + versions + '</td>' +
        '<td>' + pinned + '</td>' +
        '<td>' + it.workflows + '</td>' +
        '<td>' + it.repos + '</td>';
      tr.addEventListener('click', (function(id) {
        return function() { showActionDetailView(id); };
      })(it.identifier));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
  }

  function showActionListView() {
    var d = document.getElementById('actions-inv-detail-view');
    var l = document.getElementById('actions-inv-list-view');
    if (d) d.style.display = 'none';
    if (l) l.style.display = 'block';
  }

  // showActionDetailView swaps the BOM tab to a per-action usage page.
  function showActionDetailView(identifier) {
    var l = document.getElementById('actions-inv-list-view');
    var d = document.getElementById('actions-inv-detail-view');
    var body = document.getElementById('actions-inv-detail-body');
    if (!l || !d || !body) return;
    body.innerHTML = '';
    body.appendChild(buildActionDetail(identifier));
    l.style.display = 'none';
    d.style.display = 'block';
    renderActionUsages(); // fill the table now that it's in the DOM
    var content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
  }

  // buildActionDetail computes how one action is used across the org (versions,
  // repos, workflows, pinning) from the in-memory workflow data.
  function buildActionDetail(identifier) {
    var usages = [];
    (report && report.workflow_files || []).forEach(function(wf) {
      (wf.actions || []).forEach(function(a) {
        if ((a.owner + '/' + a.name) === identifier) {
          usages.push({ repo: wf.repo_name, file: wf.file_name, path: wf.path, ref: a.ref || '(unspecified)', pinned: a.pinned });
        }
      });
    });

    var meta = (actionsInventoryData || []).filter(function(i) { return i.identifier === identifier; })[0] || {};
    var repos = {}, wfs = {}, versions = {}, unpinned = 0;
    usages.forEach(function(u) {
      repos[u.repo] = true;
      wfs[u.repo + '/' + u.file] = true;
      versions[u.ref] = (versions[u.ref] || 0) + 1;
      if (!u.pinned) unpinned++;
    });

    var wrap = document.createElement('div');

    // Header
    var head = document.createElement('div');
    head.className = 'section-header';
    var trust = meta.trust_label ? ' <span class="badge ' + (meta.trust === 'third_party' ? 'high' : meta.trust === 'verified' ? 'medium' : 'low') + '">' + gEsc(meta.trust_label) + '</span>' : '';
    head.innerHTML = '<h2>' + ghLinkHTML(ghActionUrl(identifier), identifier) + trust + '</h2>';
    wrap.appendChild(head);

    // Stat strip
    var strip = document.createElement('div');
    strip.className = 'stat-strip';
    strip.innerHTML = [
      statBox(usages.length, 'total uses', ''),
      statBox(Object.keys(versions).length, 'versions', ''),
      statBox(Object.keys(wfs).length, 'workflows', ''),
      statBox(Object.keys(repos).length, 'repositories', ''),
      statBox(unpinned, 'unpinned uses', unpinned ? 'high' : ''),
    ].join('');
    wrap.appendChild(strip);

    // Store state for the filterable/paginated usage table.
    actionUsages = usages;
    actionVerFilter = '';
    actionUsagePage = 1;

    // Version filter chips (each version + its usage count — doubles as the
    // versions breakdown, so no separate list).
    var vkeys = Object.keys(versions).sort(function(a, b) { return versions[b] - versions[a]; });
    var chipRow = document.createElement('div');
    chipRow.className = 'chip-row';
    chipRow.innerHTML = '<span class="chip-row-label">Version</span>' +
      '<select class="filter-select" id="action-ver-select"><option value="">All (' + usages.length + ')</option>' +
      vkeys.map(function(v) {
        return '<option value="' + gEsc(v) + '">' + gEsc(fmtActionVersion(v)) + ' (' + versions[v] + ')</option>';
      }).join('') + '</select>';
    chipRow.querySelector('#action-ver-select').addEventListener('change', function() {
      actionVerFilter = this.value;
      actionUsagePage = 1;
      renderActionUsages();
    });
    wrap.appendChild(chipRow);

    // Usage table container (filled by renderActionUsages once in the DOM).
    var usec = document.createElement('div');
    usec.className = 'detail-section detail-full-width';
    usec.innerHTML = '<div class="detail-section-title" id="action-usage-title"></div>' +
      '<div class="table-wrap"><table id="action-usage-table"></table></div>' +
      '<div class="pagination" id="action-usage-pagination"></div>';
    wrap.appendChild(usec);

    return wrap;
  }

  // renderActionUsages renders the version-filtered, 15-per-page usage table for
  // the currently open action.
  function renderActionUsages() {
    var table = document.getElementById('action-usage-table');
    if (!table) return;
    var filtered = actionVerFilter
      ? actionUsages.filter(function(u) { return u.ref === actionVerFilter; })
      : actionUsages;
    filtered = filtered.slice().sort(function(a, b) { return (a.repo + a.file).localeCompare(b.repo + b.file); });

    var title = document.getElementById('action-usage-title');
    if (title) title.textContent = 'Where it is used (' + filtered.length + ')';

    var totalPages = Math.max(1, Math.ceil(filtered.length / ACTION_USAGE_PAGE_SIZE));
    if (actionUsagePage > totalPages) actionUsagePage = totalPages;
    if (actionUsagePage < 1) actionUsagePage = 1;
    var pageRows = filtered.slice((actionUsagePage - 1) * ACTION_USAGE_PAGE_SIZE, actionUsagePage * ACTION_USAGE_PAGE_SIZE);

    var rows = pageRows.map(function(u) {
      return '<tr>' +
        '<td>' + ghLinkHTML(ghRepoUrl(u.repo), u.repo) + '</td>' +
        '<td>' + ghLinkHTML(ghFileUrl(u.repo, u.path), u.file) + '</td>' +
        '<td><span class="ver-badge">' + gEsc(fmtActionVersion(u.ref)) + '</span></td>' +
        '<td><span class="badge ' + (u.pinned ? 'neutral' : 'medium') + '">' + (u.pinned ? 'pinned' : 'unpinned') + '</span></td>' +
        '</tr>';
    }).join('');
    table.innerHTML = '<thead><tr><th>Repository</th><th>Workflow</th><th>Version</th><th>Pinned</th></tr></thead><tbody>' +
      (rows || '<tr><td class="empty-cell">No usages for this version.</td></tr>') + '</tbody>';

    buildPagination('action-usage-pagination', filtered.length, actionUsagePage, function(p) {
      actionUsagePage = p;
      renderActionUsages();
    }, ACTION_USAGE_PAGE_SIZE);
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

  // --- GitHub deep-link helpers (open github.com in a new tab; the user's
  // browser session handles auth). All take the org from the loaded report. ---
  function ghBase() { return 'https://github.com/' + encodeURIComponent(orgName); }
  function ghRepoUrl(repo) { return ghBase() + '/' + encodeURIComponent(repo); }
  function ghFileUrl(repo, path, line) {
    var u = ghRepoUrl(repo) + '/blob/HEAD/' + path.split('/').map(encodeURIComponent).join('/');
    return line ? u + '#L' + line : u;
  }
  function ghUserUrl(login) { return 'https://github.com/' + encodeURIComponent(login); }
  function ghAppUrl(slug) { return 'https://github.com/apps/' + encodeURIComponent(slug); }
  // owner/name (action) or owner/repo/path... (reusable workflow) → repo page.
  function ghActionUrl(identifier) {
    var p = String(identifier).split('/');
    if (p.length <= 2) return 'https://github.com/' + p.join('/');
    return 'https://github.com/' + p[0] + '/' + p[1];
  }
  function ghRepoSettingsUrl(repo, section) { return ghRepoUrl(repo) + '/settings/' + section; }
  function ghOrgSettingsUrl(section) { return 'https://github.com/organizations/' + encodeURIComponent(orgName) + '/settings/' + section; }

  // ghLinkHTML returns an <a> string; addLinkCell appends a linked <td>.
  function ghLinkHTML(url, text) {
    return '<a href="' + url + '" target="_blank" rel="noopener" class="gh-link">' + gEsc(text) + '</a>';
  }
  function addLinkCell(tr, url, text) {
    var td = document.createElement('td');
    if (text && orgName) {
      td.innerHTML = ghLinkHTML(url, text);
    } else {
      td.textContent = text || '-';
    }
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

  // SSO type filter chips (main SSO tab)
  document.querySelectorAll('#sso-type-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#sso-type-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      ssoTypeFilter = btn.dataset.type;
      ssoPage = 1;
      if (report) renderSSOCredentials(report.sso_credentials);
    });
  });

  // SSO expiry filter chips (main SSO tab)
  document.querySelectorAll('#sso-expiry-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#sso-expiry-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      ssoExpiryFilter = btn.dataset.expiry;
      ssoPage = 1;
      if (report) renderSSOCredentials(report.sso_credentials);
    });
  });

  // SSO type filter chips inside the drill-down view
  document.querySelectorAll('#drill-sso-type-chips .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#drill-sso-type-chips .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      drillSsoTypeFilter = btn.dataset.type;
      drillPage = 1;
      renderDrillTable();
    });
  });

  // SSO expiry filter chips inside the drill-down view
  document.querySelectorAll('#drill-sso-expiry-chips .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#drill-sso-expiry-chips .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      drillSsoExpiryFilter = btn.dataset.expiry;
      drillPage = 1;
      renderDrillTable();
    });
  });

  // Actions BOM trust filter chips
  document.querySelectorAll('#actions-trust-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#actions-trust-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      actionsTrustFilter = btn.dataset.trust;
      actionsInvPage = 1;
      renderActionsInventory(actionsInventoryData);
    });
  });

  document.querySelectorAll('#secrets-scope-filter .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#secrets-scope-filter .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      secretScopeFilter = btn.dataset.scope;
      secretPage = 1;
      if (report) renderSecrets(report.secrets);
    });
  });

  document.querySelectorAll('#pats-view-toggle .filter-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#pats-view-toggle .filter-chip').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      setPatsView(btn.dataset.view);
    });
  });

  setupFilter('pats-filter', renderPATs, 'pats');
  setupFilter('apps-filter', function(apps) { appPage = 1; renderApps(apps); }, 'apps');
  setupFilter('sso-filter', function(creds) { ssoPage = 1; renderSSOCredentials(creds); }, 'sso_credentials');
  setupFilter('secrets-filter', function(s) { secretPage = 1; renderSecrets(s); }, 'secrets');
  setupFilter('deploy-keys-filter', renderDeployKeys, 'deploy_keys');
  setupFilter('workflow-perms-filter', function(p) { wpPage = 1; renderWorkflowPerms(p); }, 'workflow_permissions');
  setupFilter('workflow-files-filter', renderWorkflowFiles, 'workflow_files');
  (function() {
    var inp = document.getElementById('actions-inventory-filter');
    if (!inp) return;
    inp.addEventListener('input', function(e) {
      var q = e.target.value.toLowerCase();
      actionsInvPage = 1;
      if (!q) { renderActionsInventory(actionsInventoryData); return; }
      renderActionsInventory(actionsInventoryData.filter(function(it) {
        return JSON.stringify(it).toLowerCase().indexOf(q) !== -1;
      }));
    });
  })();

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
          secretPage = 1; renderSecrets(data.secrets);
          renderDeployKeys(data.deploy_keys);
          wpPage = 1; renderWorkflowPerms(data.workflow_permissions);
          renderWorkflowFiles(data.workflow_files);
          document.getElementById('scan-time').textContent =
            'Last scan\n' + new Date(data.scanned_at).toLocaleString();
          updateTabCounts();
          renderInsightStrips(data);
          renderOverview();
          graphBuilt = false;
          if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
          fetchJSON('/api/violations').then(function(v) { if (report) report.violations = v; renderViolations(v); updateViolationCount(v.length); });
          fetchJSON('/api/diff').then(function(d) { diffData = d; renderDiff(d); });
          loadCompliance();
          loadActionsInventory();
          loadOverviewInsights();
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
      complianceChecks = checks || [];
      renderCompliance(complianceChecks);
      renderComplianceFailing(complianceChecks);
      renderOverview();
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
    if (container) container.innerHTML = '';

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

    // The detailed control cards were removed from the Overview; the compact
    // failing-controls list (renderComplianceFailing) covers the actionable part.
    if (!container) return;

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
    if (tabId === 'tab-attack-surface') {
      if (!graphBuilt && report) initAttackSurfaceGraph();
      else if (cyInstance && cyInstance.edges().length) startEdgeFlow(); // resume flow on re-entry
    } else {
      stopEdgeFlow(); // pause the rAF loop while another tab is active
    }
  });

  function updateTabCounts() {
    if (!report) return;
    setCount('count-pats', (report.pats || []).length);
    setCount('count-apps', (report.apps || []).length);

    var reqCount = (report.pending_requests || []).length;
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
      if (item.html) value.innerHTML = item.html; else value.textContent = item.value;
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
      { label: 'GitHub App', html: app.app_slug ? ghLinkHTML(ghAppUrl(app.app_slug), '@' + app.app_slug) : '-' },
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
      buildFindingsSection(file),
      buildRiskSection(assessment),
      buildRecommendationsSection(assessment),
      buildSupplyChainSection(scenarios),
      buildMetaSection('Workflow Details', metaItems),
    ]);
  }

  // Curated remediation guidance per rule, so the detail view is actionable
  // without depending on (or naming) the external analyzer.
  var FINDING_REMEDIATION = {
    'template-injection': 'Do not interpolate untrusted ${{ github.* }} context directly into run: scripts. Pass values through env: and reference them as $VARS, or use actions/github-script with explicit inputs.',
    'excessive-permissions': 'Set least-privilege permissions at the workflow or job level (e.g. permissions: { contents: read }). Avoid write-all and grant only the scopes the job needs.',
    'artipacked': 'Set persist-credentials: false on actions/checkout unless a later step needs the stored token — otherwise the credential can be packed into uploaded artifacts.',
    'dangerous-triggers': 'pull_request_target / workflow_run run with repository secrets against untrusted input. Avoid them, or move privileged steps to a separate workflow gated by a protected environment, and never check out untrusted code while secrets are in scope.',
    'secrets-inherit': 'Avoid secrets: inherit when calling reusable workflows; pass only the specific secrets that workflow requires.',
    'cache-poisoning': 'Use restrictive cache keys and avoid restoring caches across trust boundaries; disable caching on release/deploy workflows where a poisoned cache could reach production.',
    'unpinned-uses': 'Pin actions to a full commit SHA rather than a mutable tag or branch.',
    'github-env': 'Avoid writing untrusted data to $GITHUB_ENV / $GITHUB_PATH; an attacker-controlled value can alter later steps.'
  };

  function findingRemediation(ruleID) {
    return FINDING_REMEDIATION[ruleID] || 'Review the flagged step and apply least-privilege and input-sanitization best practices.';
  }

  // buildFindingsSection renders the full, severity-ranked security findings for
  // a workflow, each with its description and remediation guidance.
  function buildFindingsSection(file) {
    var findings = (file.zizmor_findings || []).slice();
    if (findings.length === 0) return null;
    findings.sort(function(a, b) {
      return (ZIZMOR_SEV_ORDER[a.severity] != null ? ZIZMOR_SEV_ORDER[a.severity] : 9) -
             (ZIZMOR_SEV_ORDER[b.severity] != null ? ZIZMOR_SEV_ORDER[b.severity] : 9);
    });

    var section = document.createElement('div');
    section.className = 'detail-section detail-full-width';
    var title = document.createElement('div');
    title.className = 'detail-section-title';
    var fileLabel = file.repo_name + ' / ' + file.file_name;
    var fileLink = (orgName && file.path) ? ghLinkHTML(ghFileUrl(file.repo_name, file.path), fileLabel) : gEsc(fileLabel);
    title.innerHTML = 'Security findings — ' + fileLink +
      ' <span style="color:var(--text-dim);font-weight:500">(' + findings.length + ')</span>';
    section.appendChild(title);

    findings.forEach(function(f) {
      var row = document.createElement('div');
      row.className = 'zizmor-finding';
      var sev = f.severity || 'low';
      var locText = f.line ? 'line ' + f.line : '';
      var loc = locText
        ? ' · ' + ((orgName && file.path) ? ghLinkHTML(ghFileUrl(file.repo_name, file.path, f.line), locText) : locText)
        : '';
      row.innerHTML = '<span class="sev-chip sev-' + gEsc(sev) + '">' + gEsc(sev) + '</span>' +
        '<span class="zizmor-rule">' + gEsc(f.rule_id) + '</span>' +
        '<span class="zizmor-loc">' + loc + (f.confidence ? ' · ' + gEsc(f.confidence) + ' confidence' : '') + '</span>' +
        '<div class="zizmor-desc">' + gEsc(f.desc) + '</div>' +
        '<div class="zizmor-fix"><span class="zizmor-fix-label">Fix:</span> ' + gEsc(findingRemediation(f.rule_id)) + '</div>';
      section.appendChild(row);
    });
    return section;
  }

  // renderZizmorSummary fills the banner above the audit table with aggregate
  // zizmor counts across all workflows.
  function renderZizmorSummary(files) {
    var el = document.getElementById('workflow-zizmor-summary');
    if (!el) return;
    var c = { high: 0, medium: 0, low: 0, informational: 0 }, total = 0, flagged = 0;
    (files || []).forEach(function(wf) {
      var fs = wf.zizmor_findings || [];
      if (fs.length) flagged++;
      fs.forEach(function(f) { total++; if (c[f.severity] != null) c[f.severity]++; });
    });
    if (total === 0) {
      el.innerHTML = '<span class="clean-note">No security findings across ' + (files || []).length + ' workflows</span>';
      return;
    }

    // Build the row subsets behind each tile so clicking a tile opens that list
    // (mirrors the drill-down behaviour of the PATs / Apps / Secrets tabs).
    var allFindings = [], affected = [];
    (files || []).forEach(function(wf) {
      var fs = wf.zizmor_findings || [];
      if (fs.length) affected.push(wf);
      fs.forEach(function(f) {
        allFindings.push({ f: f, repo: wf.repo_name, file: wf.file_name, wf: wf });
      });
    });
    function sevRows(sev) { return allFindings.filter(function(r) { return r.f.severity === sev; }); }
    var FCOLS = [
      { h: 'Severity', c: function(r) { var s = r.f.severity || 'low'; return '<span class="sev-chip sev-' + gEsc(s) + '">' + gEsc(s) + '</span>'; } },
      { h: 'Rule', c: function(r) { return '<span class="zizmor-rule">' + gEsc(r.f.rule_id) + '</span>'; } },
      { h: 'Workflow', c: function(r) { return gEsc(r.repo + ' / ' + r.file + (r.f.line ? ':' + r.f.line : '')); } },
      { h: 'Finding', c: function(r) { return gEsc(r.f.desc || ''); } },
    ];
    var WCOLS = [
      { h: 'Workflow', c: function(wf) { return gEsc((wf.repo_name || '') + ' / ' + (wf.file_name || '')); } },
      { h: 'Repository', c: function(wf) { return wf.repo_name ? ghLinkHTML(ghRepoUrl(wf.repo_name), wf.repo_name) : '—'; } },
      { h: 'Findings', c: function(wf) { return (wf.zizmor_findings || []).length; } },
    ];
    function onFinding(r) { navTo('tab-workflow-files'); showWorkflowDetailView(r.wf); }
    function onWf(wf) { navTo('tab-workflow-files'); showWorkflowDetailView(wf); }
    var fOpts = { cols: FCOLS, onRow: onFinding };

    var boxes = [
      { v: total,    l: 'findings',            sev: '',     drill: registerDrill('wa-total', 'workflow-files', 'Workflow security findings', allFindings, fOpts) },
      { v: flagged,  l: 'workflows affected',  sev: '',     drill: registerDrill('wa-affected', 'workflow-files', 'Workflows with findings', affected, { cols: WCOLS, onRow: onWf }) },
      { v: c.high,   l: 'high',                sev: 'high', drill: registerDrill('wa-high', 'workflow-files', 'High-severity workflow findings', sevRows('high'), fOpts) },
      { v: c.medium, l: 'medium',              sev: 'medium', drill: registerDrill('wa-medium', 'workflow-files', 'Medium-severity workflow findings', sevRows('medium'), fOpts) },
      { v: c.low,    l: 'low',                 sev: 'low',  drill: registerDrill('wa-low', 'workflow-files', 'Low-severity workflow findings', sevRows('low'), fOpts) },
    ];
    if (c.informational) boxes.push({ v: c.informational, l: 'informational', sev: 'informational', drill: registerDrill('wa-info', 'workflow-files', 'Informational workflow findings', sevRows('informational'), fOpts) });
    el.innerHTML = boxes.map(function(b) { return statBox(b.v, b.l, b.sev, b.drill); }).join('');
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
      // ── Base node: solid filled circle, white glyph, two-line label below ──
      // (Wiz Explorer style: bold name + muted type subtitle under each node.)
      { selector: 'node', style: {
        'shape': 'ellipse',
        'background-color': '#64748b', 'background-opacity': 1,
        'background-image': 'data(icon)',
        'background-width': '20px', 'background-height': '20px',
        'background-position-x': '50%', 'background-position-y': '50%',
        'background-clip': 'none',
        'label': 'data(label2)',
        'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 8,
        'text-wrap': 'wrap', 'text-max-width': '140px',
        'font-size': '11px', 'font-weight': '700', 'color': '#0f172a', 'line-height': 1.4,
        'border-width': 2.5, 'border-color': '#ffffff', 'border-opacity': 1,
        'width': 46, 'height': 46,
        'shadow-blur': 11, 'shadow-color': '#0f172a', 'shadow-opacity': 0.16, 'shadow-offset-x': 0, 'shadow-offset-y': 2,
      }},

      // ── Real GitHub avatar (apps / PAT owners / org): fill the circle with
      //    the actual logo instead of the octicon glyph. The data-URI glyphs are
      //    still used for nodes without an avatar. ──
      { selector: 'node[avatar]', style: {
        'background-image': 'data(avatar)',
        'background-fit': 'cover', 'background-clip': 'node',
        'background-width': '100%', 'background-height': '100%',
        'background-position-x': '50%', 'background-position-y': '50%',
        'background-color': '#ffffff',
      }},

      // ── Type identity = solid fill color (white glyph reads on every fill) ──
      { selector: 'node[type="pat"]',         style: { 'background-color': '#f97316' }},
      { selector: 'node[type="app"]',         style: { 'background-color': '#f97316' }},
      { selector: 'node[type="sso"]',         style: { 'background-color': '#a855f7' }},
      { selector: 'node[type="deploy_key"]',  style: { 'background-color': '#f59e0b' }},
      { selector: 'node[type="allrepos"]',    style: { 'background-color': '#3b82f6' }},
      { selector: 'node[type="repo"]',        style: { 'background-color': '#3b82f6' }},
      { selector: 'node[type="workflow"]',    style: { 'background-color': '#16a34a' }},
      { selector: 'node[type="action"]',      style: { 'background-color': '#8b5cf6' }},
      { selector: 'node[type="secret"]',      style: { 'background-color': '#0ea5e9' }},
      { selector: 'node[type="environment"]', style: { 'background-color': '#14b8a6' }},
      // OIDC role = the production boundary (crown jewel, enlarged + red glow).
      { selector: 'node[type="oidc_role"]', style: {
        'width': 58, 'height': 58, 'background-color': '#dc2626',
        'background-width': '24px', 'background-height': '24px',
        'border-color': '#ffffff', 'border-width': 3, 'color': '#b91c1c', 'font-weight': '800',
        'shadow-blur': 24, 'shadow-color': '#dc2626', 'shadow-opacity': 0.42, 'shadow-offset-y': 0,
      }},
      // AWS account = the production target (crown jewel) — strongest emphasis.
      { selector: 'node[type="aws_account"]', style: {
        'width': 66, 'height': 66, 'background-color': '#b91c1c',
        'background-width': '28px', 'background-height': '28px',
        'border-color': '#ffffff', 'border-width': 3.5, 'color': '#991b1b', 'font-weight': '800',
        'shadow-blur': 30, 'shadow-color': '#dc2626', 'shadow-opacity': 0.52, 'shadow-offset-y': 0,
      }},

      // High-risk nodes get a red halo (keeps their solid fill).
      { selector: 'node[risk="high"]', style: {
        'shadow-blur': 22, 'shadow-color': '#ef4444', 'shadow-opacity': 0.45, 'shadow-offset-y': 0,
      }},

      // Long-lived high-criticality secret = crown jewel (SaaS/infra boundary):
      // enlarged with a strong red halo, like the OIDC/AWS targets.
      { selector: 'node[boundary]', style: {
        'width': 56, 'height': 56,
        'background-width': '22px', 'background-height': '22px',
        'shadow-blur': 24, 'shadow-color': '#dc2626', 'shadow-opacity': 0.5, 'shadow-offset-y': 0,
        'font-weight': '800',
      }},

      // Collapse/expand toggle chip: a neutral dashed pill with a chevron — styled
      // to read as a CONTROL, not an entity, so it's clearly distinct from the
      // colored app/action nodes around it. Down chevron = expand, up = collapse.
      { selector: 'node[expander]', style: {
        'shape': 'round-rectangle',
        'background-color': '#64748b', 'background-opacity': 1,
        'background-image': 'data(icon)', 'background-width': '13px', 'background-height': '13px',
        'border-style': 'dashed', 'border-width': 2, 'border-color': '#94a3b8',
        'color': '#475569', 'font-weight': '700', 'font-size': '10px',
        'width': 56, 'height': 34,
        'shadow-blur': 0, 'shadow-opacity': 0,
      }},
      // Expanded ("Show less") chip gets a lighter fill to reinforce the flip.
      { selector: 'node[expander][expanded=1]', style: {
        'background-color': '#94a3b8',
      }},

      // ── Domain zones as real compound parents (true containment) ──
      // Nodes are children of their zone, so a node can never visually drift
      // into the wrong region the way the old bounding-box overlays allowed.
      { selector: 'node[zone]', style: {
        'shape': 'round-rectangle',
        'background-image': 'none',
        'background-color': '#475569', 'background-opacity': 0.06,
        'border-width': 1.5, 'border-color': 'rgba(71,85,105,0.40)', 'border-opacity': 1,
        'border-style': 'dashed',
        'label': 'data(label)', 'text-valign': 'top', 'text-halign': 'left',
        'text-margin-y': 6, 'text-margin-x': 10,
        'font-size': '11px', 'font-weight': '800', 'color': '#475569',
        'text-transform': 'uppercase', 'padding': '30px',
        'events': 'no',
        'shadow-blur': 0, 'shadow-opacity': 0,
      }},
      { selector: 'node[zone="cloud"]', style: {
        'background-color': '#dc2626', 'border-color': 'rgba(220,38,38,0.45)', 'color': '#b91c1c',
      }},

      // ── Edges: thin, clean, gradient-toned with subtle relationship labels ──
      { selector: 'edge', style: {
        'width': 1.6,
        'curve-style': 'taxi', 'taxi-direction': 'horizontal', 'taxi-turn': '45%',
        'target-arrow-shape': 'triangle', 'target-arrow-color': '#cbd5e1',
        'line-color': '#cbd5e1', 'arrow-scale': 1, 'opacity': 0.95,
        'label': 'data(label)', 'font-size': '8px', 'font-weight': '600', 'color': '#94a3b8',
        'text-background-color': '#ffffff', 'text-background-opacity': 0.92,
        'text-background-padding': '2px', 'text-background-shape': 'roundrectangle',
      }},
      { selector: 'edge[edgeType="controls"]',          style: { 'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b', 'width': 2 }},
      { selector: 'edge[edgeType="can_modify"]',        style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', 'width': 2 }},
      { selector: 'edge[edgeType="has_access"]',        style: { 'line-color': '#3b82f6', 'target-arrow-color': '#3b82f6' }},
      { selector: 'edge[edgeType="can_trigger"]',       style: { 'line-color': '#16a34a', 'target-arrow-color': '#16a34a' }},
      { selector: 'edge[edgeType="can_hijack"]',        style: { 'line-color': '#8b5cf6', 'target-arrow-color': '#8b5cf6', 'line-style': 'dashed', 'width': 2 }},
      { selector: 'edge[edgeType="references_secret"]', style: { 'line-color': '#0ea5e9', 'target-arrow-color': '#0ea5e9', 'width': 2 }},
      { selector: 'edge[edgeType="exposes_secret"]',    style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316', 'line-style': 'dashed' }},
      // The GitHub→AWS OIDC crossing = trust boundary (bold dashed red).
      { selector: 'edge[edgeType="assumes_role"]',      style: { 'line-color': '#dc2626', 'target-arrow-color': '#dc2626', 'width': 3, 'line-style': 'dashed', 'font-weight': '800', 'color': '#b91c1c' }},
      { selector: 'edge[edgeType="in_account"]',        style: { 'line-color': '#b91c1c', 'target-arrow-color': '#b91c1c', 'width': 2.5 }},
      { selector: 'edge[edgeType="deploys_to_env"]',    style: { 'line-color': '#14b8a6', 'target-arrow-color': '#14b8a6' }},
      { selector: 'edge[edgeType="includes"]',          style: { 'line-style': 'dotted', 'opacity': 0.25, 'label': '' }},

      // Flow edges: dashed pattern that startEdgeFlow() animates (marching ants).
      { selector: 'edge.flow', style: { 'line-style': 'dashed', 'line-dash-pattern': [6, 4] }},

      // ── Interaction states ─────────────────────────────────────
      { selector: '.dimmed', style: { 'opacity': 0.15 }},
      { selector: '.highlighted', style: { 'opacity': 1 }},
      { selector: 'edge.highlighted', style: { 'opacity': 1, 'width': 2.6, 'line-style': 'dashed', 'line-dash-pattern': [6, 4] }},
      { selector: '.blast-source', style: {
        'border-color': '#2563eb', 'border-width': 5,
        'shadow-blur': 26, 'shadow-color': '#2563eb', 'shadow-opacity': 0.5, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
        'font-weight': '800',
      }},
      { selector: '.filtered-out', style: { 'display': 'none' }},

      // ── Entry-points spotlight: ring colored by attacker-entry class (amber=
      //    supply-chain, indigo=identity, slate=trigger); non-entries dimmed.
      //    Severity halo (shadow) is left intact, so it stacks with the ring. ──
      { selector: 'node.em-supplychain', style: { 'border-color': '#f59e0b', 'border-width': 6, 'border-opacity': 1 }},
      { selector: 'node.em-identity',    style: { 'border-color': '#6366f1', 'border-width': 6, 'border-opacity': 1 }},
      { selector: 'node.em-trigger',     style: { 'border-color': '#64748b', 'border-width': 6, 'border-opacity': 1 }},
      { selector: '.entry-dim', style: { 'opacity': 0.18 }},
    ];
  }

  // Authentic GitHub Octicons (16×16, fill, MIT-licensed) for each entity type —
  // used both as inline SVG in the attack-path cards and as node background images
  // in the graph. AWS/OIDC (outside GitHub) use the server/key marks.
  var NODE_SVG = {
    pat:        '<path d="M10.5 0a5.499 5.499 0 1 1-1.288 10.848l-.932.932a.749.749 0 0 1-.53.22H7v.75a.749.749 0 0 1-.22.53l-.5.5a.749.749 0 0 1-.53.22H5v.75a.749.749 0 0 1-.22.53l-.5.5a.749.749 0 0 1-.53.22h-2A1.75 1.75 0 0 1 0 14.25v-2c0-.199.079-.389.22-.53l4.932-4.932A5.5 5.5 0 0 1 10.5 0Zm-4 5.5c-.001.431.069.86.205 1.269a.75.75 0 0 1-.181.768L1.5 12.56v1.69c0 .138.112.25.25.25h1.69l.06-.06v-1.19a.75.75 0 0 1 .75-.75h1.19l.06-.06v-1.19a.75.75 0 0 1 .75-.75h1.19l1.023-1.025a.75.75 0 0 1 .768-.18A4 4 0 1 0 6.5 5.5ZM11 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z"/>',
    app:        '<path d="M1.5 3.25c0-.966.784-1.75 1.75-1.75h2.5c.966 0 1.75.784 1.75 1.75v2.5A1.75 1.75 0 0 1 5.75 7.5h-2.5A1.75 1.75 0 0 1 1.5 5.75Zm7 0c0-.966.784-1.75 1.75-1.75h2.5c.966 0 1.75.784 1.75 1.75v2.5a1.75 1.75 0 0 1-1.75 1.75h-2.5A1.75 1.75 0 0 1 8.5 5.75Zm-7 7c0-.966.784-1.75 1.75-1.75h2.5c.966 0 1.75.784 1.75 1.75v2.5a1.75 1.75 0 0 1-1.75 1.75h-2.5a1.75 1.75 0 0 1-1.75-1.75Zm7 0c0-.966.784-1.75 1.75-1.75h2.5c.966 0 1.75.784 1.75 1.75v2.5a1.75 1.75 0 0 1-1.75 1.75h-2.5a1.75 1.75 0 0 1-1.75-1.75ZM3.25 3a.25.25 0 0 0-.25.25v2.5c0 .138.112.25.25.25h2.5A.25.25 0 0 0 6 5.75v-2.5A.25.25 0 0 0 5.75 3Zm7 0a.25.25 0 0 0-.25.25v2.5c0 .138.112.25.25.25h2.5a.25.25 0 0 0 .25-.25v-2.5a.25.25 0 0 0-.25-.25Zm-7 7a.25.25 0 0 0-.25.25v2.5c0 .138.112.25.25.25h2.5a.25.25 0 0 0 .25-.25v-2.5a.25.25 0 0 0-.25-.25Zm7 0a.25.25 0 0 0-.25.25v2.5c0 .138.112.25.25.25h2.5a.25.25 0 0 0 .25-.25v-2.5a.25.25 0 0 0-.25-.25Z"/>',
    sso:        '<path d="M10.561 8.073a6.005 6.005 0 0 1 3.432 5.142.75.75 0 1 1-1.498.07 4.5 4.5 0 0 0-8.99 0 .75.75 0 0 1-1.498-.07 6.004 6.004 0 0 1 3.431-5.142 3.999 3.999 0 1 1 5.123 0ZM10.5 5a2.5 2.5 0 1 0-5 0 2.5 2.5 0 0 0 5 0Z"/>',
    deploy_key: '<path d="M0 2.75A2.75 2.75 0 0 1 2.75 0h10.5A2.75 2.75 0 0 1 16 2.75v10.5A2.75 2.75 0 0 1 13.25 16H2.75A2.75 2.75 0 0 1 0 13.25ZM2.75 1.5c-.69 0-1.25.56-1.25 1.25v10.5c0 .69.56 1.25 1.25 1.25h10.5c.69 0 1.25-.56 1.25-1.25V2.75c0-.69-.56-1.25-1.25-1.25Z"/><path d="M8 4a.75.75 0 0 1 .75.75V6.7l1.69-.975a.75.75 0 0 1 .75 1.3L9.5 8l1.69.976a.75.75 0 0 1-.75 1.298L8.75 9.3v1.951a.75.75 0 0 1-1.5 0V9.299l-1.69.976a.75.75 0 0 1-.75-1.3L6.5 8l-1.69-.975a.75.75 0 0 1 .75-1.3l1.69.976V4.75A.75.75 0 0 1 8 4Z"/>',
    allrepos:   '<path d="M7.122.392a1.75 1.75 0 0 1 1.756 0l5.003 2.902c.83.481.83 1.68 0 2.162L8.878 8.358a1.75 1.75 0 0 1-1.756 0L2.119 5.456a1.251 1.251 0 0 1 0-2.162ZM8.125 1.69a.248.248 0 0 0-.25 0l-4.63 2.685 4.63 2.685a.248.248 0 0 0 .25 0l4.63-2.685ZM1.601 7.789a.75.75 0 0 1 1.025-.273l5.249 3.044a.248.248 0 0 0 .25 0l5.249-3.044a.75.75 0 0 1 .752 1.298l-5.248 3.044a1.75 1.75 0 0 1-1.756 0L1.874 8.814A.75.75 0 0 1 1.6 7.789Zm0 3.5a.75.75 0 0 1 1.025-.273l5.249 3.044a.248.248 0 0 0 .25 0l5.249-3.044a.75.75 0 0 1 .752 1.298l-5.248 3.044a1.75 1.75 0 0 1-1.756 0l-5.248-3.044a.75.75 0 0 1-.273-1.025Z"/>',
    repo:       '<path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.495 2.495 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.708A2.486 2.486 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.087a.249.249 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z"/>',
    workflow:   '<path d="M0 1.75C0 .784.784 0 1.75 0h3.5C6.216 0 7 .784 7 1.75v3.5A1.75 1.75 0 0 1 5.25 7H4v4a1 1 0 0 0 1 1h4v-1.25C9 9.784 9.784 9 10.75 9h3.5c.966 0 1.75.784 1.75 1.75v3.5A1.75 1.75 0 0 1 14.25 16h-3.5A1.75 1.75 0 0 1 9 14.25v-.75H5A2.5 2.5 0 0 1 2.5 11V7h-.75A1.75 1.75 0 0 1 0 5.25Zm1.75-.25a.25.25 0 0 0-.25.25v3.5c0 .138.112.25.25.25h3.5a.25.25 0 0 0 .25-.25v-3.5a.25.25 0 0 0-.25-.25Zm9 9a.25.25 0 0 0-.25.25v3.5c0 .138.112.25.25.25h3.5a.25.25 0 0 0 .25-.25v-3.5a.25.25 0 0 0-.25-.25Z"/>',
    action:     '<path d="m8.878.392 5.25 3.045c.54.314.872.89.872 1.514v6.098a1.75 1.75 0 0 1-.872 1.514l-5.25 3.045a1.75 1.75 0 0 1-1.756 0l-5.25-3.045A1.75 1.75 0 0 1 1 11.049V4.951c0-.624.332-1.201.872-1.514L7.122.392a1.75 1.75 0 0 1 1.756 0ZM7.875 1.69l-4.63 2.685L8 7.133l4.755-2.758-4.63-2.685a.248.248 0 0 0-.25 0ZM2.5 5.677v5.372c0 .09.047.171.125.216l4.625 2.683V8.432Zm6.25 8.271 4.625-2.683a.25.25 0 0 0 .125-.216V5.677L8.75 8.432Z"/>',
    secret:     '<path d="m8.533.133 5.25 1.68A1.75 1.75 0 0 1 15 3.48V7c0 1.566-.32 3.182-1.303 4.682-.983 1.498-2.585 2.813-5.032 3.855a1.697 1.697 0 0 1-1.33 0c-2.447-1.042-4.049-2.357-5.032-3.855C1.32 10.182 1 8.566 1 7V3.48a1.75 1.75 0 0 1 1.217-1.667l5.25-1.68a1.748 1.748 0 0 1 1.066 0Zm-.61 1.429.001.001-5.25 1.68a.251.251 0 0 0-.174.237V7c0 1.36.275 2.666 1.057 3.859.784 1.194 2.121 2.342 4.366 3.298a.196.196 0 0 0 .154 0c2.245-.957 3.582-2.103 4.366-3.297C13.225 9.666 13.5 8.358 13.5 7V3.48a.25.25 0 0 0-.174-.238l-5.25-1.68a.25.25 0 0 0-.153 0ZM9.5 6.5c0 .536-.286 1.032-.75 1.3v2.45a.75.75 0 0 1-1.5 0V7.8A1.5 1.5 0 1 1 9.5 6.5Z"/>',
    oidc_role:  '<path d="M10.5 0a5.499 5.499 0 1 1-1.288 10.848l-.932.932a.749.749 0 0 1-.53.22H7v.75a.749.749 0 0 1-.22.53l-.5.5a.749.749 0 0 1-.53.22H5v.75a.749.749 0 0 1-.22.53l-.5.5a.749.749 0 0 1-.53.22h-2A1.75 1.75 0 0 1 0 14.25v-2c0-.199.079-.389.22-.53l4.932-4.932A5.5 5.5 0 0 1 10.5 0Zm-4 5.5c-.001.431.069.86.205 1.269a.75.75 0 0 1-.181.768L1.5 12.56v1.69c0 .138.112.25.25.25h1.69l.06-.06v-1.19a.75.75 0 0 1 .75-.75h1.19l.06-.06v-1.19a.75.75 0 0 1 .75-.75h1.19l1.023-1.025a.75.75 0 0 1 .768-.18A4 4 0 1 0 6.5 5.5ZM11 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z"/>',
    aws_account:'<path d="M1.75 1h12.5c.966 0 1.75.784 1.75 1.75v4c0 .372-.116.717-.314 1 .198.283.314.628.314 1v4a1.75 1.75 0 0 1-1.75 1.75H1.75A1.75 1.75 0 0 1 0 12.75v-4c0-.358.109-.707.314-1a1.739 1.739 0 0 1-.314-1v-4C0 1.784.784 1 1.75 1ZM1.5 2.75v4c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25v-4a.25.25 0 0 0-.25-.25H1.75a.25.25 0 0 0-.25.25Zm.25 5.75a.25.25 0 0 0-.25.25v4c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25v-4a.25.25 0 0 0-.25-.25ZM7 4.75A.75.75 0 0 1 7.75 4h4.5a.75.75 0 0 1 0 1.5h-4.5A.75.75 0 0 1 7 4.75ZM7.75 10h4.5a.75.75 0 0 1 0 1.5h-4.5a.75.75 0 0 1 0-1.5ZM3 4.75A.75.75 0 0 1 3.75 4h.5a.75.75 0 0 1 0 1.5h-.5A.75.75 0 0 1 3 4.75ZM3.75 10h.5a.75.75 0 0 1 0 1.5h-.5a.75.75 0 0 1 0-1.5Z"/>',
    environment:'<path d="M14.064 0h.186C15.216 0 16 .784 16 1.75v.186a8.752 8.752 0 0 1-2.564 6.186l-.458.459c-.314.314-.641.616-.979.904v3.207c0 .608-.315 1.172-.833 1.49l-2.774 1.707a.749.749 0 0 1-1.11-.418l-.954-3.102a1.214 1.214 0 0 1-.145-.125L3.754 9.816a1.218 1.218 0 0 1-.124-.145L.528 8.717a.749.749 0 0 1-.418-1.11l1.71-2.774A1.748 1.748 0 0 1 3.31 4h3.204c.288-.338.59-.665.904-.979l.459-.458A8.749 8.749 0 0 1 14.064 0ZM8.938 3.623h-.002l-.458.458c-.76.76-1.437 1.598-2.02 2.5l-1.5 2.317 2.143 2.143 2.317-1.5c.902-.583 1.74-1.26 2.499-2.02l.459-.458a7.25 7.25 0 0 0 2.123-5.127V1.75a.25.25 0 0 0-.25-.25h-.186a7.249 7.249 0 0 0-5.125 2.123ZM3.56 14.56c-.732.732-2.334 1.045-3.005 1.148a.234.234 0 0 1-.201-.064.234.234 0 0 1-.064-.201c.103-.671.416-2.273 1.15-3.003a1.502 1.502 0 1 1 2.12 2.12Zm6.94-3.935c-.088.06-.177.118-.266.175l-2.35 1.521.548 1.783 1.949-1.2a.25.25 0 0 0 .119-.213ZM3.678 8.116 5.2 5.766c.058-.09.117-.178.176-.266H3.309a.25.25 0 0 0-.213.119l-1.2 1.95ZM12 5a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z"/>',
    trigger:    '<path d="M9.504.43a1.516 1.516 0 0 1 2.437 1.713L10.415 5.5h2.123c1.57 0 2.346 1.909 1.22 3.004l-7.34 7.142a1.249 1.249 0 0 1-.871.354h-.302a1.25 1.25 0 0 1-1.157-1.723L5.633 10.5H3.462c-1.57 0-2.346-1.909-1.22-3.004L9.503.43Z"/>'
  };
  // Inline SVG (inherits color via currentColor) for HTML cards.
  function iconSvg(type) {
    var inner = NODE_SVG[type] || '<circle cx="8" cy="8" r="5"/>';
    return '<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor">' + inner + '</svg>';
  }
  // Data-URI SVG for Cytoscape node background images. Glyphs are white so they
  // read on the solid-color node fills (Wiz Explorer style).
  function iconDataUri(type) {
    var color = '#ffffff';
    var inner = NODE_SVG[type] || '<circle cx="8" cy="8" r="5"/>';
    // width/height are REQUIRED here: without intrinsic dimensions an SVG data-URI
    // rasterizes to zero size on Chrome's canvas and the node shows no glyph.
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="' + color + '">' + inner + '</svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  // Chevron glyphs for the collapse/expand toggle chip — a control affordance
  // (down = "expand to show more", up = "collapse"), distinct from entity glyphs.
  var CHIP_SVG = {
    down: '<path d="M12.78 5.22a.749.749 0 0 1 0 1.06l-4.25 4.25a.749.749 0 0 1-1.06 0L3.22 6.28a.749.749 0 1 1 1.06-1.06L8 8.939l3.72-3.719a.749.749 0 0 1 1.06 0Z"/>',
    up:   '<path d="M3.22 10.78a.749.749 0 0 1 0-1.06l4.25-4.25a.749.749 0 0 1 1.06 0l4.25 4.25a.749.749 0 1 1-1.06 1.06L8 6.811 4.28 10.53a.749.749 0 0 1-1.06 0Z"/>'
  };
  function chipIconDataUri(expanded) {
    var inner = expanded ? CHIP_SVG.up : CHIP_SVG.down;
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="#ffffff">' + inner + '</svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  // nodeLabel2 builds the two-line node caption: bold name + muted type subtitle
  // (Wiz Explorer style). Crown jewels (prod boundary/target) get a 👑 prefix.
  function nodeLabel2(type, label) {
    var meta = GRAPH_TYPE_META[type];
    var sub = meta ? meta.label : type;
    var crown = (type === 'aws_account' || type === 'oidc_role') ? '👑 ' : '';
    return crown + (label || '') + '\n' + sub;
  }

  // EDGE_LABELS maps backend edge types to short uppercase labels on the graph.
  var EDGE_LABELS = {
    controls: 'CONTROLS', includes: 'VISIBLE_TO', can_hijack: 'USES',
    references_secret: 'READS', assumes_role: '⊥ TRUST BOUNDARY', deploys_to_env: 'DEPLOYS', in_account: 'IN ACCOUNT',
    // legacy client-side types, kept for safety
    can_modify: 'CAN_WRITE', has_access: 'CAN_READ', can_trigger: 'HAS_WORKFLOW', exposes_secret: 'HAS_SECRET'
  };

  // mapBackendGraph converts /api/attack-graph output into Cytoscape elements,
  // preserving the data shape the rest of the graph UI expects (entity, risk).
  function mapBackendGraph(g) {
    var nodes = (g.nodes || []).map(function(n) {
      var type = n.type === 'all_repos' ? 'allrepos' : n.type;
      var entity = n.meta || {};
      if (type === 'allrepos') entity = { total: (n.meta && n.meta.total) || 0 };
      var data = { id: n.id, type: type, label: n.label, name: n.label, label2: nodeLabel2(type, n.label), icon: iconDataUri(type), entity: entity, risk: n.risk || 'none' };
      var avatarUrl = n.meta && n.meta.avatar;
      if (avatarUrl) data.avatar = avatarUrl;
      return { data: data };
    });
    var edges = (g.edges || []).map(function(e) {
      return { data: { id: e.id, source: e.source, target: e.target,
        edgeType: e.type, label: EDGE_LABELS[e.type] || e.label || e.type } };
    });
    return { nodes: nodes, edges: edges };
  }

  function gEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function(c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  // loadFindings renders the insight-first hero: ranked attack paths to
  // production and prioritized action items. Clicking a row drills into the
  // (small, aggregated) graph below.
  function loadFindings() {
    var host = document.getElementById('graph-findings');
    if (!host) return;
    host.innerHTML = '<div class="findings-loading">Analyzing attack paths…</div>';
    fetchJSON('/api/attack-graph/findings').then(function(f) {
      if (!f) { host.innerHTML = ''; return; }
      host.innerHTML = '';
      host.appendChild(findingsSection('☁ Attack Paths to Production', f.paths || [], renderPathRow,
        'No workflow reaches a production boundary (OIDC role or prod environment).'));
      host.appendChild(findingsSection('🛠 Prioritized Action Items', f.actions || [], renderActionRow,
        'No action items surfaced.'));
      wireFindingRows(host);
    }).catch(function() { host.innerHTML = '<div class="findings-loading">Failed to load findings.</div>'; });
  }

  var FINDINGS_PAGE_SIZE = 10;

  function findingsSection(title, items, rowFn, emptyMsg) {
    var sec = document.createElement('div');
    sec.className = 'findings-section';
    var head = document.createElement('div');
    head.className = 'findings-title';
    // Count + severity breakdown reflect the FULL list, not the current page.
    head.innerHTML = title + ' <span class="findings-count">' + items.length + '</span>' + sevCounts(items);
    sec.appendChild(head);
    if (!items.length) {
      var empty = document.createElement('div');
      empty.className = 'findings-empty';
      empty.textContent = emptyMsg;
      sec.appendChild(empty);
      return sec;
    }
    var list = document.createElement('div');
    list.className = 'findings-list';
    sec.appendChild(list);
    var pager = document.createElement('div');
    pager.className = 'findings-pager';
    sec.appendChild(pager);

    var page = 0;
    var pageCount = Math.ceil(items.length / FINDINGS_PAGE_SIZE);

    function renderPage() {
      var start = page * FINDINGS_PAGE_SIZE;
      var end = Math.min(start + FINDINGS_PAGE_SIZE, items.length);
      var html = '';
      for (var i = start; i < end; i++) html += rowFn(items[i]);
      list.innerHTML = html;
      if (pageCount <= 1) { pager.style.display = 'none'; return; }
      pager.style.display = 'flex';
      pager.innerHTML =
        '<button class="findings-page-btn" data-dir="-1"' + (page === 0 ? ' disabled' : '') + '>‹ Prev</button>' +
        '<span class="findings-page-info">' + (start + 1) + '–' + end + ' of ' + items.length + '</span>' +
        '<button class="findings-page-btn" data-dir="1"' + (page >= pageCount - 1 ? ' disabled' : '') + '>Next ›</button>';
      pager.querySelectorAll('.findings-page-btn').forEach(function(b) {
        b.addEventListener('click', function() {
          page = Math.max(0, Math.min(pageCount - 1, page + parseInt(b.getAttribute('data-dir'), 10)));
          renderPage();
          head.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        });
      });
    }
    renderPage();
    return sec;
  }

  function sevCounts(items) {
    var c = { critical: 0, high: 0, medium: 0 };
    items.forEach(function(it) { if (c[it.severity] != null) c[it.severity]++; });
    var out = '';
    ['critical', 'high', 'medium'].forEach(function(s) {
      if (c[s]) out += '<span class="sev-mini sev-' + s + '">' + c[s] + ' ' + s + '</span>';
    });
    return out;
  }

  function chipHTML(sev) { return '<span class="sev-chip sev-' + gEsc(sev) + '">' + gEsc(sev) + '</span>'; }

  var AP_KIND = { trigger: 'Trigger', workflow: 'Workflow', secret: 'Secret', oidc_role: 'OIDC role', aws_account: 'AWS account', environment: 'Environment', action: 'Action', repo: 'Repo' };

  // renderChain renders a Wiz-style attack path: each hop is an icon node card,
  // connected left→right by arrows. The first node is the entry point, the last
  // is the production target ("crown jewel"), both emphasized.
  function renderChain(steps) {
    steps = steps || [];
    var arrow = '<div class="ap-arrow"><svg width="22" height="12" viewBox="0 0 22 12" fill="none">' +
      '<path d="M0 6h18M13 1l6 5-6 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></div>';
    return steps.map(function(s, i) {
      var isEntry = i === 0, isTarget = i === steps.length - 1;
      var roleTag = isEntry ? ' · entry' : (isTarget ? ' · target' : '');
      var note = s.note ? '<div class="ap-node-note">' + gEsc(s.note) + '</div>' : '';
      return '<div class="ap-node ap-' + gEsc(s.kind) + (isEntry ? ' ap-entry' : '') + (isTarget ? ' ap-target' : '') + '">' +
        '<div class="ap-node-icon">' + iconSvg(s.kind) + '</div>' +
        '<div class="ap-node-body">' +
          '<div class="ap-node-kind">' + gEsc(AP_KIND[s.kind] || s.kind) + roleTag + '</div>' +
          '<div class="ap-node-name">' + gEsc(s.label) + '</div>' + note +
        '</div></div>';
    }).join(arrow);
  }

  function renderPathRow(p) {
    var acct = p.aws_account ? ' <span class="finding-acct">AWS ' + gEsc(p.aws_account) + '</span>' : '';
    var trigger = p.trigger
      ? '<div class="finding-trigger"><span class="ft-label">Potential trigger</span><code>' + gEsc(p.trigger) + '</code> — ' + gEsc(p.trigger_risk || '') + '</div>'
      : '';
    var fixes = (p.fixes && p.fixes.length)
      ? '<div class="finding-actions"><span class="fa-label">Action items to fix</span><ul>' +
          p.fixes.map(function(x) { return '<li>' + gEsc(x) + '</li>'; }).join('') + '</ul></div>'
      : '<div class="finding-fix"><b>Fix:</b> ' + gEsc(p.fix) + '</div>';
    return '<div class="finding-row sev-border-' + gEsc(p.severity) + '" data-node="' + gEsc(p.workflow_id) + '">' +
      '<div class="finding-head">' + chipHTML(p.severity) +
        '<span class="finding-title">' + gEsc(p.repo) + ' / ' + gEsc(p.workflow) + '</span>' + acct + '</div>' +
      '<div class="finding-chain ap-path">' + renderChain(p.steps) + '</div>' +
      trigger +
      '<div class="finding-why"><b>Why:</b> ' + gEsc(p.why) + '</div>' +
      fixes + '</div>';
  }

  function renderActionRow(a) {
    return '<div class="finding-row sev-border-' + gEsc(a.severity) + '" data-node="' + gEsc(a.focus_id) + '">' +
      '<div class="finding-head">' + chipHTML(a.severity) +
        '<span class="finding-title">' + gEsc(a.title) + '</span>' +
        '<span class="kind-tag">' + gEsc((a.kind || '').replace(/_/g, ' ')) + '</span></div>' +
      '<div class="finding-detail">' + gEsc(a.detail) + '</div>' +
      '<div class="finding-fix"><b>Fix:</b> ' + gEsc(a.fix) + '</div></div>';
  }

  // Delegated so it survives pagination re-renders (rows are replaced per page).
  function wireFindingRows(host) {
    host.addEventListener('click', function(e) {
      var row = e.target.closest ? e.target.closest('.finding-row') : null;
      if (!row || !host.contains(row)) return;
      var id = row.getAttribute('data-node');
      if (!id) return;
      focusNode(id);
      var detail = document.querySelector('.graph-main');
      if (detail) detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  // loadGraphAnalytics renders the ranked findings cards above the graph:
  // largest blast radius, paths to production, risky actions, privileged flows.
  function loadGraphAnalytics() {
    var host = document.getElementById('graph-analytics');
    if (!host) return;
    fetchJSON('/api/attack-graph/analytics').then(function(a) {
      if (!a) { host.style.display = 'none'; return; }
      host.style.display = 'grid';
      host.innerHTML = '';
      host.appendChild(rankedCard('💣 Largest blast radius', a.top_secrets || []));
      host.appendChild(pathsCard('☁ Paths to production', a.paths_to_prod || []));
      host.appendChild(rankedCard('🔌 Risky 3rd-party actions', a.risky_actions || []));
      host.appendChild(rankedCard('⚙ Most-privileged workflows', a.privileged_flows || []));
    }).catch(function() { host.style.display = 'none'; });
  }

  function asTags(tags) {
    return (tags || []).map(function(t) { return '<span class="as-tag t-' + gEsc(t) + '">' + gEsc(t) + '</span>'; }).join('');
  }

  function rankedCard(title, rows) {
    var card = document.createElement('div');
    card.className = 'as-card';
    var h = '<div class="as-card-title">' + title + '</div>';
    if (!rows.length) { card.innerHTML = h + '<div class="as-empty">None found</div>'; return card; }
    h += '<div class="as-list">';
    rows.slice(0, 6).forEach(function(r) {
      h += '<div class="as-row" data-node="' + gEsc(r.id) + '">' +
        '<span class="as-dot ' + gEsc(r.risk || 'low') + '"></span>' +
        '<span class="as-label">' + gEsc(r.label) + '</span>' +
        '<span class="as-detail">' + gEsc(r.detail || '') + '</span>' + asTags(r.tags) + '</div>';
    });
    card.innerHTML = h + '</div>';
    wireCardRows(card);
    return card;
  }

  function pathsCard(title, paths) {
    var card = document.createElement('div');
    card.className = 'as-card';
    var h = '<div class="as-card-title">' + title + '</div>';
    if (!paths.length) { card.innerHTML = h + '<div class="as-empty">No paths to a production boundary detected</div>'; return card; }
    h += '<div class="as-list">';
    paths.slice(0, 6).forEach(function(p) {
      h += '<div class="as-row" data-node="' + gEsc(p.workflow_id) + '">' +
        '<span class="as-dot ' + gEsc(p.risk || 'medium') + '"></span>' +
        '<span class="as-label">' + gEsc((p.repo ? p.repo + ' / ' : '') + p.workflow_label) + '</span>' +
        '<span class="as-detail">→ ' + gEsc(p.boundary) + '</span>' + asTags(p.via) + '</div>';
    });
    card.innerHTML = h + '</div>';
    wireCardRows(card);
    return card;
  }

  function wireCardRows(card) {
    card.querySelectorAll('.as-row').forEach(function(row) {
      row.addEventListener('click', function() { focusGraphNode(row.getAttribute('data-node')); });
    });
  }

  // focusGraphNode is the bridge from a ranked finding to the focused subgraph.
  function focusGraphNode(id) { focusNode(id); }

  var graphNodeIndex = [];   // [{id,type,label,risk}] for search
  var currentFocusId = null; // node currently being investigated

  // initAttackSurfaceGraph sets up the focus-first view: ranked findings + a
  // search box, and an EMPTY canvas. Nothing is rendered until the user picks a
  // component — then only that node's blast-radius subgraph is drawn.
  function initAttackSurfaceGraph() {
    if (!report || graphBuilt) return;
    var container = document.getElementById('cy-container');
    if (!container) return;
    graphBuilt = true;

    loadFindings();

    cyInstance = cytoscape({
      container: container,
      elements: [],
      style: getCytoscapeStylesheet(),
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.3
    });
    // Debug handle for support/inspection from the console (read-only graph data
    // already visible on screen).
    window.__attackGraph = cyInstance;

    // Tapping a node in a focused subgraph re-centers the investigation on it.
    // Zone parents are non-interactive (events:'no'), but guard defensively.
    cyInstance.on('tap', 'node', function(evt) {
      if (evt.target.isParent()) return;
      // The toggle chip expands/collapses its group instead of refocusing.
      if (evt.target.data('expander')) { toggleGraphGroup(evt.target.data('type')); return; }
      var id = evt.target.id();
      if (id !== currentFocusId) focusNode(id);
    });

    // Pointer cursor over the toggle chip signals it's clickable (a control).
    cyInstance.on('mouseover', 'node[expander]', function() { if (container) container.style.cursor = 'pointer'; });
    cyInstance.on('mouseout', 'node[expander]', function() { if (container) container.style.cursor = ''; });

    showGraphEmptyState();

    fetchJSON('/api/attack-graph/nodes')
      .then(function(nodes) { graphNodeIndex = nodes || []; })
      .catch(function() {});
  }

  function showGraphEmptyState() {
    var el = document.getElementById('graph-empty');
    if (el) el.style.display = 'flex';
  }

  // focusNode fetches the blast radius for a node and renders only that
  // self-contained subgraph, replacing whatever was on the canvas.
  function focusNode(id) {
    if (!id) return;
    currentFocusId = id;
    var empty = document.getElementById('graph-empty');
    if (empty) empty.style.display = 'none';

    fetchJSON('/api/blast-radius?id=' + encodeURIComponent(id)).then(function(res) {
      if (!res || !res.subgraph) return;
      renderSubgraph(res.subgraph, id);

      var oType = res.origin.type === 'all_repos' ? 'allrepos' : res.origin.type;
      var meta = GRAPH_TYPE_META[oType] || { icon: '🎯' };
      var crumb = document.getElementById('graph-focus-crumb');
      if (crumb) { crumb.style.display = ''; crumb.innerHTML = (meta.icon || '🎯') + ' <strong>' + gEsc(res.origin.label) + '</strong> <span class="crumb-type">' + gEsc(oType) + '</span>'; }
      var clr = document.getElementById('graph-clear-btn');
      if (clr) clr.style.display = '';

      showBackendBlastPanel({ type: oType, label: res.origin.label }, res);
    }).catch(function() {});
  }

  // renderSubgraph draws a standalone subgraph with a tidy left→right tiered
  // Edge types that represent an active step toward the target — these get the
  // animated "flow" treatment in the focused subgraph (skip structural "includes").
  var FLOW_EDGE_TYPES = { assumes_role: 1, in_account: 1, references_secret: 1, can_hijack: 1, deploys_to_env: 1, controls: 1, can_modify: 1, exposes_secret: 1, can_trigger: 1, has_access: 1 };

  var edgeFlowRAF = null;
  // startEdgeFlow animates line-dash-offset on the flow/highlighted edges so the
  // attack path visibly "streams" toward the crown jewel (Wiz-style). Guarded to
  // stay cheap: skips large graphs and stops when the tab isn't visible.
  function startEdgeFlow() {
    stopEdgeFlow();
    if (!cyInstance) return;
    var edges = cyInstance.edges('.flow, .highlighted');
    if (!edges || edges.length === 0 || edges.length > 200) return;
    var offset = 0;
    var step = function() {
      var tab = document.getElementById('tab-attack-surface');
      if (!cyInstance || !tab || !tab.classList.contains('active')) { edgeFlowRAF = null; return; }
      offset -= 0.9;
      edges.style('line-dash-offset', offset);
      edgeFlowRAF = requestAnimationFrame(step);
    };
    edgeFlowRAF = requestAnimationFrame(step);
  }
  function stopEdgeFlow() {
    if (edgeFlowRAF) { cancelAnimationFrame(edgeFlowRAF); edgeFlowRAF = null; }
  }

  // ── Domain zones ──────────────────────────────────────────────────
  // Separate what lives inside GitHub from the external cloud/AWS side. The OIDC
  // role + AWS account are the "outside GitHub" set; everything else is GitHub.
  // Zones are rendered as real Cytoscape compound parents in renderSubgraph
  // (true containment), so this set only decides each node's parent zone.
  var CLOUD_TYPES = { oidc_role: 1, aws_account: 1 };

  // Collapsible node types: when a focused subgraph fans out into many peers of
  // these types, only the first few are shown and the rest are folded behind a
  // clickable toggle chip, so dense fan-outs stay readable. The chip stays in
  // both states — "+N more" when collapsed, "collapse" when expanded — so the
  // toggle is reversible: tapping again restores the original collapsed state.
  var COLLAPSE_TYPES = { app: 'GitHub Apps', action: 'Actions' };
  var COLLAPSE_LIMIT = 2;
  var graphSg = null, graphOriginId = null, graphExpanded = {};

  function graphRiskRank(r) { return ({ high: 3, medium: 2, low: 1, none: 0 })[r] || 0; }

  // ── Entry-points spotlight ────────────────────────────────────────────────
  // Classify a node as an attacker entry point by supply-chain class, or null if
  // it isn't a front door. Triggers that an attacker can reach/initiate count as
  // a trigger entry; broad credentials as identity; mutable/3rd-party actions as
  // a dependency (supply-chain) entry.
  var entryMode = false;
  var ENTRY_TRIGGERS = { workflow_dispatch: 1, pull_request: 1, pull_request_target: 1, issue_comment: 1, repository_dispatch: 1, workflow_call: 1 };
  function entryClassFor(n) {
    var t = n.type, m = n.meta || {};
    if (t === 'action') return m.pinned === false ? 'supplychain' : null; // mutable tag = hijackable
    if (t === 'app' || t === 'pat' || t === 'deploy_key' || t === 'sso') return 'identity';
    if (t === 'workflow') {
      var trg = m.triggers || [];
      for (var i = 0; i < trg.length; i++) if (ENTRY_TRIGGERS[trg[i]]) return 'trigger';
    }
    return null;
  }

  // applyEntryMode toggles the spotlight on the currently-drawn graph: entries get
  // a class-colored ring (via em-* classes on the precomputed data.entryClass),
  // everything else dims. Re-applied after every (re)draw so it survives focus,
  // expand/collapse, etc.
  function applyEntryMode() {
    if (!cyInstance) return;
    cyInstance.batch(function() {
      cyInstance.elements().removeClass('em-supplychain em-identity em-trigger entry-dim');
      if (!entryMode) return;
      cyInstance.nodes().forEach(function(n) {
        if (n.isParent() || n.data('expander')) return;
        var ec = n.data('entryClass');
        if (ec) n.addClass('em-' + ec); else n.addClass('entry-dim');
      });
      cyInstance.edges().addClass('entry-dim');
    });
  }

  // renderSubgraph stores the subgraph and draws it fresh with every collapsible
  // group collapsed. drawSubgraph does the actual element build + layout so a
  // toggle interaction can re-render the same subgraph with new expansion state.
  function renderSubgraph(sg, originId) {
    graphSg = sg; graphOriginId = originId; graphExpanded = {};
    drawSubgraph();
  }

  // toggleGraphGroup flips a collapsible type between expanded and collapsed
  // (tapping its chip) and redraws — clicking again returns to the prior state.
  function toggleGraphGroup(type) {
    graphExpanded[type] = !graphExpanded[type];
    drawSubgraph();
  }

  // (dagre) layout — far more legible than the full force-directed graph.
  function drawSubgraph() {
    if (!cyInstance || !graphSg) return;
    var sg = graphSg, originId = graphOriginId;
    var rawNodes = sg.nodes || [];
    var rawEdges = sg.edges || [];

    var typeById = {};
    rawNodes.forEach(function(n) { typeById[n.id] = n.type; });

    // Per collapsible type with enough peers, record a toggle group. Keep the
    // highest-risk few visible; when collapsed, hide the rest behind the chip.
    // The group (and its chip) exists in BOTH states so the toggle is reversible.
    var hidden = {};      // nodeId -> true (collapsed-away)
    var groups = [];      // { type, hiddenCount, expanded, memberIds }
    Object.keys(COLLAPSE_TYPES).forEach(function(type) {
      var ofType = rawNodes.filter(function(n) { return n.type === type && n.id !== originId; });
      if (ofType.length <= COLLAPSE_LIMIT) return;
      var sorted = ofType.slice().sort(function(a, b) { return graphRiskRank(b.risk) - graphRiskRank(a.risk); });
      var expanded = !!graphExpanded[type];
      if (!expanded) sorted.slice(COLLAPSE_LIMIT).forEach(function(n) { hidden[n.id] = true; });
      groups.push({
        type: type, hiddenCount: sorted.length - COLLAPSE_LIMIT, expanded: expanded,
        memberIds: sorted.map(function(n) { return n.id; })
      });
    });

    // Each node is a child of its domain zone (compound parent): GitHub vs the
    // external Cloud/Production (AWS) side. Real containment — not a coordinate
    // overlay — so secrets and other GitHub-side nodes can't render inside the
    // cloud box just because the layout placed them in the same column.
    var zoneSeen = {};
    var nodes = [];
    rawNodes.forEach(function(n) {
      if (hidden[n.id]) return;
      var type = n.type === 'all_repos' ? 'allrepos' : n.type;
      var entity = n.meta || {};
      if (type === 'allrepos') entity = { total: (n.meta && n.meta.total) || 0 };
      var zone = CLOUD_TYPES[type] ? 'zone:cloud' : 'zone:github';
      zoneSeen[zone] = true;
      var data = { id: n.id, parent: zone, type: type, label: n.label, name: n.label, label2: nodeLabel2(type, n.label), icon: iconDataUri(type), entity: entity, risk: n.risk || 'none' };
      // Apps / PAT owners / org carry a real GitHub avatar URL — show the actual
      // logo instead of the octicon glyph. Read from n.meta (not entity, which is
      // rebuilt for allrepos and would drop it). Only set when present, so the
      // node[avatar] selector doesn't match (and blank) glyph-only nodes.
      var avatarUrl = n.meta && n.meta.avatar;
      if (avatarUrl) data.avatar = avatarUrl;
      // Precompute the entry-point class so the spotlight toggle is instant.
      var ec = entryClassFor(n);
      if (ec) data.entryClass = ec;
      // Long-lived high-criticality secrets are crown jewels (a SaaS/infra
      // boundary), not just generic secrets — mark + label them as such.
      if (type === 'secret' && n.meta && n.meta.boundary) {
        data.boundary = 1;
        data.label2 = '👑 ' + n.label + '\n' + (n.meta.provider || 'Secret');
      }
      nodes.push({ data: data });
    });

    // One toggle chip per group, in the same zone. Label reflects the current
    // state so the same node both expands and collapses.
    groups.forEach(function(g) {
      var zone = CLOUD_TYPES[g.type] ? 'zone:cloud' : 'zone:github';
      zoneSeen[zone] = true;
      var noun = COLLAPSE_TYPES[g.type];
      var label2 = g.expanded
        ? 'Show less\n' + noun
        : 'Show ' + g.hiddenCount + ' more\n' + noun;
      nodes.push({ data: {
        id: 'expander:' + g.type, parent: zone, type: g.type, expander: true,
        expanded: g.expanded ? 1 : 0, label2: label2,
        icon: chipIconDataUri(g.expanded), risk: 'none'
      } });
    });

    var nodeCount = nodes.length;
    // Prepend only the zone parents that actually have children (a parent must
    // be added before its children, and an empty zone shouldn't draw a box).
    var parents = [];
    if (zoneSeen['zone:github']) parents.push({ data: { id: 'zone:github', zone: 'github', label: 'GitHub' } });
    if (zoneSeen['zone:cloud'])  parents.push({ data: { id: 'zone:cloud',  zone: 'cloud',  label: 'Cloud · Production (AWS)' } });
    nodes = parents.concat(nodes);

    // Build edges; reroute any edge touching a hidden node to that type's chip,
    // de-duplicating so the collapsed group keeps its connections.
    var edges = [];
    var edgeSeen = {};
    function pushEdge(s, t, etype) {
      if (s === t) return;
      var key = s + '|' + t + '|' + etype;
      if (edgeSeen[key]) return;
      edgeSeen[key] = true;
      edges.push({ data: { id: key, source: s, target: t, edgeType: etype, label: EDGE_LABELS[etype] || etype } });
    }
    rawEdges.forEach(function(e) {
      var s = hidden[e.source] ? 'expander:' + typeById[e.source] : e.source;
      var t = hidden[e.target] ? 'expander:' + typeById[e.target] : e.target;
      pushEdge(s, t, e.type);
    });
    // An expanded group hides nothing, so its chip has no rerouted edges — wire it
    // to the group's neighbors so the "collapse" chip sits with its members.
    groups.forEach(function(g) {
      if (!g.expanded) return;
      var member = {};
      g.memberIds.forEach(function(id) { member[id] = true; });
      rawEdges.forEach(function(e) {
        if (member[e.source]) pushEdge('expander:' + g.type, e.target, e.type);
        else if (member[e.target]) pushEdge(e.source, 'expander:' + g.type, e.type);
      });
    });

    cyInstance.elements().remove();
    cyInstance.add({ nodes: nodes, edges: edges });
    // The container may have been hidden (inactive tab) or resized since the cy
    // instance was created, leaving cytoscape with a stale size — so fit would
    // mis-scale and the graph renders tiny/off-screen. Recompute size first.
    cyInstance.resize();
    var layout = cyInstance.layout({ name: 'dagre', rankDir: 'LR', nodeSep: 48, rankSep: 130, edgeSep: 24, fit: true, padding: 60, animate: true, animationDuration: 350, animationEasing: 'ease-out' });
    layout.one('layoutstop', function() {
      cyInstance.resize();
      separateZones();
      cyInstance.fit(undefined, 50);
      // Don't let a wide path shrink into unreadability — keep a sensible minimum
      // zoom and center on the entry point; the user pans from there.
      if (cyInstance.zoom() < 0.55) {
        cyInstance.zoom(0.7);
        var s = cyInstance.getElementById(originId);
        if (s && s.length) cyInstance.center(s);
      }
    });
    layout.run();

    cyInstance.batch(function() {
      cyInstance.elements().removeClass('dimmed highlighted blast-source flow');
      // Tag the high-signal relationship edges so they animate toward the target.
      cyInstance.edges().forEach(function(e) {
        if (FLOW_EDGE_TYPES[e.data('edgeType')]) e.addClass('flow');
      });
      var src = cyInstance.getElementById(originId);
      if (src) src.addClass('blast-source');
    });
    startEdgeFlow();
    applyEntryMode(); // re-apply the spotlight if it's currently on

    var statsEl = document.getElementById('graph-stats');
    if (statsEl) {
      var note = nodeCount > 180 ? ' · large blast radius — see summary panel' : '';
      statsEl.textContent = nodeCount + ' nodes, ' + edges.length + ' edges' + note;
    }
  }

  // separateZones pushes the Cloud cluster clear of the GitHub cluster after
  // layout. cytoscape-dagre lays out only leaf nodes and draws zone parents
  // around them afterward — dagre never sees the clusters, so the two zone boxes
  // can overlap in the shared column (a secret and an OIDC role sit at the same
  // depth). Shifting the cloud leaves right guarantees their bounding boxes — and
  // therefore the drawn zone rectangles — never overlap, so a GitHub-side node
  // can't render inside the red Cloud box. No-op when already separated.
  function separateZones() {
    if (!cyInstance) return;
    var leaves = cyInstance.nodes().filter(function(n) { return !n.isParent(); });
    var gh = leaves.filter(function(n) { return n.data('parent') === 'zone:github'; });
    var cl = leaves.filter(function(n) { return n.data('parent') === 'zone:cloud'; });
    if (!gh.length || !cl.length) return;
    var gap = 130; // ≈ rankSep, plus room for the two boxes' padding
    var delta = (gh.boundingBox().x2 + gap) - cl.boundingBox().x1;
    if (delta <= 0) return; // dagre already left a gap; nothing to do
    cl.positions(function(ele) {
      var p = ele.position();
      return { x: p.x + delta, y: p.y };
    });
  }

  function clearGraphFocus() {
    currentFocusId = null;
    stopEdgeFlow();
    setEntryMode(false); // reset the spotlight when leaving the graph
    if (cyInstance) cyInstance.elements().remove();
    var empty = document.getElementById('graph-empty'); if (empty) empty.style.display = 'flex';
    var crumb = document.getElementById('graph-focus-crumb'); if (crumb) crumb.style.display = 'none';
    var clr = document.getElementById('graph-clear-btn'); if (clr) clr.style.display = 'none';
    var statsEl = document.getElementById('graph-stats'); if (statsEl) statsEl.textContent = '';
    closeGraphInfoPanel();
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

  // showBlastRadius queries the backend for the direction-aware reachable set
  // (downstream = what a compromise reaches; upstream = what depends on it, e.g.
  // workflows that break if a secret is rotated) and highlights it.
  function showBlastRadius(sourceNode) {
    if (!cyInstance) return;
    var id = sourceNode.id();
    fetchJSON('/api/blast-radius?id=' + encodeURIComponent(id)).then(function(res) {
      if (!res) return;
      var nodeIds = {}; nodeIds[id] = true;
      var edgeIds = {};
      ['downstream', 'upstream'].forEach(function(dir) {
        var r = res[dir] || {};
        (r.nodes || []).forEach(function(n) { nodeIds[n.id] = true; });
        (r.edge_ids || []).forEach(function(e) { edgeIds[e] = true; });
      });

      var reachable = cyInstance.collection();
      Object.keys(nodeIds).forEach(function(nid) { reachable = reachable.merge(cyInstance.getElementById(nid)); });
      var reachableEdges = cyInstance.collection();
      Object.keys(edgeIds).forEach(function(eid) { reachableEdges = reachableEdges.merge(cyInstance.getElementById(eid)); });

      cyInstance.batch(function() {
        cyInstance.elements().addClass('dimmed').removeClass('highlighted blast-source');
        reachable.removeClass('dimmed').addClass('highlighted');
        reachableEdges.removeClass('dimmed').addClass('highlighted');
        sourceNode.removeClass('highlighted').addClass('blast-source');
      });
      startEdgeFlow();

      showBackendBlastPanel(sourceNode.data(), res);
    }).catch(function() {});
  }

  // showBackendBlastPanel renders the blast-radius summary from the backend
  // result: headline stats plus the reachable secrets and OIDC roles.
  function showBackendBlastPanel(sourceData, res) {
    var panel = document.getElementById('graph-info-panel');
    var titleEl = document.getElementById('gip-title');
    var bodyEl = document.getElementById('gip-body');
    var meta = GRAPH_TYPE_META[sourceData.type] || { icon: '💥' };

    titleEl.innerHTML = (meta.icon || '💥') + ' Blast Radius';
    bodyEl.innerHTML = '';

    var header = document.createElement('div');
    header.className = 'gip-entity-header';
    header.innerHTML = '<div class="gip-entity-type">Source: <code>' + sourceData.label + '</code></div>' +
      '<div class="gip-entity-meta">' + (meta.label || sourceData.type) + '</div>';
    bodyEl.appendChild(header);

    // Summary stat grid from backend (labels are origin-type aware).
    var summary = document.createElement('div');
    summary.className = 'blast-summary';
    (res.summary || []).forEach(function(item) {
      var stat = document.createElement('div');
      stat.className = 'blast-stat';
      stat.innerHTML = '<div class="blast-stat-value">' + item.value + '</div>' +
        '<div class="blast-stat-label">' + item.label + '</div>';
      summary.appendChild(stat);
    });
    bodyEl.appendChild(summary);

    // Collect reachable secrets / OIDC roles / workflows across both directions.
    var names = { secret: [], oidc_role: [], workflow: [] };
    ['downstream', 'upstream'].forEach(function(dir) {
      ((res[dir] || {}).nodes || []).forEach(function(n) {
        if (names[n.type]) names[n.type].push(n.label);
      });
    });
    function dedupe(a) { return a.filter(function(v, i) { return a.indexOf(v) === i; }); }

    function listSection(label, arr, klass) {
      arr = dedupe(arr);
      if (!arr.length) return;
      var div = document.createElement('div');
      div.className = 'gip-why-section';
      div.innerHTML = '<span class="gip-why-label">' + label + ':</span> <code>' +
        arr.slice(0, 8).join('</code>, <code>') + '</code>' +
        (arr.length > 8 ? ' +' + (arr.length - 8) + ' more' : '');
      bodyEl.appendChild(div);
    }

    if (sourceData.type === 'secret') {
      listSection('Workflows that break if rotated', names.workflow, 'wf');
    } else {
      listSection('Secrets reachable', names.secret, 'sec');
      listSection('OIDC roles reachable', names.oidc_role, 'role');
    }

    panel.style.display = 'flex';
  }

  var GRAPH_TYPE_META = {
    secret:     { label: 'Secret',            color: '#DC2626', icon: '🔒' },
    allrepos:   { label: 'All Repositories',  color: '#2563EB', icon: '🗄' },
    repo:       { label: 'Repository',        color: '#2563EB', icon: '📦' },
    workflow:   { label: 'Workflow',           color: '#16A34A', icon: '⚙' },
    action:     { label: 'Action (3rd-party)', color: '#7C3AED', icon: '🔌' },
    oidc_role:  { label: 'OIDC role (boundary)', color: '#DC2626', icon: '☁' },
    aws_account:{ label: 'AWS account (target)', color: '#991B1B', icon: '☁' },
    environment:{ label: 'Environment',       color: '#10B981', icon: '🚀' },
    pat:        { label: 'Personal Access Token', color: '#F97316', icon: '🔑' },
    app:        { label: 'GitHub App',             color: '#F97316', icon: '🤖' },
    sso:        { label: 'SSO credential',         color: '#EC4899', icon: '👤' },
    deploy_key: { label: 'Deploy Key',        color: '#D97706', icon: '🗝' }
  };

  function buildGraphLegend() {
    var seen = {};
    var html = '';
    var order = ['secret', 'repo', 'workflow', 'action', 'oidc_role', 'environment', 'sso', 'pat', 'deploy_key'];
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
      var uses = entity.uses || 1;
      var warn = document.createElement('div');
      warn.className = 'gip-why-section';
      if (entity.pinned) {
        warn.innerHTML = '<span class="gip-why-label">Pinned:</span> <code>' + d.label + '</code> is referenced by SHA in ' + uses + ' workflow' + (uses === 1 ? '' : 's') + '. Switch to Blast Radius mode to see what it can reach if the upstream repo is compromised.';
      } else {
        warn.innerHTML = '<span class="gip-why-label">Why high:</span> Unpinned action <code>' + d.label + '</code> is used by ' + uses + ' workflow' + (uses === 1 ? '' : 's') + ' and can be hijacked by overwriting its tag — injecting code into every build that uses it.';
        var fix = document.createElement('div');
        fix.className = 'gip-fix-section';
        fix.innerHTML = '<span class="gip-fix-label">Fix:</span> Pin to a full commit SHA instead of a tag reference.';
        bodyEl.appendChild(warn);
        bodyEl.appendChild(fix);
      }
      if (entity.pinned) bodyEl.appendChild(warn);
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

  // --- Graph Toolbar Handlers (focus-first) ---

  (function setupGraphSearch() {
    var input = document.getElementById('graph-search-input');
    var results = document.getElementById('graph-search-results');
    if (!input || !results) return;

    function render(q) {
      var matches = graphNodeIndex.filter(function(n) {
        return n.label && n.label.toLowerCase().indexOf(q) >= 0;
      });
      // High-risk first, then alphabetical; cap the dropdown.
      var rw = { high: 3, medium: 2, low: 1, none: 0 };
      matches.sort(function(a, b) {
        var d = (rw[b.risk] || 0) - (rw[a.risk] || 0);
        return d !== 0 ? d : a.label.localeCompare(b.label);
      });
      matches = matches.slice(0, 12);
      if (!matches.length) { results.innerHTML = '<div class="gsr-empty">No matches</div>'; results.style.display = 'block'; return; }
      results.innerHTML = matches.map(function(n) {
        return '<div class="gsr-row" data-id="' + gEsc(n.id) + '">' +
          '<span class="as-dot ' + gEsc(n.risk || 'low') + '"></span>' +
          '<span class="gsr-type">' + gEsc(n.type) + '</span>' +
          '<span class="gsr-label">' + gEsc(n.label) + '</span></div>';
      }).join('');
      results.style.display = 'block';
      results.querySelectorAll('.gsr-row').forEach(function(row) {
        row.addEventListener('mousedown', function(ev) {
          ev.preventDefault();
          input.value = ''; results.style.display = 'none';
          focusNode(row.getAttribute('data-id'));
        });
      });
    }

    input.addEventListener('input', function() {
      var q = input.value.trim().toLowerCase();
      if (!q) { results.style.display = 'none'; results.innerHTML = ''; return; }
      render(q);
    });
    input.addEventListener('focus', function() {
      var q = input.value.trim().toLowerCase();
      if (q) render(q);
    });
    input.addEventListener('blur', function() {
      setTimeout(function() { results.style.display = 'none'; }, 150);
    });
  })();

  document.getElementById('graph-fit-btn').addEventListener('click', function() {
    if (cyInstance && cyInstance.elements().length) cyInstance.fit(undefined, 40);
  });

  // Entry-points spotlight toggle.
  function setEntryMode(on) {
    entryMode = on;
    var btn = document.getElementById('graph-entry-btn');
    if (btn) btn.classList.toggle('active', on);
    var legend = document.getElementById('graph-entry-legend');
    if (legend) legend.style.display = on ? 'flex' : 'none';
    applyEntryMode();
  }
  document.getElementById('graph-entry-btn').addEventListener('click', function() {
    setEntryMode(!entryMode);
  });

  document.getElementById('graph-clear-btn').addEventListener('click', function() {
    clearGraphFocus();
  });

  document.getElementById('gip-close').addEventListener('click', function() {
    closeGraphInfoPanel();
  });

  (function() {
    var back = document.getElementById('workflow-detail-back');
    if (back) back.addEventListener('click', showWorkflowListView);
    var aback = document.getElementById('actions-inv-detail-back');
    if (aback) aback.addEventListener('click', showActionListView);
    var mback = document.getElementById('metric-drill-back');
    if (mback) mback.addEventListener('click', closeMetricDrill);
    var iback = document.getElementById('item-detail-back');
    if (iback) iback.addEventListener('click', closeItemDetail);
  })();

  // Clicking a stat box drills into a table of exactly those items (15/page).
  document.addEventListener('click', function(e) {
    var box = e.target.closest && e.target.closest('.zsum-box[data-drill]');
    if (box) openMetricDrill(box.getAttribute('data-drill'));
  });

  // Overview: clicking a top-exposure row opens the Attack Surface tab focused on
  // that workflow; the "view attack surface" link just switches tabs.
  document.addEventListener('click', function(e) {
    if (!e.target.closest) return;
    var ex = e.target.closest('.exposure-row[data-wfid]');
    if (ex) { navTo('tab-attack-surface'); focusNode(ex.getAttribute('data-wfid')); return; }
    var sa = e.target.closest('.ov-seeall[data-tab]');
    if (sa) navTo(sa.getAttribute('data-tab'));
  });

  // Clicking a GitHub deep-link opens github.com in a new tab without also
  // triggering the row's expand/navigate handler.
  document.addEventListener('click', function(e) {
    if (e.target.closest && e.target.closest('a.gh-link')) e.stopPropagation();
  }, true);

  // --- Init ---
  loadAll();

})();
