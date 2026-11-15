/* MIFARE Classic Dump Parser — UI */
(() => {
  'use strict';
  const M = window.Mifare;
  const H = M.hex2;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const sp = (cls, txt, title) => `<span class="c-${cls}"${title ? ` title="${esc(title)}"` : ''}>${esc(txt)}</span>`;
  const pcls = (p) => 'p-' + (p === 'A|B' ? 'AB' : p);
  const spaced = (hex) => (hex || '').match(/../g)?.join(' ') || '';

  const state = { parser: null, cmp: { A: null, B: null } };

  /* ═══════════════════ tabs ═══════════════════ */
  function switchTab(t) {
    if (!$('#tab-' + t)) t = 'parser';
    $$('.tab[data-tab]').forEach((x) => x.classList.toggle('active', x.dataset.tab === t));
    $$('.tabpane').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + t));
    history.replaceState(null, '', '#' + t);
  }
  $$('.tab[data-tab]').forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
  switchTab((location.hash || '#parser').slice(1).split('/')[0]);

  /* repo link: points at the GitHub repo when served from GitHub Pages */
  (() => {
    const m = location.hostname.match(/^([^.]+)\.github\.io$/i);
    const repo = location.pathname.split('/').filter(Boolean)[0];
    if (m && repo) $('#repo-link').href = `https://github.com/${m[1]}/${repo}`;
  })();

  /* ═══════════════════ file loading ═══════════════════ */
  function readFile(file) {
    return file.arrayBuffer().then((buf) => ({ name: file.name, bytes: new Uint8Array(buf) }));
  }
  function fetchSample(path) {
    return fetch(path).then((r) => {
      if (!r.ok) throw new Error(`could not load ${path}`);
      return r.arrayBuffer();
    }).then((buf) => ({ name: path.split('/').pop(), bytes: new Uint8Array(buf) }));
  }
  function setupDrop(zone, onFile) {
    const input = $('input[type=file]', zone);
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => { if (input.files[0]) readFile(input.files[0]).then(onFile); input.value = ''; });
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('over'));
    zone.addEventListener('drop', (e) => {
      e.preventDefault(); zone.classList.remove('over');
      const f = e.dataTransfer.files[0];
      if (f) readFile(f).then(onFile);
    });
  }
  function parse(file, uidLen = 0) {
    const d = M.loadDump(file.bytes);
    return { d, res: M.analyse(d, uidLen), name: file.name, file };
  }
  function download(name, text, type = 'application/octet-stream') {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* ═══════════════════ shared rendering ═══════════════════ */

  /** Per-byte {cls, f(field), title} for a block. */
  function byteFields(info, man) {
    const out = [];
    const F = (cls, f, title) => out.push({ cls, f, title });
    const b = info.block;
    switch (info.type) {
      case 'manufacturer':
        if (man && man.uidLen === 4) {
          for (let i = 0; i < 4; i++) F('uid', 'uid', `UID byte ${i}`);
          F(man.bccOk ? 'bcc' : 'bad', 'bcc', man.bccOk ? 'BCC — XOR of UID bytes (valid)' : `BCC — invalid, expected ${H(man.bccCalc)}`);
          F('sak', 'sak', 'SAK');
          F('atqa', 'atqa', 'ATQA (LSB)'); F('atqa', 'atqa', 'ATQA (MSB)');
          for (let i = 0; i < 8; i++) F('mfr', 'mfr', 'Manufacturer data');
        } else {
          for (let i = 0; i < 7; i++) F('uid', 'uid', `UID byte ${i}`);
          for (let i = 0; i < 9; i++) F('mfr', 'mfr', 'Manufacturer data');
        }
        break;
      case 'trailer':
        for (let i = 0; i < 6; i++) F('keya', 'keya', `Key A byte ${i}`);
        for (let i = 0; i < 3; i++) F(info.accValid === false ? 'bad' : 'acc', 'acc', `Access bits (byte ${6 + i})`);
        F('gpb', 'gpb', 'GPB / user byte (byte 9)');
        for (let i = 0; i < 6; i++) F('keyb', 'keyb', `Key B byte ${i}`);
        break;
      case 'value':
        for (let i = 0; i < 4; i++) F('value', 'v1', `Value (LE) = ${info.value}`);
        for (let i = 0; i < 4; i++) F('valinv', 'vi', 'Inverted value');
        for (let i = 0; i < 4; i++) F('value', 'v2', 'Value copy');
        F('addr', 'ad', `Address ${H(info.addr)}`); F('valinv', 'ai', 'Inverted address');
        F('addr', 'ad', 'Address copy'); F('valinv', 'ai', 'Inverted address copy');
        break;
      case 'mad': {
        const start = b === 1 ? 2 : (b === 64 ? 2 : 0);
        const base = { 1: 1, 2: 8, 64: 17, 65: 24, 66: 32 }[b];
        for (let j = 0; j < 16; j++) {
          if (j < start) F(j === 0 ? 'crc' : 'madinfo', j === 0 ? 'crc' : 'info', j === 0 ? 'MAD CRC-8' : 'MAD info byte');
          else { const s = base + Math.floor((j - start) / 2); F('aid', 'aid' + s, `AID for sector ${s}`); }
        }
        break;
      }
      case 'empty': for (let i = 0; i < 16; i++) F('empty', '', ''); break;
      default: for (let i = 0; i < 16; i++) F('data', '', '');
    }
    return out;
  }

  function blockTag(info, compact) {
    switch (info.type) {
      case 'manufacturer': return sp('uid', compact ? 'mfr' : 'manufacturer');
      case 'trailer': return sp('acc', compact ? 'trailer' : 'sector trailer');
      case 'value': return compact ? `${sp('value', 'val ')}${sp('head', info.value)}`
        : `${sp('value', 'value ')}${sp('head', info.value)}${sp('addr', '  addr ' + H(info.addr))}`;
      case 'mad': return sp('madinfo', 'MAD');
      case 'empty': return sp('dim', 'empty');
      case 'unknown': return sp('unknown', 'not read');
      default: return sp('dim', 'data');
    }
  }

  /** One hexdump row. diffMask: bool[16] | null, other: Uint8Array for titles */
  function hexRow(d, info, man, opt = {}) {
    const blk = d.block(info.block), kn = d.bknown(info.block);
    const fields = byteFields(info, man);
    let bytes = '';
    for (let i = 0; i < 16; i++) {
      const f = fields[i];
      const diff = opt.diff && opt.diff[i];
      let title = f.title;
      if (diff && opt.other) title = `${title ? title + ' · ' : ''}${opt.side === 'A' ? 'B' : 'A'} has ${opt.otherKnown[i] ? H(opt.other[i]) : '--'}`;
      const cls = (kn[i] ? 'c-' + f.cls : 'c-unknown') + (diff ? ' diff' : '');
      bytes += `<span class="${cls}"${f.f ? ` data-f="${f.f}"` : ''}${title ? ` title="${esc(title)}"` : ''}>${kn[i] ? H(blk[i]) : '--'}</span>`;
    }
    let ascii = '';
    if (opt.ascii) {
      for (let i = 0; i < 16; i++) {
        const x = blk[i];
        ascii += !kn[i] ? ' ' : (x >= 0x20 && x < 0x7f ? esc(String.fromCharCode(x)) : '<span class="np">.</span>');
      }
    }
    const grp = info.group === 3 ? 'T' : info.group;
    return `<div class="row${opt.changed ? ' changed' : ''}"><span class="bn">${info.block}</span><span class="grp">${grp}</span>` +
      `<span class="bar">│</span><span class="bytes">${bytes}</span>` +
      (opt.ascii ? `<span class="bar">│</span><span class="ascii">${ascii}</span>` : '') +
      `<span class="bar">│</span><span class="tag">${blockTag(info, opt.compact)}</span></div>`;
  }

  function aclTables(conds, valid, kbr, first, n) {
    let html = '';
    if (!valid) html += `<div class="footnote" style="color:var(--err)">Inverted copies don't match — table decoded from the non-inverted bits only.</div>`;
    html += `<div class="bits">C1C2C3&nbsp; ${conds.map((c, g) => `g${g}:<b>${c}</b>`).join('')} <span class="c-dim">(g3 = trailer)</span></div>`;
    html += '<div class="tablewrap"><table class="acltable"><thead><tr><th>Blocks</th><th>C1 C2 C3</th><th>Read</th><th>Write</th><th>Increment</th><th>Dec / Tfr / Rst</th><th>Meaning</th></tr></thead><tbody>';
    let anyEff = false;
    for (let g = 0; g < 3; g++) {
      const label = n === 4 ? `${first + g}` : `${first + g * 5}–${first + g * 5 + 4}`;
      const row = M.DATA_ACL[conds[g]];
      html += `<tr><td class="c-muted">${label}</td><td class="cbits">${conds[g].split('').join(' ')}</td>`;
      for (const p of row.slice(0, 4)) {
        const [e, ch] = M.effective(p, kbr);
        anyEff = anyEff || ch;
        html += `<td class="${pcls(e)}"${ch ? ` title="${esc(p)} on paper — Key B is readable so it can't authenticate"` : ''}>${e}${ch ? '*' : ''}</td>`;
      }
      html += `<td class="meaning">${esc(row[4])}</td></tr>`;
    }
    html += '</tbody></table></div>';
    const t = M.TRAILER_ACL[conds[3]];
    html += '<div class="tablewrap"><table class="acltable" style="margin-top:10px"><thead><tr><th>Trailer</th><th>C1 C2 C3</th><th>Key A read</th><th>Key A write</th><th>ACL read</th><th>ACL write</th><th>Key B read</th><th>Key B write</th><th>Meaning</th></tr></thead><tbody>';
    html += `<tr><td class="c-muted">${first + n - 1}</td><td class="cbits">${conds[3].split('').join(' ')}</td>` +
      t.slice(0, 6).map((p) => `<td class="${pcls(p)}">${p}</td>`).join('') + `<td class="meaning">${esc(t[6])}</td></tr>`;
    html += '</tbody></table></div>';
    if (anyEff) html += '<div class="footnote">* Key B is readable in this sector, so the card refuses it for authentication — effective right shown.</div>';
    return html;
  }

  function keyLine(label, key, cls, sec) {
    const which = label.slice(-1);
    if (!key) return `<span class="k">${label}</span><span>${sp('unknown', '------------')}<span class="note c-dim">not in dump</span></span>`;
    let notes = '';
    if (key === '000000000000' && which === 'A') notes += '<span class="note c-warn">possibly masked — cards never return Key A; the dump tool may not have filled it in</span>';
    else if (key === '000000000000' && which === 'B' && !sec.keybReadable) notes += '<span class="note c-warn">possibly masked — Key B isn\'t readable under these access bits</span>';
    else if (M.KNOWN_KEYS[key]) notes += `<span class="note c-warn">⚠ ${esc(M.KNOWN_KEYS[key])}</span>`;
    if (which === 'B' && sec.keybReadable) notes += '<span class="note c-warn">readable → used as data, not usable for auth</span>';
    return `<span class="k">${label}</span><span>${sp(cls, key)}${notes}</span>`;
  }

  function sectorBadges(sec) {
    const b = [];
    if (sec.accessValid === false) b.push('<span class="badge b-err">INVALID ACL</span>');
    if ([sec.keyA, sec.keyB].some((k) => k && M.KNOWN_KEYS[k] && k !== '000000000000')) b.push('<span class="badge b-warn">default key</span>');
    if (sec.keybReadable) b.push('<span class="badge b-dim">Key B readable</span>');
    const vals = sec.blockInfo.filter((x) => x.type === 'value').length;
    if (vals) b.push(`<span class="badge b-value">${vals} value</span>`);
    if (sec.blockInfo.some((x) => x.type === 'mad')) b.push('<span class="badge b-mad">MAD</span>');
    if (isUntouched(sec)) b.push('<span class="badge b-dim">blank</span>');
    return b.join('');
  }

  function isUntouched(sec) {
    return sec.accessBytes === 'FF0780' && sec.keyA === 'FFFFFFFFFFFF' && sec.keyB === 'FFFFFFFFFFFF' &&
      sec.blockInfo.every((x) => x.type === 'empty' || x.type === 'trailer' || x.type === 'manufacturer');
  }

  function groupFindings(warnings) {
    const g = new Map();
    for (const w of warnings) {
      const k = w.level + '\u0000' + w.msg;
      if (!g.has(k)) g.set(k, { level: w.level, msg: w.msg, secs: [] });
      g.get(k).secs.push(w.sector);
    }
    const order = { err: 0, warn: 1, info: 2 };
    return [...g.values()].sort((a, b) => order[a.level] - order[b.level] || (a.secs[0] ?? -1) - (b.secs[0] ?? -1));
  }
  function sectorRanges(secs, link) {
    if (secs.every((s) => s === null)) return 'file';
    const s = secs.filter((x) => x !== null).sort((a, b) => a - b);
    const parts = [];
    let a = s[0], p = s[0];
    for (const x of s.slice(1).concat([Infinity])) {
      if (x === p + 1) { p = x; continue; }
      parts.push([a, p]); a = p = x;
    }
    const fmt = (n) => link ? `<a href="#sec-${n}" data-jump="${n}">S${String(n).padStart(2, '0')}</a>` : `S${String(n).padStart(2, '0')}`;
    return parts.map(([x, y]) => x === y ? fmt(x) : `${fmt(x)}–${fmt(y)}`).join(', ');
  }

  /* hover: highlight all bytes of the same field in the row */
  document.addEventListener('mouseover', (e) => {
    const t = e.target.closest('.bytes span[data-f]');
    $$('.bytes span.hl').forEach((x) => x.classList.remove('hl'));
    if (!t) return;
    $$(`span[data-f="${t.dataset.f}"]`, t.parentNode).forEach((x) => x.classList.add('hl'));
  });

  /* jump links */
  document.addEventListener('click', (e) => {
    const a = e.target.closest('[data-jump]');
    if (!a) return;
    e.preventDefault();
    const pane = a.closest('.tabpane');
    const el = $(`#${pane.id === 'tab-compare' ? 'cmp' : 'sec'}-${a.dataset.jump}`, pane);
    if (!el) return;
    el.classList.remove('collapsed', 'flash');
    void el.offsetWidth;
    el.classList.add('flash');
    el.scrollIntoView({ block: 'start' });
  });

  /* ═══════════════════ PARSER VIEW ═══════════════════ */

  function legendHTML() {
    return `<div class="legend">
      <span>${sp('uid', 'UID')} ${sp('bcc', 'BCC')} ${sp('sak', 'SAK')} ${sp('atqa', 'ATQA')}</span><span class="sep">│</span>
      <span>${sp('keya', 'Key A')} ${sp('acc', 'Access')} ${sp('gpb', 'GPB')} ${sp('keyb', 'Key B')}</span><span class="sep">│</span>
      <span>${sp('value', 'Value')} ${sp('valinv', '~Value')} ${sp('addr', 'Addr')}</span><span class="sep">│</span>
      <span>${sp('crc', 'MAD-CRC')} ${sp('aid', 'AID')}</span><span class="sep">│</span>
      <span>Rights: <span class="p-AB">A|B</span> <span class="p-A">A</span> <span class="p-B">B</span> <span class="p-never">never</span></span>
      <span class="sep">│</span><span>hover a byte for its meaning</span></div>`;
  }

  function renderParser() {
    const P = state.parser;
    if (!P) return;
    const { d, res, name } = P;
    const man = res.manufacturer;
    const showAscii = $('#opt-ascii').checked;
    const collapse = $('#opt-collapse').checked;
    const groups = groupFindings(res.warnings);
    const nErr = groups.filter((g) => g.level === 'err').length;
    const nWarn = groups.filter((g) => g.level === 'warn').length;
    const keys = new Map();
    res.sectors.forEach((s) => [s.keyA, s.keyB].forEach((k) => k && keys.set(k, (keys.get(k) || 0) + 1)));

    let h = '';
    // overview
    h += '<div class="overview">';
    h += `<div class="stat"><div class="k">File</div><div class="v">${esc(name)}</div><div class="s">${esc(res.format)}</div></div>`;
    h += `<div class="stat"><div class="k">Card</div><div class="v">${esc(res.card)}</div><div class="s">${res.size} bytes · ${res.nsec} sectors</div></div>`;
    if (man) {
      h += `<div class="stat"><div class="k">UID (${man.uidLen}-byte)</div><div class="v c-uid">${spaced(man.uid)}</div><div class="s">${man.uidLen === 4 ? `SAK ${H(man.sak)} · ATQA ${man.atqa}` : esc(man.mfr)}</div></div>`;
    }
    h += `<div class="stat"><div class="k">Keys</div><div class="v">${keys.size} unique</div><div class="s">${[...keys.keys()].filter((k) => M.KNOWN_KEYS[k] && k !== '000000000000').length} known/default</div></div>`;
    h += `<div class="stat"><div class="k">Findings</div><div class="v"><span class="${nErr ? 'c-err' : 'c-ok'}">${nErr} err</span> · <span class="${nWarn ? 'c-warn' : 'c-ok'}">${nWarn} warn</span></div><div class="s">${res.mad ? `MAD v${res.mad.version} ${res.mad.crcOk ? '✔' : '✘ CRC'}` : 'no MAD'}</div></div>`;
    h += '</div>';

    h += `<div class="toolbar">
      <button class="btn small" id="exp-json">⇩ JSON</button>
      <button class="btn small" id="exp-keys">⇩ Keys (.dic)</button>
      <button class="btn small" id="copy-uid">Copy UID</button>
      <button class="btn small" id="to-compare">Compare with another dump →</button>
      <span class="spacer"></span>
      <button class="btn small" id="expand-all">Expand all</button>
      <button class="btn small" id="collapse-all">Collapse all</button></div>`;
    h += legendHTML();

    // summary
    h += `<div class="panel"><h2>Key &amp; access summary</h2><div class="tablewrap"><table><thead><tr>
      <th>Sec</th><th>Blocks</th><th>Key A</th><th>Key B</th><th>Access</th><th>GPB</th><th>Notes</th></tr></thead><tbody>`;
    for (const s of res.sectors) {
      h += `<tr class="click" data-jump="${s.sector}"><td>${s.sector}</td><td class="c-muted">${s.firstBlock}–${s.trailerBlock}</td>
        <td>${s.keyA ? sp('keya', s.keyA) : sp('unknown', '------------')}</td>
        <td>${s.keyB ? sp('keyb', s.keyB) : sp('unknown', '------------')}</td>
        <td>${s.accessBytes ? sp(s.accessValid ? 'acc' : 'bad', spaced(s.accessBytes)) : sp('unknown', '-- -- --')}</td>
        <td>${s.gpb !== null ? sp('gpb', H(s.gpb)) : '--'}</td><td>${sectorBadges(s)}</td></tr>`;
    }
    h += '</tbody></table></div></div>';

    // findings
    h += `<div class="panel"><h2>Findings<span class="count">${nErr} error(s) · ${nWarn} warning(s) · ${groups.length - nErr - nWarn} note(s)</span></h2><ul class="findings">`;
    if (!groups.length) h += '<li><span class="ico c-ok">✔</span><span></span><span class="msg">nothing notable</span></li>';
    for (const g of groups) {
      const ico = { err: '✘', warn: '⚠', info: '•' }[g.level];
      h += `<li class="f-${g.level}"><span class="ico">${ico}</span><span class="where">${sectorRanges(g.secs, true)}</span><span class="msg">${esc(g.msg)}</span></li>`;
    }
    h += '</ul></div>';

    // unique keys
    h += '<div class="panel"><h2>Unique keys<span class="count">' + keys.size + '</span></h2><div class="tablewrap"><table><tbody>';
    for (const [k, c] of [...keys.entries()].sort((a, b) => b[1] - a[1])) {
      h += `<tr><td>${sp('acc', k)}</td><td class="c-muted">×${c}</td><td class="${M.KNOWN_KEYS[k] ? 'c-warn' : 'c-dim'}">${esc(M.KNOWN_KEYS[k] || '')}</td></tr>`;
    }
    h += '</tbody></table></div></div>';

    // nav
    h += '<div class="secnav">' + res.sectors.map((s) => {
      const cls = s.accessValid === false ? 'err' : ([s.keyA, s.keyB].some((k) => k && M.KNOWN_KEYS[k] && k !== '000000000000') ? 'warnk' : '');
      return `<a href="#sec-${s.sector}" data-jump="${s.sector}" class="${cls}">S${s.sector}</a>`;
    }).join('') + '</div>';

    // sectors
    for (const sec of res.sectors) {
      const collapsed = collapse && isUntouched(sec);
      h += `<section class="sector${collapsed ? ' collapsed' : ''}" id="sec-${sec.sector}">
        <div class="sec-head"><span class="chev">▾</span><h3>Sector ${sec.sector}</h3><span class="blocks">blocks ${sec.firstBlock}–${sec.trailerBlock}</span><span class="badges">${sectorBadges(sec)}</span></div>
        <div class="sec-body"><div class="hexdump">`;
      for (const info of sec.blockInfo) {
        if (info.type === 'trailer') info.accValid = sec.accessValid;
        h += hexRow(d, info, man, { ascii: showAscii });
      }
      h += '</div><div class="details">';
      if (sec.sector === 0) {
        h += '<div class="kv">';
        if (man && man.uidLen === 4) {
          h += `<span class="k">UID</span><span>${sp('uid', spaced(man.uid))}<span class="note c-dim">4-byte${man.uid.startsWith('08') ? ', 08 = random ID' : ''}</span></span>`;
          h += `<span class="k">BCC</span><span>${sp(man.bccOk ? 'bcc' : 'bad', H(man.bcc))}<span class="note ${man.bccOk ? 'c-ok' : 'c-err'}">${man.bccOk ? '✔ matches UID XOR' : '✘ expected ' + H(man.bccCalc)}</span></span>`;
          h += `<span class="k">SAK</span><span>${sp('sak', H(man.sak))}<span class="note c-dim">${esc(man.sakName)}</span></span>`;
          h += `<span class="k">ATQA</span><span>${sp('atqa', man.atqa)}</span>`;
          h += `<span class="k">Mfr</span><span>${sp('mfr', spaced(man.mfrData))}<span class="note c-dim">as stored in the dump</span></span>`;
        } else if (man) {
          h += `<span class="k">UID</span><span>${sp('uid', spaced(man.uid))}<span class="note c-dim">7-byte · manufacturer: ${esc(man.mfr)}</span></span>`;
          h += `<span class="k">Mfr</span><span>${sp('mfr', spaced(man.mfrData))}</span>`;
        }
        h += '</div>';
        if (res.mad) h += madHTML(res.mad, 'MAD v1');
      }
      if (sec.sector === 16 && res.mad && res.mad.mad2) h += madHTML(res.mad.mad2, 'MAD v2');
      h += `<div class="subhead">Keys &amp; access</div><div class="kv">${keyLine('Key A', sec.keyA, 'keya', sec)}${keyLine('Key B', sec.keyB, 'keyb', sec)}`;
      if (sec.accessBytes) {
        h += `<span class="k">Access</span><span>${sp(sec.accessValid ? 'acc' : 'bad', spaced(sec.accessBytes))}<span class="note ${sec.accessValid ? 'c-ok' : 'c-err'}">${sec.accessValid ? '✔ valid' : '✘ INVALID — inverted bits mismatch; a real card bricks this sector'}</span></span>`;
        if (sec.gpb !== null) {
          let gn = '';
          if (sec.sector === 0 && sec.gpb & 0x80) gn = `MAD present, v${sec.gpb & 3}${sec.gpb & 0x40 ? ', multi-application' : ''}`;
          h += `<span class="k">GPB</span><span>${sp('gpb', H(sec.gpb))}${gn ? `<span class="note c-dim">${gn}</span>` : ''}</span>`;
        }
        h += '</div>' + aclTables(sec.conds, sec.accessValid, sec.keybReadable, sec.firstBlock, sec.blocks);
      } else {
        h += `<span class="k">Access</span><span>${sp('unknown', '-- -- --')}<span class="note c-dim">access bits not in dump</span></span></div>`;
      }
      h += '</div></div></section>';
    }

    const rep = $('#report');
    rep.innerHTML = h;
    rep.hidden = false;
    $('#dropzone').classList.add('compact');

    $('#exp-json').onclick = () => download(name.replace(/\.[^.]+$/, '') + '.json', JSON.stringify(M.toJSON(res), null, 2), 'application/json');
    $('#exp-keys').onclick = () => download(name.replace(/\.[^.]+$/, '') + '_keys.dic', [...keys.keys()].join('\n') + '\n', 'text/plain');
    $('#copy-uid').onclick = (e) => { if (man) navigator.clipboard?.writeText(man.uid).then(() => { e.target.textContent = 'Copied ✔'; setTimeout(() => (e.target.textContent = 'Copy UID'), 1200); }); };
    $('#to-compare').onclick = () => { setCmp('A', P.file); switchTab('compare'); };
    $('#expand-all').onclick = () => $$('#report .sector').forEach((s) => s.classList.remove('collapsed'));
    $('#collapse-all').onclick = () => $$('#report .sector').forEach((s) => s.classList.add('collapsed'));
  }

  function madHTML(m, title) {
    const cps = m.info & 0x3f;
    let h = `<div class="subhead">${title}</div><div class="kv"><span class="k">CRC</span><span>${sp('crc', H(m.crc))}<span class="note ${m.crcOk ? 'c-ok' : 'c-err'}">${m.crcOk ? '✔ valid' : '✘ calculated ' + H(m.crcCalc)}</span></span>`;
    h += `<span class="k">Info</span><span>${sp('madinfo', H(m.info))}<span class="note c-dim">card publisher sector: ${cps || 'none'}</span></span></div><div class="madgrid">`;
    for (const a of m.aids) h += `<div><span>S${String(a.sector).padStart(2, '0')}</span> ${sp(a.ac || a.fcc ? 'aid' : 'dim', a.aid)} <span>${esc(a.label)}</span></div>`;
    return h + '</div>';
  }

  // section header toggles (delegated)
  document.addEventListener('click', (e) => {
    const head = e.target.closest('.sec-head');
    if (head && !e.target.closest('a')) head.parentNode.classList.toggle('collapsed');
  });

  function loadParser(file) {
    $('#error').hidden = true;
    try {
      state.parser = parse(file, +$('#uid-len').value);
      renderParser();
    } catch (err) {
      $('#error').textContent = `Couldn't parse ${file.name}: ${err.message}`;
      $('#error').hidden = false;
    }
  }
  setupDrop($('#dropzone'), loadParser);
  $('#load-sample').onclick = () => fetchSample('samples/sample_1k.mfd').then(loadParser).catch((e) => { $('#error').textContent = e.message; $('#error').hidden = false; });
  $('#uid-len').onchange = () => state.parser && loadParser(state.parser.file);
  $('#opt-ascii').onchange = renderParser;
  $('#opt-collapse').onchange = renderParser;

  /* ═══════════════════ COMPARE VIEW ═══════════════════ */

  function setCmp(slot, file) {
    $('#cmp-error').hidden = true;
    try {
      state.cmp[slot] = parse(file);
      const z = $('#drop-' + slot);
      z.classList.add('loaded');
      const r = state.cmp[slot].res;
      $('#file-' + slot).innerHTML = `${esc(file.name)}<br><span class="c-muted">${esc(r.card)}${r.manufacturer ? ' · UID ' + r.manufacturer.uid : ''}</span>`;
      renderCompare();
    } catch (err) {
      $('#cmp-error').textContent = `Couldn't parse ${file.name}: ${err.message}`;
      $('#cmp-error').hidden = false;
    }
  }
  $$('.cmp-drop').forEach((z) => setupDrop(z, (f) => setCmp(z.dataset.slot, f)));
  $('#cmp-swap').onclick = () => {
    const { A, B } = state.cmp;
    state.cmp = { A: null, B: null };
    $$('.cmp-drop').forEach((z) => z.classList.remove('loaded'));
    ['A', 'B'].forEach((s) => ($('#file-' + s).textContent = 'no file'));
    if (B) setCmp('A', B.file);
    if (A) setCmp('B', A.file);
    if (!A || !B) renderCompare();
  };
  $('#cmp-sample').onclick = () => Promise.all([fetchSample('samples/sample_1k.mfd'), fetchSample('samples/sample_1k_after.mfd')])
    .then(([a, b]) => { setCmp('A', a); setCmp('B', b); })
    .catch((e) => { $('#cmp-error').textContent = e.message; $('#cmp-error').hidden = false; });
  $('#cmp-only').onchange = renderCompare;

  function diffBlock(dA, dB, b) {
    const a = dA.block(b), bb = dB.block(b), ka = dA.bknown(b), kb = dB.bknown(b);
    const mask = [];
    for (let i = 0; i < 16; i++) mask.push(ka[i] !== kb[i] || (ka[i] && a[i] !== bb[i]));
    return mask;
  }

  function sectorChanges(sA, sB, A, B) {
    const ch = [];
    const arrow = '<span class="arrow">→</span>';
    const fmtKey = (k, cls) => (k ? sp(cls, k) : sp('unknown', 'not in dump'));
    if (sA.keyA !== sB.keyA) ch.push(['Key A', `${fmtKey(sA.keyA, 'keya')} ${arrow} ${fmtKey(sB.keyA, 'keya')}`]);
    if (sA.keyB !== sB.keyB) ch.push(['Key B', `${fmtKey(sA.keyB, 'keyb')} ${arrow} ${fmtKey(sB.keyB, 'keyb')}`]);
    if (sA.accessBytes !== sB.accessBytes) {
      let detail = '';
      if (sA.conds && sB.conds) {
        const parts = [];
        for (let g = 0; g < 4; g++) {
          if (sA.conds[g] === sB.conds[g]) continue;
          const lbl = g === 3 ? 'trailer' : (sA.blocks === 4 ? `blk ${sA.firstBlock + g}` : `blks ${sA.firstBlock + g * 5}–${sA.firstBlock + g * 5 + 4}`);
          const mean = (c) => (g === 3 ? M.TRAILER_ACL[c][6] : M.DATA_ACL[c][4]);
          parts.push(`${lbl}: <i>${esc(mean(sA.conds[g]))}</i> → <i>${esc(mean(sB.conds[g]))}</i>`);
        }
        detail = `<div class="c-muted small" style="flex-basis:100%;padding-left:130px">${parts.join('<br>')}</div>`;
      }
      ch.push(['Access bits', `${sp(sA.accessValid === false ? 'bad' : 'acc', spaced(sA.accessBytes) || '--')} ${arrow} ${sp(sB.accessValid === false ? 'bad' : 'acc', spaced(sB.accessBytes) || '--')}${detail}`]);
    }
    if (sA.gpb !== sB.gpb) ch.push(['GPB', `${sp('gpb', sA.gpb === null ? '--' : H(sA.gpb))} ${arrow} ${sp('gpb', sB.gpb === null ? '--' : H(sB.gpb))}`]);
    sA.blockInfo.forEach((ia, i) => {
      const ib = sB.blockInfo[i];
      if (ia.type === 'trailer') return;
      const mask = diffBlock(A.d, B.d, ia.block);
      const n = mask.filter(Boolean).length;
      if (!n) return;
      if (ia.type === 'value' && ib.type === 'value') {
        const delta = ib.value - ia.value;
        ch.push([`Block ${ia.block} value`, `${sp('value', ia.value)} ${arrow} ${sp('value', ib.value)} <span class="${delta >= 0 ? 'delta-pos' : 'delta-neg'}">(${delta >= 0 ? '+' : ''}${delta})</span>${ia.addr !== ib.addr ? ` · addr ${H(ia.addr)} → ${H(ib.addr)}` : ''}`]);
      } else if (ia.type !== ib.type) {
        ch.push([`Block ${ia.block}`, `${esc(ia.type)} ${arrow} ${esc(ib.type)} <span class="c-muted">(${n} byte${n > 1 ? 's' : ''} differ)</span>`]);
      } else {
        ch.push([`Block ${ia.block}`, `<span class="c-muted">${n} byte${n > 1 ? 's' : ''} differ</span>`]);
      }
    });
    return ch;
  }

  function renderCompare() {
    const { A, B } = state.cmp;
    const rep = $('#cmp-report');
    if (!A || !B) { rep.hidden = true; return; }
    const onlyChanged = $('#cmp-only').checked;
    const nsec = Math.min(A.res.nsec, B.res.nsec);
    const mA = A.res.manufacturer, mB = B.res.manufacturer;
    const sameUid = mA && mB && mA.uid === mB.uid;

    const perSec = [];
    let blocksChanged = 0, bytesChanged = 0;
    for (let s = 0; s < nsec; s++) {
      const sA = A.res.sectors[s], sB = B.res.sectors[s];
      const masks = sA.blockInfo.map((info) => diffBlock(A.d, B.d, info.block));
      const nb = masks.filter((m) => m.some(Boolean)).length;
      blocksChanged += nb;
      bytesChanged += masks.reduce((t, m) => t + m.filter(Boolean).length, 0);
      perSec.push({ s, sA, sB, masks, nb, changes: sectorChanges(sA, sB, A, B) });
    }
    const secsChanged = perSec.filter((p) => p.nb);

    let h = '<div class="overview">';
    for (const [slot, X] of [['A', A], ['B', B]]) {
      const m = X.res.manufacturer;
      h += `<div class="stat"><div class="k"><span class="tag${slot}">${slot}</span>${esc(X.name)}</div><div class="v ${m ? 'c-uid' : ''}">${m ? spaced(m.uid) : '—'}</div><div class="s">${esc(X.res.card)} · ${esc(X.res.format)}</div></div>`;
    }
    h += `<div class="stat"><div class="k">Same card?</div><div class="v same-badge ${sameUid ? 'c-ok' : 'c-warn'}">${sameUid ? '✔ same UID' : '✘ different UID'}</div><div class="s">${A.res.size === B.res.size ? 'same layout' : `layouts differ — comparing first ${nsec} sectors`}</div></div>`;
    h += `<div class="stat"><div class="k">Differences</div><div class="v">${bytesChanged ? `<span class="c-acc">${bytesChanged}</span> bytes` : '<span class="c-ok">identical</span>'}</div><div class="s">${blocksChanged} block(s) in ${secsChanged.length} sector(s)</div></div>`;
    h += '</div>';

    if (secsChanged.length) {
      h += `<div class="panel"><h2>Changes<span class="count">${secsChanged.length} sector(s)</span></h2><ul class="findings">`;
      for (const p of secsChanged) {
        h += `<li class="f-warn"><span class="ico c-acc">Δ</span><span class="where"><a href="#cmp-${p.s}" data-jump="${p.s}">S${String(p.s).padStart(2, '0')}</a></span><span class="msg">${p.changes.map((c) => esc(c[0])).join(' · ')}</span></li>`;
      }
      h += '</ul></div>';
      h += '<div class="secnav">' + secsChanged.map((p) => `<a href="#cmp-${p.s}" data-jump="${p.s}" class="warnk">S${p.s}</a>`).join('') + '</div>';
    }
    h += `<div class="legend"><span><span class="c-acc" style="box-shadow:inset 0 -2px 0 var(--acc);background:rgba(255,215,0,.16);padding:0 3px">XX</span> byte differs</span><span class="sep">│</span>
      <span>changed block numbers in ${sp('acc', 'yellow')}</span><span class="sep">│</span><span>hover a highlighted byte to see the other side's value</span></div>`;

    let shown = 0;
    for (const p of perSec) {
      if (onlyChanged && !p.nb) continue;
      shown++;
      const { s, sA, sB, masks } = p;
      h += `<section class="sector" id="cmp-${s}"><div class="sec-head"><span class="chev">▾</span><h3>Sector ${s}</h3>
        <span class="blocks">blocks ${sA.firstBlock}–${sA.trailerBlock}</span>
        <span class="badges">${p.nb ? `<span class="badge b-warn">${p.nb} block(s) changed</span>` : '<span class="badge b-ok">identical</span>'}</span></div>
        <div class="sec-body"><div class="cmp-cols">`;
      for (const [slot, X, sec, other] of [['A', A, sA, B], ['B', B, sB, A]]) {
        h += `<div class="cmp-col"><div class="colhead"><span class="tag${slot}">${slot}</span>${esc(X.name)}</div><div class="hexdump cmp">`;
        sec.blockInfo.forEach((info, i) => {
          if (info.type === 'trailer') info.accValid = sec.accessValid;
          h += hexRow(X.d, info, X.res.manufacturer, {
            diff: masks[i], changed: masks[i].some(Boolean), side: slot, compact: true,
            other: other.d.block(info.block), otherKnown: other.d.bknown(info.block),
          });
        });
        h += '</div></div>';
      }
      h += '</div>';
      if (p.changes.length) {
        h += '<ul class="changes">' + p.changes.map(([w, t]) => `<li><span class="what">${esc(w)}</span><span>${t}</span></li>`).join('') + '</ul>';
      }
      h += '</div></section>';
    }
    if (!shown) h += '<div class="panel c-ok">✔ The two dumps are identical in every compared sector.</div>';
    if (A.res.nsec !== B.res.nsec) {
      const bigger = A.res.nsec > B.res.nsec ? 'A' : 'B';
      h += `<div class="panel c-warn">Dump ${bigger} has ${Math.abs(A.res.nsec - B.res.nsec)} extra sector(s) that were not compared.</div>`;
    }
    rep.innerHTML = h;
    rep.hidden = false;
  }

  /* ═══════════════════ ACL CALCULATOR ═══════════════════ */

  const PRESETS = [
    ['Transport (factory)', ['000', '000', '000', '001']],
    ['Key B manages, data open', ['000', '000', '000', '011']],
    ['MAD sector 0', ['100', '100', '100', '011']],
    ['Value block in blk 1', ['100', '110', '100', '011']],
    ['Read-only, frozen trailer', ['010', '010', '010', '110']],
    ['Locked down', ['111', '111', '111', '111']],
  ];

  function buildAclBuilder() {
    const opts = (table, isTrailer) => Object.entries(table).map(([c, row]) =>
      `<option value="${c}">${c} — ${esc(isTrailer ? row[6] : row[4])}</option>`).join('');
    $('#acl-builder').innerHTML = [0, 1, 2].map((g) =>
      `<label>Block ${g} <span class="c-dim">(4K big sectors: blocks ${g * 5}–${g * 5 + 4})</span><select data-g="${g}">${opts(M.DATA_ACL)}</select></label>`).join('') +
      `<label>Sector trailer<select data-g="3">${opts(M.TRAILER_ACL, true)}</select></label>`;
    $$('#acl-builder select').forEach((s) => (s.onchange = () => {
      const conds = $$('#acl-builder select').map((x) => x.value);
      $('#acl-hex').value = M.encodeAccess(conds).map(H).join(' ');
      updateAcl(false);
    }));
    const pr = $('#acl-presets');
    const seen = new Set();
    PRESETS.forEach(([label, conds]) => {
      const hex = M.encodeAccess(conds).map(H).join(' ');
      const key = label + hex;
      if (seen.has(key)) return;
      seen.add(key);
      const b = document.createElement('button');
      b.className = 'chip';
      b.textContent = `${label} · ${hex}`;
      b.onclick = () => { $('#acl-hex').value = hex; updateAcl(true); };
      pr.appendChild(b);
    });
  }

  function updateAcl(syncSelects = true) {
    const raw = $('#acl-hex').value.replace(/[^0-9a-f]/gi, '');
    const gpbRaw = $('#acl-gpb').value.replace(/[^0-9a-f]/gi, '').padStart(2, '0').slice(-2);
    const st = $('#acl-status');
    if (raw.length !== 6) {
      st.className = 'pill err'; st.textContent = 'need 3 bytes';
      $('#acl-output').innerHTML = ''; $('#acl-trailer').textContent = '';
      return;
    }
    const b = raw.match(/../g).map((x) => parseInt(x, 16));
    const { conds, valid } = M.decodeAccess(b[0], b[1], b[2]);
    const kbr = valid && M.KEYB_READABLE.has(conds[3]);
    st.className = 'pill ' + (valid ? 'ok' : 'err');
    st.textContent = valid ? '✔ valid' : '✘ invalid — would brick the sector';
    if (syncSelects) $$('#acl-builder select').forEach((s) => (s.value = conds[+s.dataset.g]));
    $('#acl-trailer').innerHTML = `${sp('keya', 'FFFFFFFFFFFF')}${sp('acc', raw.toUpperCase())}${sp('gpb', gpbRaw.toUpperCase())}${sp('keyb', 'FFFFFFFFFFFF')} <span class="c-dim">(keys shown as defaults)</span>`;
    let html = aclTables(conds, valid, kbr, 0, 4);
    if (!valid) {
      const fixed = M.encodeAccess(conds).map(H).join(' ');
      html += `<div class="footnote">Correctly inverted version of these conditions: <code class="c-acc">${fixed}</code></div>`;
    }
    $('#acl-output').innerHTML = html;
  }
  buildAclBuilder();
  $('#acl-hex').addEventListener('input', () => updateAcl(true));
  $('#acl-gpb').addEventListener('input', () => updateAcl(false));
  updateAcl(true);
})();
