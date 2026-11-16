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
  window.addEventListener('hashchange', () => { const t = location.hash.slice(1); if ($('#tab-' + t)) switchTab(t); });

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
      if (diff && opt.others) title = `${title ? title + ' · ' : ''}${opt.others.map((o) => `${o.slot}: ${o.kn[i] ? H(o.blk[i]) : '--'}`).join(', ')}`;
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
      (opt.noTag ? '' : `<span class="bar">│</span><span class="tag">${blockTag(info, opt.compact)}</span>`) + '</div>';
  }

  /** Render rows, folding 3+ consecutive "quiet" blocks into a single line. */
  function foldRows(infos, isQuiet, render) {
    let out = '', i = 0;
    while (i < infos.length) {
      let j = i;
      while (j < infos.length && isQuiet(infos[j], j)) j++;
      if (j - i >= 3) {
        out += `<div class="row fold"><span class="bn">${infos[i].block}–${infos[j - 1].block}</span><span class="bar">│</span><span class="c-dim">${j - i} empty blocks</span></div>`;
        i = j;
      } else {
        out += render(infos[i], i);
        i++;
      }
    }
    return out;
  }

  function aclTables(conds, valid, kbr, first, n) {
    let html = '';
    if (!valid) html += '<div class="line c-err small">Invalid access bits — the inverted copy doesn\'t match, so a real card would lock this sector. Decoded from the plain bits:</div>';
    html += '<div class="tablewrap"><table class="acltable"><thead><tr><th>Block</th><th>Read</th><th>Write</th><th>Incr</th><th>Decr</th><th></th></tr></thead><tbody>';
    let anyEff = false;
    const same = conds[0] === conds[1] && conds[1] === conds[2];
    for (let g = 0; g < (same ? 1 : 3); g++) {
      const label = same ? `${first}–${first + n - 2}` : (n === 4 ? `${first + g}` : `${first + g * 5}–${first + g * 5 + 4}`);
      const row = M.DATA_ACL[conds[g]];
      html += `<tr><td class="c-muted">${label}</td>`;
      for (const p of row.slice(0, 4)) {
        const [e, ch] = M.effective(p, kbr);
        anyEff = anyEff || ch;
        html += `<td class="${pcls(e)}">${e}${ch ? '*' : ''}</td>`;
      }
      html += `<td class="meaning">${esc(row[4])}</td></tr>`;
    }
    const t = M.TRAILER_ACL[conds[3]];
    const w = (p) => `<span class="${pcls(p)}">${p}</span>`;
    html += `<tr class="trow"><td class="c-muted">${first + n - 1}</td><td colspan="4">write Key A ${w(t[1])} · access ${w(t[3])} · Key B ${w(t[5])}</td><td class="meaning">${esc(t[6])}</td></tr>`;
    html += '</tbody></table></div>';
    if (anyEff) html += '<div class="footnote">* Key B is readable here, so only Key A works.</div>';
    return html;
  }

  function sectorBadges(sec) {
    const b = [];
    if (sec.accessValid === false) b.push('<span class="badge b-err">INVALID ACL</span>');
    if ([sec.keyA, sec.keyB].some((k) => k && M.KNOWN_KEYS[k] && k !== '000000000000')) b.push('<span class="badge b-warn">default key</span>');
    const vals = sec.blockInfo.filter((x) => x.type === 'value').length;
    if (vals) b.push(`<span class="badge b-value">${vals} value</span>`);
    if (sec.blockInfo.some((x) => x.type === 'mad')) b.push('<span class="badge b-mad">MAD</span>');
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
    if (el.tagName === 'DETAILS') el.open = true;
    el.classList.remove('collapsed', 'flash');
    void el.offsetWidth;
    el.classList.add('flash');
    el.scrollIntoView({ block: 'start' });
  });

  /* ═══════════════════ PARSER VIEW ═══════════════════ */

  function renderParser() {
    const P = state.parser;
    if (!P) return;
    const { d, res, name } = P;
    const man = res.manufacturer;
    const groups = groupFindings(res.warnings).filter((g) => g.level !== 'info');
    const nErr = groups.filter((g) => g.level === 'err').length;
    const keys = new Set();
    res.sectors.forEach((s) => [s.keyA, s.keyB].forEach((k) => k && keys.add(k)));

    // split sectors into shown cards and runs of blank (factory) sectors; sector 0 always shown
    const items = [];
    for (const s of res.sectors) {
      const blank = s.sector !== 0 && isUntouched(s);
      const last = items[items.length - 1];
      if (blank && last && last.blank) last.secs.push(s);
      else items.push(blank ? { blank: true, secs: [s] } : { blank: false, sec: s });
    }
    const runLabel = (secs) => secs.length === 1 ? `${secs[0].sector}` : `${secs[0].sector}–${secs[secs.length - 1].sector}`;

    let h = `<div class="infobar">
      <span class="mono">${esc(name)}</span><span class="dot">·</span><span>${esc(res.card)}</span>
      ${man ? `<span class="dot">·</span><span>UID ${sp('uid', man.uid)}</span>` : ''}
      <span class="dot">·</span><span class="${nErr ? 'c-err' : groups.length ? 'c-warn' : 'c-ok'}">${nErr ? nErr + ' error(s)' : groups.length ? groups.length + ' warning(s)' : '✔ no issues'}</span>
      <span class="spacer"></span>
      <button class="btn small" id="exp-json">⇩ JSON</button><button class="btn small" id="exp-keys">⇩ Keys</button></div>`;

    if (groups.length) {
      h += '<ul class="findings panel">' + groups.map((g) =>
        `<li class="f-${g.level}"><span class="ico">${g.level === 'err' ? '✘' : '⚠'}</span><span class="where">${sectorRanges(g.secs, true)}</span><span class="msg">${esc(g.msg)}</span></li>`).join('') + '</ul>';
    }

    // summary table
    h += '<div class="panel tight"><div class="tablewrap"><table><thead><tr><th>Sector</th><th>Key A</th><th>Key B</th><th>Access</th><th></th></tr></thead><tbody>';
    for (const it of items) {
      if (it.blank) {
        h += `<tr class="click" data-jump="${it.secs[0].sector}"><td>${runLabel(it.secs)}</td><td colspan="4" class="c-dim">blank · factory keys · transport access</td></tr>`;
        continue;
      }
      const s = it.sec;
      h += `<tr class="click" data-jump="${s.sector}"><td>${s.sector}</td>
        <td>${s.keyA ? sp('keya', s.keyA) : sp('unknown', '—')}</td>
        <td>${s.keyB ? sp('keyb', s.keyB) : sp('unknown', '—')}</td>
        <td>${s.accessBytes ? sp(s.accessValid ? 'acc' : 'bad', spaced(s.accessBytes)) : sp('unknown', '—')}</td>
        <td>${sectorBadges(s)}</td></tr>`;
    }
    h += '</tbody></table></div></div>';

    h += `<div class="legend">${sp('uid', 'UID')} ${sp('keya', 'Key A')} ${sp('acc', 'Access')} ${sp('gpb', 'GPB')} ${sp('keyb', 'Key B')} ${sp('value', 'Value')} <span class="c-dim">· hover a byte for details</span></div>`;

    for (const it of items) {
      if (it.blank) {
        h += `<details class="blankrun" id="sec-${it.secs[0].sector}"><summary>Sectors ${runLabel(it.secs)} <span class="c-dim">— ${it.secs.length} blank sector${it.secs.length > 1 ? 's' : ''}, factory keys</span></summary>`;
        h += it.secs.map((s) => sectorCard(d, res, s)).join('') + '</details>';
      } else {
        h += sectorCard(d, res, it.sec);
      }
    }

    const rep = $('#report');
    rep.innerHTML = h;
    rep.hidden = false;
    $('#dropzone').classList.add('compact');
    $('#exp-json').onclick = () => download(name.replace(/\.[^.]+$/, '') + '.json', JSON.stringify(M.toJSON(res), null, 2), 'application/json');
    $('#exp-keys').onclick = () => download(name.replace(/\.[^.]+$/, '') + '_keys.dic', [...keys].join('\n') + '\n', 'text/plain');
  }

  function sectorCard(d, res, sec) {
    const man = res.manufacturer;
    let h = `<section class="sector" id="sec-${sec.sector}">
      <div class="sec-head"><span class="chev">▾</span><h3>Sector ${sec.sector}</h3><span class="blocks">blocks ${sec.firstBlock}–${sec.trailerBlock}</span><span class="badges">${sectorBadges(sec)}</span></div>
      <div class="sec-body"><div class="hexdump">`;
    sec.blockInfo.forEach((info) => { if (info.type === 'trailer') info.accValid = sec.accessValid; });
    h += foldRows(sec.blockInfo, (info) => info.type === 'empty', (info) => hexRow(d, info, man, { ascii: true }));
    h += '</div><div class="details">';
    if (sec.sector === 0 && man) {
      h += man.uidLen === 4
        ? `<div class="line">UID ${sp('uid', spaced(man.uid))} · BCC ${man.bccOk ? sp('ok', '✔') : sp('err', '✘ expected ' + H(man.bccCalc))} · SAK ${sp('sak', H(man.sak))} <span class="c-dim">${esc(man.sakName)}</span> · ATQA ${sp('atqa', man.atqa)}</div>`
        : `<div class="line">UID ${sp('uid', spaced(man.uid))} <span class="c-dim">7-byte · ${esc(man.mfr)}</span></div>`;
      if (res.mad) h += madHTML(res.mad, 'MAD v1');
    }
    if (sec.sector === 16 && res.mad && res.mad.mad2) h += madHTML(res.mad.mad2, 'MAD v2');
    const notes = [keyNote('A', sec.keyA, sec), keyNote('B', sec.keyB, sec)].filter(Boolean);
    if (notes.length) h += `<div class="line c-warn small">${notes.join(' · ')}</div>`;
    if (sec.conds) h += aclTables(sec.conds, sec.accessValid, sec.keybReadable, sec.firstBlock, sec.blocks);
    else h += '<div class="line c-dim">Access bits not in dump</div>';
    return h + '</div></div></section>';
  }

  function keyNote(which, key, sec) {
    if (!key) return '';
    if (key === '000000000000' && (which === 'A' || !sec.keybReadable)) return `Key ${which} is zeros — probably masked by the card`;
    if (which === 'B' && sec.keybReadable) return 'Key B is readable, so it can\'t be used to log in';
    if (M.KNOWN_KEYS[key] && key !== 'FFFFFFFFFFFF') return `Key ${which}: ${esc(M.KNOWN_KEYS[key])}`;
    return '';
  }

  function madHTML(m, title) {
    const used = m.aids.filter((x) => x.ac || x.fcc);
    const apps = [...new Set(used.map((x) => x.label || x.aid))];
    return `<div class="line">${title} · CRC ${m.crcOk ? sp('ok', '✔') : sp('err', '✘')} · ${used.length ? `${used.length} sector(s) assigned: ${esc(apps.join(', '))}` : 'no applications'}</div>`;
  }

  // section header toggles (delegated)
  document.addEventListener('click', (e) => {
    const head = e.target.closest('.sec-head');
    if (head && !e.target.closest('a')) head.parentNode.classList.toggle('collapsed');
  });

  function loadParser(file) {
    $('#error').hidden = true;
    try {
      state.parser = parse(file);
      renderParser();
    } catch (err) {
      $('#error').textContent = `Couldn't parse ${file.name}: ${err.message}`;
      $('#error').hidden = false;
    }
  }
  setupDrop($('#dropzone'), loadParser);
  $('#load-sample').onclick = () => fetchSample('samples/sample_1k.mfd').then(loadParser).catch((e) => { $('#error').textContent = e.message; $('#error').hidden = false; });

  /* ═══════════════════ COMPARE VIEW (2 or 3 dumps) ═══════════════════ */

  const SLOTS = ['A', 'B', 'C'];
  state.cmp.C = null;

  function setCmp(slot, file) {
    $('#cmp-error').hidden = true;
    try {
      state.cmp[slot] = parse(file);
      $('#drop-' + slot).classList.add('loaded');
      const r = state.cmp[slot].res;
      $('#file-' + slot).innerHTML = `${esc(file.name)}<br><span class="c-muted">${esc(r.card)}${r.manufacturer ? ' · UID ' + r.manufacturer.uid : ''}</span>`;
      renderCompare();
    } catch (err) {
      $('#cmp-error').textContent = `Couldn't parse ${file.name}: ${err.message}`;
      $('#cmp-error').hidden = false;
    }
  }
  $$('.cmp-drop').forEach((z) => setupDrop(z, (f) => setCmp(z.dataset.slot, f)));
  $('#clear-C').addEventListener('click', (e) => {
    e.stopPropagation();
    state.cmp.C = null;
    $('#drop-C').classList.remove('loaded');
    $('#file-C').textContent = 'optional';
    renderCompare();
  });
  $('#cmp-only').onchange = renderCompare;
  state.cmpView = 'side';
  $$('#cmp-view button').forEach((b) => (b.onclick = () => {
    state.cmpView = b.dataset.v;
    $$('#cmp-view button').forEach((x) => x.classList.toggle('on', x === b));
    $('#cmp-only-wrap').hidden = state.cmpView !== 'side';
    renderCompare();
  }));

  const popcount = (n) => { let c = 0; while (n) { c += n & 1; n >>= 1; } return c; };

  /** For one block: per byte, the OR of (first ^ other) over all dumps → which bits differ. */
  function bitMask(X, b) {
    const blks = X.map((x) => x.d.block(b)), kns = X.map((x) => x.d.bknown(b));
    const out = [];
    for (let i = 0; i < 16; i++) {
      let m = 0;
      for (let k = 1; k < X.length; k++) {
        if (kns[k][i] !== kns[0][i]) m = 0xff;
        else if (kns[0][i]) m |= blks[0][i] ^ blks[k][i];
      }
      out.push(m);
    }
    return out;
  }

  /** 8-bit binary string with differing bits highlighted. */
  function bitsHTML(v, known, mask) {
    if (!known) return '<span class="c-unknown">--------</span>';
    let h = '';
    for (let j = 7; j >= 0; j--) {
      const bit = (v >> j) & 1;
      h += (mask >> j) & 1 ? `<b class="bd">${bit}</b>` : `<span class="b${bit}">${bit}</span>`;
    }
    return h;
  }

  /** All changed blocks across the compared sectors, with field info from dump A. */
  function changedBlocks(X, perSec) {
    const out = [];
    for (const p of perSec) {
      p.masks.forEach((m, i) => {
        if (!m.some(Boolean)) return;
        const info = p.secs[0].blockInfo[i];
        out.push({ sector: p.s, info, bmask: bitMask(X, info.block), fields: byteFields(info, X[0].res.manufacturer) });
      });
    }
    return out;
  }

  function renderByteTable(X, blocks) {
    let h = '<div class="panel tight"><div class="tablewrap"><table class="bytetable"><thead><tr><th>Sector</th><th>Block</th><th>Byte</th><th>Field</th>' +
      X.map((x) => `<th>${slotTag(x.slot)}</th>`).join('') + '<th>Bits Δ</th></tr></thead><tbody>';
    for (const cb of blocks) {
      for (let i = 0; i < 16; i++) {
        const m = cb.bmask[i];
        if (!m) continue;
        const f = cb.fields[i];
        const field = f.title ? f.title.replace(/ = .*$/, '') : (cb.info.type === 'empty' ? 'data (empty in A)' : 'data');
        h += `<tr><td class="c-muted"><a href="#" data-cmpjump="${cb.sector}">S${String(cb.sector).padStart(2, '0')}</a></td><td>${cb.info.block}</td><td>${i}</td><td class="c-${f.cls || 'data'} fieldname">${esc(field)}</td>`;
        for (const x of X) {
          const v = x.d.block(cb.info.block)[i], kn = x.d.bknown(cb.info.block)[i];
          h += `<td class="bytecell">${kn ? sp('head', H(v)) : sp('unknown', '--')} <span class="bitstr">${bitsHTML(v, kn, m)}</span></td>`;
        }
        h += `<td><span class="c-acc">${popcount(m)}</span> <span class="c-dim">mask ${H(m)}</span></td></tr>`;
      }
    }
    return h + '</tbody></table></div></div>';
  }

  function renderBitView(X, blocks) {
    let h = `<div class="legend"><b class="bd">1</b> bit differs · <span class="b1">1</span> / <span class="b0">0</span> same in all dumps · hover a byte for its field</div>`;
    for (const cb of blocks) {
      const nbits = cb.bmask.reduce((t, m) => t + popcount(m), 0);
      const nbytes = cb.bmask.filter(Boolean).length;
      h += `<section class="sector bitblock"><div class="sec-head"><span class="chev">▾</span><h3>Block ${cb.info.block}</h3>
        <span class="blocks">sector ${cb.sector} · ${esc(cb.info.type)}</span>
        <span class="badges"><span class="badge b-warn">${nbits} bit${nbits > 1 ? 's' : ''} in ${nbytes} byte${nbytes > 1 ? 's' : ''}</span></span></div><div class="sec-body">`;
      for (const half of [0, 8]) {
        h += '<div class="bitgrid"><div class="bitrow head"><span class="lbl"></span>';
        for (let i = half; i < half + 8; i++) h += `<span class="cell${cb.bmask[i] ? ' chg' : ''}">byte ${i}</span>`;
        h += '</div>';
        for (const x of X) {
          const blk = x.d.block(cb.info.block), kn = x.d.bknown(cb.info.block);
          h += `<div class="bitrow"><span class="lbl">${slotTag(x.slot)}</span>`;
          for (let i = half; i < half + 8; i++) {
            const f = cb.fields[i];
            h += `<span class="cell${cb.bmask[i] ? ' chg' : ''}" title="${esc((f.title || 'data') + ' — ' + (kn[i] ? '0x' + H(blk[i]) : 'unknown'))}">` +
              `<span class="hx c-${kn[i] ? (f.cls || 'data') : 'unknown'}">${kn[i] ? H(blk[i]) : '--'}</span>${bitsHTML(blk[i], kn[i], cb.bmask[i])}</span>`;
          }
          h += '</div>';
        }
        h += '</div>';
      }
      h += '</div></section>';
    }
    return h;
  }

  document.addEventListener('click', (e) => {
    const a = e.target.closest('[data-cmpjump]');
    if (!a) return;
    e.preventDefault();
    $$('#cmp-view button').find((b) => b.dataset.v === 'side').click();
    const el = $('#cmp-' + a.dataset.cmpjump);
    if (el) { el.classList.remove('collapsed'); el.scrollIntoView({ block: 'start' }); }
  });

  /** Per-byte mask: true where the loaded dumps don't all agree. */
  function diffBlock(dumps, b) {
    const blks = dumps.map((x) => x.d.block(b)), kns = dumps.map((x) => x.d.bknown(b));
    const mask = [];
    for (let i = 0; i < 16; i++) {
      let diff = false;
      for (let k = 1; k < dumps.length; k++) {
        if (kns[k][i] !== kns[0][i] || (kns[0][i] && blks[k][i] !== blks[0][i])) diff = true;
      }
      mask.push(diff);
    }
    return mask;
  }

  const allSame = (arr) => arr.every((v) => v === arr[0]);
  const slotTag = (slot) => `<span class="tag${slot}">${slot}</span>`;

  /** Changes in one sector across the loaded dumps: [label, html|null]. */
  function sectorChanges(secs, X) {
    const ch = [];
    const list = (vals, fmt) => vals.map((v, k) => `${slotTag(X[k].slot)}${fmt(v)}`).join('  ');
    const fmtKey = (cls) => (k) => (k ? sp(cls, k) : sp('unknown', '—'));
    if (!allSame(secs.map((s) => s.keyA))) ch.push(['Key A', list(secs.map((s) => s.keyA), fmtKey('keya'))]);
    if (!allSame(secs.map((s) => s.keyB))) ch.push(['Key B', list(secs.map((s) => s.keyB), fmtKey('keyb'))]);
    if (!allSame(secs.map((s) => s.accessBytes))) {
      ch.push(['Access bits', list(secs, (s) => {
        const meaning = s.conds ? ` <span class="c-dim">${esc(M.TRAILER_ACL[s.conds[3]][6])}</span>` : '';
        return sp(s.accessValid === false ? 'bad' : 'acc', spaced(s.accessBytes) || '—') + meaning;
      })]);
    }
    if (!allSame(secs.map((s) => s.gpb))) ch.push(['GPB', list(secs.map((s) => s.gpb), (g) => sp('gpb', g === null ? '—' : H(g)))]);
    secs[0].blockInfo.forEach((i0, i) => {
      if (i0.type === 'trailer') return;
      const infos = secs.map((s) => s.blockInfo[i]);
      if (!diffBlock(X, i0.block).some(Boolean)) return;
      if (infos.every((x) => x.type === 'value')) {
        ch.push([`Block ${i0.block} value`, list(infos, (x) => {
          const delta = x.value - infos[0].value;
          return sp('value', x.value) + (x === infos[0] || !delta ? '' : ` <span class="${delta > 0 ? 'delta-pos' : 'delta-neg'}">(${delta > 0 ? '+' : ''}${delta})</span>`);
        })]);
      } else if (!allSame(infos.map((x) => x.type))) {
        ch.push([`Block ${i0.block}`, list(infos, (x) => esc(x.type))]);
      } else {
        ch.push([`Block ${i0.block}`, null]);
      }
    });
    return ch;
  }

  function changeSummary(changes) {
    const named = changes.filter((c) => !/^Block \d+$/.test(c[0])).map((c) => esc(c[0]));
    const plain = changes.filter((c) => /^Block \d+$/.test(c[0])).map((c) => +c[0].split(' ')[1]);
    if (plain.length) {
      const r = plain.length === 1 ? `block ${plain[0]}` : (plain[plain.length - 1] - plain[0] === plain.length - 1 ? `blocks ${plain[0]}–${plain[plain.length - 1]}` : `blocks ${plain.join(', ')}`);
      named.push(r + ' data');
    }
    return named.join(' · ');
  }

  function renderCompare() {
    const X = SLOTS.filter((s) => state.cmp[s]).map((s) => ({ slot: s, ...state.cmp[s] }));
    const rep = $('#cmp-report');
    if (X.length < 2) { rep.hidden = true; return; }
    const onlyChanged = $('#cmp-only').checked;
    const nsec = Math.min(...X.map((x) => x.res.nsec));
    const uids = X.map((x) => x.res.manufacturer && x.res.manufacturer.uid);
    const sameUid = uids[0] && allSame(uids);

    const perSec = [];
    let blocksChanged = 0, bytesChanged = 0;
    for (let s = 0; s < nsec; s++) {
      const secs = X.map((x) => x.res.sectors[s]);
      const masks = secs[0].blockInfo.map((info) => diffBlock(X, info.block));
      const nb = masks.filter((m) => m.some(Boolean)).length;
      blocksChanged += nb;
      bytesChanged += masks.reduce((t, m) => t + m.filter(Boolean).length, 0);
      perSec.push({ s, secs, masks, nb, changes: nb ? sectorChanges(secs, X) : [] });
    }
    const secsChanged = perSec.filter((p) => p.nb);

    const cblocks = changedBlocks(X, perSec);
    const bitsChanged = cblocks.reduce((t, cb) => t + cb.bmask.reduce((u, m) => u + popcount(m), 0), 0);
    const fileTag = (x) => `${slotTag(x.slot)}${esc(x.name)}${x.res.manufacturer ? ` <span class="c-dim">(${x.res.manufacturer.uid})</span>` : ''}`;
    let h = `<div class="infobar">${X.map(fileTag).join('<span class="dot">vs</span>')}<span class="dot">·</span>
      <span class="${sameUid ? 'c-ok' : 'c-warn'}">${sameUid ? 'same card' : 'different cards'}</span><span class="dot">·</span>
      <span>${bytesChanged ? `${sp('acc', bytesChanged)} bytes (${sp('acc', bitsChanged)} bits) differ in ${blocksChanged} block(s)` : sp('ok', 'identical')}</span></div>`;
    if (secsChanged.length) {
      h += '<ul class="findings panel">' + secsChanged.map((p) =>
        `<li><span class="ico c-acc">Δ</span><span class="where"><a href="#cmp-${p.s}" data-jump="${p.s}">S${String(p.s).padStart(2, '0')}</a></span><span class="msg">${changeSummary(p.changes)}</span></li>`).join('') + '</ul>';
    }

    if (state.cmpView !== 'side') {
      if (!cblocks.length) h += `<div class="panel c-ok">✔ No differences.</div>`;
      else h += state.cmpView === 'bytes' ? renderByteTable(X, cblocks) : renderBitView(X, cblocks);
      rep.innerHTML = h;
      rep.hidden = false;
      return;
    }
    const three = X.length === 3;
    let shown = 0;
    for (const p of perSec) {
      if (onlyChanged && !p.nb) continue;
      shown++;
      const { s, secs, masks } = p;
      h += `<section class="sector" id="cmp-${s}"><div class="sec-head"><span class="chev">▾</span><h3>Sector ${s}</h3>
        <span class="blocks">blocks ${secs[0].firstBlock}–${secs[0].trailerBlock}</span>
        <span class="badges">${p.nb ? `<span class="badge b-warn">${p.nb} block(s) changed</span>` : '<span class="badge b-ok">identical</span>'}</span></div>
        <div class="sec-body"><div class="cmp-cols${three ? ' three' : ''}">`;
      X.forEach((x, k) => {
        const sec = secs[k];
        sec.blockInfo.forEach((info) => { if (info.type === 'trailer') info.accValid = sec.accessValid; });
        h += `<div class="cmp-col"><div class="colhead">${slotTag(x.slot)}${esc(x.name)}</div><div class="hexdump cmp">`;
        h += foldRows(sec.blockInfo,
          (info, i) => secs.every((sc) => sc.blockInfo[i].type === 'empty') && !masks[i].some(Boolean),
          (info, i) => hexRow(x.d, info, x.res.manufacturer, {
            diff: masks[i], changed: masks[i].some(Boolean), compact: true, noTag: three,
            others: X.filter((o) => o !== x).map((o) => ({ slot: o.slot, blk: o.d.block(info.block), kn: o.d.bknown(info.block) })),
          }));
        h += '</div></div>';
      });
      h += '</div>';
      const shownCh = p.changes.filter((c) => c[1]);
      if (shownCh.length) {
        h += '<ul class="changes">' + shownCh.map(([w, t]) => `<li><span class="what">${esc(w)}</span><span>${t}</span></li>`).join('') + '</ul>';
      }
      h += '</div></section>';
    }
    if (!shown) h += `<div class="panel c-ok">✔ The ${X.length === 3 ? 'three' : 'two'} dumps are identical in every compared sector.</div>`;
    if (!allSame(X.map((x) => x.res.nsec))) {
      h += `<div class="panel c-warn">The dumps have different sizes — only the first ${nsec} sectors were compared.</div>`;
    }
    rep.innerHTML = h;
    rep.hidden = false;
  }

})();
