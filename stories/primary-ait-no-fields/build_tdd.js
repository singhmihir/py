// Technical design document for the Primary AIT resolution without new fields or tables.
// Reads measure.json (timings) and test_summary.json (check counts) produced by measure.py and test.py.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, TableLayoutType, PageNumber, Footer } = require('docx');
const M = JSON.parse(fs.readFileSync(__dirname + '/measure.json', 'utf8'));
const T = JSON.parse(fs.readFileSync(__dirname + '/test_summary.json', 'utf8'));
const FONT = 'Arial', SZ = 17, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 50 : o.after, line: o.line || 232 }, alignment: o.align }); };
const h = (text) => new Paragraph({ children: [t(text, { bold: true, size: 22 })], spacing: { before: 120, after: 30, line: 232 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0', space: 2 } } });
const b = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: 0 }, spacing: { after: 24, line: 232 } });
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 28, bottom: 28, left: 70, right: 70 } });
function table(headers, rows, widths, monoCols) {
  monoCols = monoCols || [];
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 17, mono: !bold && monoCols.indexOf(i) > -1 }), { after: 0, line: 220 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const ms = (v) => (v == null ? '-' : Number(v).toLocaleString('en-US'));
const K = [];
K.push(p(t('Primary AIT Resolution for Discovered Items', { bold: true, size: 30 }), { after: 20 }));
K.push(p(t('Technical design: keeping the Primary AIT on discovered items current without new fields or tables', { color: MUTED }), { after: 80 }));

K.push(h('1. Purpose and constraints'));
K.push(p(t('Every discovered item (Discovered Items, Application Releases, Container Images) carries a Primary AIT derived from the CMDB: the AIT of the business application behind the services its CI belongs to. The value drives finding ownership, so it must be right at import time and follow CMDB changes within minutes. The current build derives it per discovered item with a graph walk in a business rule and a scheduled job, which does not scale to the discovered item volume.')));
K.push(p(t('Constraints for this design: no new fields, no new tables, no new columns on any table; only the three existing Primary AIT fields on the discovered item tables are written; imports must carry the value immediately; CMDB changes may take minutes to propagate.')));

K.push(h('2. The derivation'));
K.push(b([t('services(ci)', { mono: true }), t(': the service associations of the CI in both directions ('), t('svc_ci_assoc', { mono: true }), t('), the CI itself when it is a service, and its Related Services links ('), t('sn_vul_m2m_ci_services', { mono: true }), t('). When all three are empty, the same sources on the CIs related to it through '), t('cmdb_rel_ci', { mono: true }), t(' in either direction, which is the fallback of the current rule.')]));
K.push(b([t('primary(service)', { mono: true }), t(': among the business applications related to the service in either direction, the AIT with the lowest RTO tier; ties broken by AIT number.')]));
K.push(b([t('primary(ci)', { mono: true }), t(': the best of '), t('primary(service)', { mono: true }), t(' over '), t('services(ci)', { mono: true }), t('. '), t('primary(discovered item)', { mono: true }), t(' = '), t('primary(its CI)', { mono: true }), t('.')]));
K.push(p(t('The sources and the fallback are properties, so the derivation can be narrowed to the current rule exactly (drop related) or widened to the platform impact walk (fallback = walk) without a code change.')));

K.push(h('3. Design'));
K.push(p(t('No intermediate value is stored anywhere. The Primary AIT of a service or a CI is computed from the index tables when needed, in a handful of indexed reads, and only the discovered item rows hold a result. Three mechanisms keep those rows right:')));
K.push(b([t('Import path. ', { bold: true }), t('A before rule on each discovered item table (insert, and update when the CI changes) writes the value in the same transaction. Nothing is queued for imports; an item is never seen without its value.')]));
K.push(b([t('Keyed propagation. ', { bold: true }), t('After rules on the source tables queue one event naming what changed: a CI whose membership changed (service association, Related Services), the two ends of a relationship, a business application whose AIT changed, an AIT whose tier changed. The rules compute nothing. A script action on a dedicated sequential queue expands the key to the CIs it can affect, resolves each CI once, groups the CIs by the value found and stamps each discovered item table in sets of 200 CIs, touching only rows that hold a different value. Events are processed one at a time in the order queued, so a later change always writes after an earlier one.')]));
K.push(b([t('Safety nets. ', { bold: true }), t('A catch-up job every 15 minutes replays the last 30 minutes of association, Related Services and relationship inserts, which covers bulk writes that bypass business rules. A nightly job re-derives every discovered item that has a CI, in 16 partitions per table, and clears items that lost their CI. Both are idempotent: an item already holding the right value is not written.')]));
K.push(p(t('The work of a change is proportional to what the change can affect, never to the number of discovered items: an association change resolves one CI; an application moving to another AIT resolves the CIs of its services; an AIT tier change resolves the CIs of every service of every application of that AIT. The event table is the work queue, which the platform persists, orders and retries.')));

K.push(h('4. Components (one Global update set)'));
K.push(table(['Component', 'Name', 'Role'], [
  ['Script include', 'AitResolver', 'resolveRecord (before rules), enqueue and enqueueRelationship (after rules), refresh (script action), refreshCis, reconcile and clearOrphans (jobs); ciAit, ciServices, serviceAit are the pure derivation'],
  ['Business rules, before', 'USEM Primary AIT - discovered item / application release / container image', 'insert and update when cmdb_ci changes; write the value'],
  ['Business rules, after', 'USEM Primary AIT - service association / related service / relationship / application AIT / AIT tier', 'insert, update, delete (the last two on update of the AIT reference or the tier); queue one keyed event'],
  ['Event and queue', 'usem.ait.refresh on queue usem_ait', 'parm1 = ait | app | service | ci | rel, parm2 = sys_ids; sequential, one job, 10 s poll'],
  ['Script action', 'USEM Primary AIT refresh', 'new AitResolver().refresh(parm1, parm2)'],
  ['Scheduled jobs', 'USEM Primary AIT reconcile (daily 02:00), USEM Primary AIT catch-up (every 15 min)', 'nightly re-derivation and orphan clearing; replay of recent inserts'],
  ['Properties', 'usem.ait.ait_table, tier_field, app_table, app_ait_field, di_tables, sources, fallback, stamp_chunk, event_queue', 'table and field names, discovered item tables (table=ci_field=ait_field per line), derivation sources and fallback, chunk size, queue name'],
], [1700, 3300, 5000], [1]));

K.push(h('5. Test results on the developer instance'));
K.push(p(t('Fixture graph: 5 business applications (one without AIT), 6 services, 10 CIs, 34 discovered items across the three tables, 4 AITs with tiers 1, 2, 3, 2 (a tie). Every scenario changed one source record through the normal write path, waited for the queue to drain and compared all 34 items with the expected values. ' + T.checks + ' checks, ' + T.runs + ' full runs, no differences, no resolver errors in the system log.')));
K.push(b(t('Items stamped at insert; an item re-pointed to another CI takes the new value in the same write, cleared when pointed at a CI without services.')));
K.push(b(t('Association insert and delete, relationship application-service insert and delete, application AIT change and revert, AIT tier change and revert (tie-break by tier, then number), relationship service-CI through the fallback, Related Services link insert and delete: all propagated within one poll cycle (7 to 11 s observed, 10 s poll).')));
K.push(b(t('A full refresh of every fixture CI found nothing stale before or after; a second run touched no row. Values written past the rules (a wrong value, a missing value, an item without CI) were repaired by the reconcile and orphan passes. An association written with rules off was picked up by the catch-up job running as a scheduled job.')));

K.push(h('6. Cost on the developer instance'));
const on = M.import_rule_on || {}, off = M.import_rule_off || {}, fo = M.fanout || {}, fc = M.fanout_clear || {}, rp = M.reconcile_partition || {}, nf = M.nightly_foreground || {};
K.push(table(['Path', 'Timed', 'Result'], [
  ['Import, CI with a service', '100 discovered item inserts, rule on / rule off', ms(on.ms_per_insert_ci_with_service) + ' ms / ' + ms(off.ms_per_insert_ci_with_service) + ' ms per insert'],
  ['Import, CI resolved through a related CI', 'same', ms(on.ms_per_insert_ci_related_only) + ' ms / ' + ms(off.ms_per_insert_ci_related_only) + ' ms per insert'],
  ['Import, CI without any link', 'same', ms(on.ms_per_insert_ci_without_links) + ' ms / ' + ms(off.ms_per_insert_ci_without_links) + ' ms per insert'],
  ['Keyed refresh, wide fan-out', 'a service gaining ' + ms(fo.cis) + ' CIs at once, ' + ms(fo.dis_of_those_cis) + ' discovered items', ms(fo.refresh_ms) + ' ms; ' + ms(fo.dis_stamped) + ' items stamped; re-run ' + ms(fo.refresh_again_ms) + ' ms'],
  ['Clearing after the associations are removed', ms(fo.cis) + ' CIs re-resolved', ms(fc.clear_ms) + ' ms, ' + ms(fc.dis_still_stamped) + ' items left stamped'],
  ['Nightly reconcile, one partition', ms(rp.cis) + ' CIs, ' + ms(rp.dis) + ' discovered items', ms(rp.ms) + ' ms (' + ms(rp.ms_per_ci) + ' ms per CI)'],
  ['Nightly pass, whole', 'three tables, 16 partitions each, orphan passes; ' + ms(T.matched_cis) + ' CIs with ' + ms(T.matched_dis) + ' items', (nf.ms ? (nf.ms / 60000).toFixed(1) + ' min' : '-') + ', run in four batches'],
], [2900, 3600, 3500]));
K.push(p(t('The instance holds ' + ms(T.total_dis) + ' discovered items and ' + ms(T.total_cis) + ' CIs, with a near-empty service graph, so the resolution cost is a floor and the stamp cost is representative. The nightly pass grows with the number of CIs that have discovered items, about ' + ms(rp.ms_per_ci) + ' ms each; each partition is a separate call, so the pass can be split across nodes or hours. The scheduled job itself ran the same code on demand without errors.', { color: MUTED })));

K.push(h('7. Deployment and assumptions to confirm'));
K.push(b([t('The AIT table and its tier field: property '), t('usem.ait.ait_table', { mono: true }), t(' (delivered as '), t('x_boar_bofa_techad_ait', { mono: true }), t('), property '), t('usem.ait.tier_field', { mono: true }), t(' and the condition of the rule '), t('USEM Primary AIT - AIT tier', { mono: true }), t(' (delivered with '), t('rto_tier', { mono: true }), t('; align both to the real column).')]));
K.push(b([t('The business application AIT reference: property '), t('usem.ait.app_ait_field', { mono: true }), t(' and the condition of the rule '), t('USEM Primary AIT - application AIT', { mono: true }), t(' (delivered with '), t('u_primary_ait', { mono: true }), t(').')]));
K.push(b([t('The discovered item tables and fields in '), t('usem.ait.di_tables', { mono: true }), t(': '), t('sn_sec_cmn_src_ci=cmdb_ci=u_primary_ait', { mono: true }), t(', '), t('sn_vul_app_release=cmdb_ci=u_primary_ait', { mono: true }), t(', '), t('sn_vul_container_image=cmdb_ci=u_bofa_primary_ait', { mono: true }), t('.')]));
K.push(b(t('Initial load: run USEM Primary AIT reconcile once after import. The queue registration provisions its own processing job. Retire the current derivation rule and job at the same time, so that two writers never compete.')));
K.push(b(t('Residual window: a discovered item written in the same instant as a change on its service can keep the earlier value until the nightly job; everything else is corrected by the keyed event within one poll cycle.')));

K.push(h('8. Alternatives considered'));
K.push(table(['Approach', 'Why not'], [
  ['Stored Primary AIT and dirty flags on CI and service (earlier design)', 'needs new columns'],
  ['Database view joining item, CI, association, relationship, application and AIT', 'no lowest-tier aggregation in a view; reports and exports still need the value on the item'],
  ['Compute at read time only', 'the field on the item must hold the value for lists, reports and the outbound payload'],
  ['One job over every discovered item, chunked or spread across nodes', 'cost stays linear in the item count and the value is only as fresh as the last run'],
  ['Session or global caches of service values', 'a value cached across transactions goes stale on the next change; dropped, the saving was about 2 ms per item'],
], [5200, 4800]));

const doc = new Document({
  creator: 'Mihir Kumar Singh', lastModifiedBy: 'Mihir Kumar Singh', title: 'Primary AIT Resolution for Discovered Items - Technical Design',
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 320, hanging: 220 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 600, bottom: 560, left: 720, right: 720 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ children: ['Page ', PageNumber.CURRENT], font: FONT, size: 15, color: MUTED })] })] }) },
    children: K }],
});
Packer.toBuffer(doc).then((buf) => { const out = __dirname + '/Primary AIT Resolution - Technical Design.docx'; fs.writeFileSync(out, buf); console.log('written', out, buf.length, 'bytes'); });
