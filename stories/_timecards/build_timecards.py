"""Build the ServiceNow time card workbooks (Daily Notes, Daily Timecard, Deloitte Reconciliation)
for 10-Aug-2026 onwards in the layout of the 27-Jul to 07-Aug workbook. `python3 build_timecards.py
[file ...]` builds the named workbooks only.

Deloitte T&E is the system of record (weekly screenshots, all approved). The ServiceNow side
carries at most 3.00h of project work per day for the week ending 22-Aug-2026 (VDI unavailable),
so that week reconciles with a known, documented variance.
"""
from datetime import date, timedelta
import os

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

HERE = os.path.dirname(os.path.abspath(__file__))

PERSON = 'Mihir Kumar Singh'
ROLE = 'L45 Security Engineer III, Kolkata'
ENGAGEMENT = 'Bank of America USEM / VMT'
AIT = '75624'
TEAM = 'SNow Boarders (34830)'

NAVY, NAVY_DARK, BAND, ALT, GREY = 'FF1F3864', 'FF152744', 'FFD6E1F0', 'FFEAF0F8', 'FF44546A'
WHITE, BLACK = 'FFFFFFFF', 'FF000000'
THIN = Side(style='thin', color='FF000000')
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def fmt(d):
    return d.strftime('%d-%b-%Y')


def day(d, worked, absence, project, sick, kind, ref, note, line=None):
    """One working day. kind: Analysis / Configurations / Design / Documentation / Sick Leave / Holiday."""
    if line is None:
        line = 'Project (%dh)' % project if project else ('%s (%dh)' % ('Sick' if kind == 'Sick Leave' else 'Holiday', sick))
    return dict(date=d, worked=worked, absence=absence, project=project, training=0, sick=sick,
                kind=kind, ref=ref, note=note, line=line)


VDI = ' VDI unavailable, 3.00h.'

WEEK_1 = dict(ending=date(2026, 8, 15), days=[
    day(date(2026, 8, 10), 8, 0, 8, 0, 'Analysis', 'SNOWUSEMTP-895',
        'Analysis - SNOWUSEMTP-895: baseline review of the Qualys CI lookup rule chain, walking the seven platform rules '
        '(Qualys Host ID, DNS, NetBIOS, FQDN, IP and Network, IP Only, Cloud Resource Id) against the custom USEM rules '
        'to confirm order and active flags, and built a fixture set of CIs across the hardware classes to reproduce the '
        'unmatched host cases.'),
    day(date(2026, 8, 11), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-895',
        'Configurations - SNOWUSEMTP-895: set the ignored CI class list for CI lookup (unmatched CI, Qualys CI, unclassed '
        'hardware, incomplete IP, DNS name) so a host is never bound to a placeholder class, extended the CI fixture set '
        'and re-ran the full rule chain against the Qualys payload samples.'),
    day(date(2026, 8, 12), 8, 0, 8, 0, 'Documentation', 'SNOWUSEMTP-895',
        'Documentation - SNOWUSEMTP-895: produced the rule-by-rule explanation workbook for the Qualys CI lookup rules '
        '(payload fields read, search order, match outcome and decline reason per rule) for the team walkthrough. Also '
        'delivered the USEMChoiceTableQualifier script include (reference qualifier).'),
    day(date(2026, 8, 13), 8, 0, 8, 0, 'Analysis', 'SNOWUSEMTP-895',
        'Analysis - SNOWUSEMTP-895: walkthrough of the Qualys CI lookup rule explanation workbook, captured the review '
        'points on the rule scripts (record limits on the match queries, the private query match helper) and scoped the '
        'readable rewrite of the sixteen custom rules.'),
    day(date(2026, 8, 14), 0, 9, 0, 9, 'Sick Leave', 'Absence',
        'Sick leave - no project activity (Deloitte T&E: SLV Sick Leave 9.00h).'),
])

WEEK_2 = dict(ending=date(2026, 8, 22), vdi=True, days=[
    day(date(2026, 8, 17), 8, 0, 3, 0, 'Analysis', 'SNOWUSEMTP-581',
        'Analysis - SNOWUSEMTP-581: offline preparation for the AIT manual ingestion build; defined the import table '
        'columns from the pentest findings sheet (application, AIT, risk rating, CWE category, affected functionality, '
        'steps to reproduce, recommendation) and the AIT to business application lookup approach.' + VDI),
    day(date(2026, 8, 18), 8, 0, 3, 0, 'Configurations', 'SNOWUSEMTP-581',
        'Configurations - SNOWUSEMTP-581: built the manual ingestion import set table, Excel data source and transform '
        'map for pentest findings, with the AIT to business application, AIT to application CI and hostname lookup rules '
        'and the placeholder CI property; loaded the sample workbooks.' + VDI),
    day(date(2026, 8, 19), 8, 0, 3, 0, 'Analysis', 'SNOWUSEMTP-581',
        'Analysis - SNOWUSEMTP-581: end-to-end run of the manual ingestion with a 30-row pentest workbook, checking '
        'application vulnerable item creation, AIT resolution and hostname matches; captured the build into the Global '
        'and Vulnerability Response update sets.' + VDI),
    day(date(2026, 8, 20), 8, 0, 3, 0, 'Configurations', 'SNOWUSEMTP-1003',
        'Configurations - SNOWUSEMTP-1003: built the peer review trigger for Configuration Compliance test results '
        '(Peer reviewed flag, business rule and USEMPeerReviewRuleRunner script include) and retested with result group '
        'fixtures; update set completed.' + VDI),
    day(date(2026, 8, 21), 8, 0, 3, 0, 'Configurations', 'Request Exception deferral limits',
        'Configurations - Request Exception: implemented reason-based deferral limits on the exception request in the '
        'Exception Management scope and exercised two exception requests through the approval chain; update set '
        'completed.' + VDI),
])

WEEK_3 = dict(ending=date(2026, 8, 29), days=[
    day(date(2026, 8, 24), 8, 0, 8, 0, 'Analysis', 'Remediation Task CC',
        'Analysis - Remediation Task CC: requirement review for the Trident resolve gate that requires a closure '
        'attachment, walking the workspace Resolve modal, the Request Closure UI action and the result group close path '
        'to place the check without touching baseline records.'),
    day(date(2026, 8, 25), 8, 0, 8, 0, 'Configurations', 'Remediation Task CC',
        'Configurations - Remediation Task CC: built the resolve gate on Trident result groups (workspace Resolve modal '
        'guard and Request Closure UI action require a resolution attachment), tested with and without the attachment; '
        'update set completed in the Configuration Compliance scope.'),
    day(date(2026, 8, 26), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1420',
        'Configurations - SNOWUSEMTP-1420: consolidated the Trident closure business rules (closure approval gate, '
        'reopen window, approval cancel on reopen) onto the TridentClosureUtil script include, added the governance '
        'group property and aligned the Trident Closure Approval flow; full approval cycle regression. V2.0 delivered.'),
    day(date(2026, 8, 27), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1420',
        'Configurations - SNOWUSEMTP-1420: fixed the re-request path so a second closure request after a rejection '
        'raises a fresh approval cycle, retested approve, reject and re-request sequences with the governance '
        'approvers. V2.1 delivered.'),
    day(date(2026, 8, 28), 0, 8, 0, 8, 'Holiday', 'Firm holiday',
        'Holiday - no project activity (Deloitte T&E: HOL Holiday 8.00h).'),
])

WEEK_4 = dict(ending=date(2026, 9, 5), days=[
    day(date(2026, 8, 31), 0, 8, 0, 8, 'Sick Leave', 'Absence',
        'Sick leave - no project activity (Deloitte T&E: SLV Sick Leave 8.00h).'),
    day(date(2026, 9, 1), 8, 0, 8, 0, 'Analysis', 'SNOWUSEMTP-1420',
        'Analysis - SNOWUSEMTP-1420: root-caused the approval retrigger defect on Resolved with Pending Approval (the '
        'flow trigger fires once per unique change, so a repeat resolve left the task without an approval) and designed '
        'the single lifecycle rule covering every State and Reason transition.'),
    day(date(2026, 9, 2), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1420',
        'Configurations - SNOWUSEMTP-1420: replaced the Trident closure rules with the single BOFA Trident closure '
        'lifecycle rule, retested every ordered state pair and Reason transition with approval rows and the '
        'normalisation fix script. V2.3 delivered. Started the P3.17 weekly Vulnerabilities Summary notification.'),
    day(date(2026, 9, 3), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP.26.P3.17',
        'Configurations - SNOWUSEMTP.26.P3.17: built the VulnSummaryDigestUtil script include, event, mail script and '
        'weekly scheduled job that send each application manager a summary of open findings across vulnerable items, '
        'application vulnerable items and container images, tested with active and inactive owners. V1.1 delivered. '
        'Began the SNOWUSEMTP-1625 CDP payload builder.'),
    day(date(2026, 9, 4), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1625',
        'Configurations - SNOWUSEMTP-1625: completed the RemediationTaskPayloadBuilder script include and the four '
        'per-table field mapping properties for the Kafka outbound remediation task payload, tested across the four '
        'remediation task tables. V2.2 delivered. Re-captured the sixteen Qualys CI lookup rules (SNOWUSEMTP-895) with '
        'the stage comments into V2.2.'),
])

WEEK_5 = dict(ending=date(2026, 9, 12), days=[
    day(date(2026, 9, 7), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-895',
        'Configurations - SNOWUSEMTP-895: built the read-only diagnosis harness for the unmatched Qualys hosts and '
        'profiled the unmatched population; added three CI lookup rules for the groups the chain could not place '
        '(management controllers, network device interfaces and VLANs, load balancer virtual IPs), each accepting a CI '
        'only when exactly one candidate remains; proved the chain on nine real unmatched discovered items, all matched. '
        'V3.0 captured in a Global update set.'),
    day(date(2026, 9, 8), 8, 0, 8, 0, 'Design', 'Primary AIT resolution',
        'Design - Primary AIT resolution: design proposal for resolving the Primary AIT and application manager on '
        'findings, with benchmarks of the stamping options across vulnerable items, application vulnerable items and '
        'container image vulnerable items; recommendation and trade-offs documented for review.'),
    day(date(2026, 9, 9), 8, 0, 8, 0, 'Documentation', 'SNOWUSEMTP-895',
        'Documentation - SNOWUSEMTP-895: rewrote the comments on all nineteen Qualys CI lookup rules as short first-hand '
        'notes (sample payload in every header, each matching stage walking the sample through, no order numbers), '
        'moved the suffix, marker and product lists inline into the three new rules and retired the six lookup '
        'properties, and produced the 43-slide technical walkthrough deck. V2.4 and V3.4 delivered; chain behaviour '
        'identical before and after.'),
    day(date(2026, 9, 10), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1625',
        'Configurations - SNOWUSEMTP-1625: standardised the Kafka producer script include for the CDP outbound '
        '(configuration in initialize, topic per table, single error format) and added payload validation ahead of the '
        'send so a malformed message is logged and never published; tested per remediation task table with captured '
        'sends and every refusal path. Wrote up the outbound REST parameter length limits for the Qualys Policy '
        'Compliance integration (setStringParameter, field lengths, request URL) for the story comment.'),
    day(date(2026, 9, 11), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-895',
        'Configurations - SNOWUSEMTP-895: investigated the Cisco IOS router matched to a Computer by the Layered DNS '
        'rule (router CI without fqdn or dns_domain, discovery chain ending on the wrong CI) and added a class-agreement '
        'check to the discovery-chain and hardware-wide rules; retested the case, its variations and the full chain; '
        'update set delivered and reply posted. Folded the payload validation into the Kafka producer, returned the '
        'CDP field mapping properties to the line format, added standard function comments to the producer and payload '
        'builder (V2.5), and produced the plain-English primer on the lookup rules for the demo.'),
])

WEEK_6 = dict(ending=date(2026, 9, 19), days=[
    day(date(2026, 9, 14), 8, 0, 8, 0, 'Analysis', 'SNOWUSEMTP-895',
        'Analysis - SNOWUSEMTP-895: built the read-only measurement script that replays the Qualys CI lookup chain over a '
        'sample of discovered items on the client development instance and reports, per item, the rule that matched, the '
        'agreement between the CI found and the scanned host, and the cause of every decline; across two runs of five '
        'hundred items the chain reproduced 499 matches, and the unmatched population resolved to hosts absent from the '
        'CMDB (87%), class contradictions, duplicate addresses and retired records. Also delivered SNOWUSEMTP-1552: an '
        'application vulnerable item keeps its deferral when the scanner closes and re-opens it, exercised through the '
        'exception request and approval path. V1.0 delivered.'),
    day(date(2026, 9, 15), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-895',
        'Configurations - SNOWUSEMTP-895: closed out the third measurement run with no rule change agreed (retired '
        'records stay candidates by the client design expectation) and delivered three rule sets: appliance acceptance '
        'on the discovery chain and hardware rules with a host name agreement check on the address rules (V1.1), a '
        'device name rule that resolves the contact centre phones and the scanners that sit outside the hardware tree '
        '(V1.0), and the load balancer member rule that walks a virtual server through its pool to the one real server '
        'behind it (V1.0). Re-issued the six rule scripts in the agreed comment layout and swept the client items for '
        'any change in outcome.'),
    day(date(2026, 9, 16), 8, 0, 8, 0, 'Documentation', 'SNOWUSEMTP-895',
        'Documentation - SNOWUSEMTP-895: produced the walkthrough material on the CI lookup rules for the architect '
        'review: a preparation document covering the chain from the discovery rules through to the NetBIOS rule, a '
        'line-by-line explanation of the load balancer member and service rules in everyday words, and flow diagrams of '
        'the member, owner and service rules, each walked through with worked examples taken from real discovered items.'),
    day(date(2026, 9, 17), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-895',
        'Configurations - SNOWUSEMTP-895: reviewed the client load balancer matches (634 items on the service rule, six '
        'on the member rule) and tightened both rules to the exact record standard with no fitness heuristics: the '
        'discovery chain rule refuses a balancer at the end of its chain, several service records carrying one name are '
        'treated as one virtual server recorded more than once, a pool member the CMDB cannot place makes the member '
        'rule decline, and the service rule attaches the virtual server record whenever the machine cannot be named. '
        'V1.2 delivered with the per-item explain script and a per-example walkthrough document for the architect. Also '
        'delivered SNOWUSEMTP-1825 (nineteen classes added to the ignored CI class property in its own scope) and the '
        'certificate class analysis: the relationship export over the 2,370 items on the certificate class showed 244 '
        'leading to a single live device, so those items are re-evaluated with the existing rules and no certificate '
        'rule is added.'),
    day(date(2026, 9, 18), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1804',
        'Configurations - SNOWUSEMTP-1804: built the VAMP outbound for application vulnerable items: the after insert '
        'and update business rule, the payload processor and the Kafka producer script include for the verification '
        'topic, with the topic and the field mapping held in system properties. The payload carries the envelope and one '
        'finding element whose sections are keyed by table name, holding exactly the fields of the mapping sheet with '
        'reference fields sent as display values; the ServiceNow field behind every payload name is resolved on the '
        'instance rather than assumed. Also produced the read-only field check script that reports, per sheet row, the '
        'field found, its type and the rows to raise with the integration team. Tested on findings with and without '
        'related records, on insert and on update. V1.6 delivered.'),
])

WEEK_7 = dict(ending=date(2026, 9, 26), days=[
    day(date(2026, 9, 21), 8, 0, 8, 0, 'Documentation', 'SNOWUSEMTP-895',
        'Documentation - SNOWUSEMTP-895: completed the CMDB team demo deck on the Qualys CI lookup rules from the client run: '
        'for every rule, what it looks for, how the script works and when it declines, one example dedicated to the rule '
        'and step-by-step pages linking every record and filter on the development instance, driven by a read-only trace '
        'script; text boxes sized to the page in the Bank of America palette. Also started SNOWUSEMTP-1624, the consequence '
        'outbound payload to CDP, built in the consequence application with validation and error handling (V1.2).'),
    day(date(2026, 9, 22), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1804',
        'Configurations - SNOWUSEMTP-1804: reworked the VAMP outbound payload to the JSON structure names of the mapping '
        'sheet, covering all remediation task types, with one property holding the sections and fields as in the CDP payloads, '
        'payload validation before the send and the Kafka story comment standard (V2.0). Reviewed the four Kafka outbound '
        'script sets (SNOWUSEMTP-1625, the Kafka producer, SNOWUSEMTP-1624 and SNOWUSEMTP-1804) and fixed and re-tested the '
        'findings of the review.'),
    day(date(2026, 9, 23), 8, 0, 8, 0, 'Configurations', 'SNOWUSEMTP-1624',
        'Configurations - SNOWUSEMTP-1624 / SNOWUSEMTP-1625: merged the Kafka producers into one script include called by the '
        'business rules on consequences, remediation tasks and vulnerable items, with the topic property chosen by the '
        'record\'s table, a synchronous send and the Kafka response shown on the record; restored the missing-field and '
        'payload messages in the processors. Delivered producer V1.5, consequence outbound V1.5 and VAMP outbound V2.3, each '
        'tested and previewed on import. Began SNOWUSEMTP-1639 with an analysis of the CDP IVR inbound build and the '
        'questions for the VAMP team, with the blockers marked.'),
    day(date(2026, 9, 24), 8, 0, 8, 0, 'Documentation', 'SNOWUSEMTP-1639',
        'Documentation - SNOWUSEMTP-1639: produced the architecture overview of the CDP IVR inbound build (Kafka topic, '
        'stream, script consumer, import set, transform map and Detection API, with a link to every record on the '
        'development instance) and a companion document explaining the three transform map scripts step by step, from the '
        'staging row through host matching and the Detection API to the vulnerable item, with the questions the team is '
        'likely to raise answered from the code.'),
    day(date(2026, 9, 25), 8, 0, 8, 0, 'Design', 'SNOWUSEMTP-2125',
        'Design - SNOWUSEMTP-2125: designed the architecture for bringing VAMP findings into Application Vulnerability '
        'Response over Hermes: script consumer and import set feeding a transform map whose scripts call the out-of-box AVR '
        'import API for the application release, application vulnerability entry and application vulnerable item, with the '
        'pen test assessment request handled by a lookup-or-create since no out-of-box API covers it. Delivered the diagram '
        'with the table of out-of-box code used, not used and not usable.'),
])

FILES = [
    dict(file='BofA_USEM_Timecard_10Aug21Aug_2026.xlsx', weeks=[WEEK_1, WEEK_2],
         notes_footer='Week ending 15-Aug carries a single Project line Mon to Thu and a Sick line on Fri 14-Aug (9.00h). '
                      'Week ending 22-Aug is capped at 3.00h of project work per day because VDI access was unavailable; '
                      'see the Reconciliation sheet for the resulting variance against the Deloitte T&E.',
         recon_intro='Deloitte is the system of record. Every daily and weekly total below is computed live. '
                     'SN Project + SN Training = Deloitte Worked. SN Sick = Deloitte Absence. Week ending 22-Aug is capped at '
                     '3.00h per day on the ServiceNow side (VDI unavailable), so those five days and that subtotal read CHECK by design.',
         recon_notes=[
             'Source of record: Deloitte T&E timesheets, weeks ending 15-Aug-2026 and 22-Aug-2026 (both showing Timesheet is approved).',
             'Week ending 15-Aug: Mon to Thu 8.00h on the India Kolkata worked line, Fri 14-Aug 9.00h SLV Sick Leave, Sat 15-Aug 0.00 (firm holiday on a non-working day); weekly 41.00, Worked 32.00, Absence 9.00.',
             'Week ending 22-Aug: Deloitte shows Mon to Fri 8.00h worked (40.00, Absence 0.00). VDI access was unavailable all week, so the ServiceNow card carries a maximum of 3.00h of project work per day; the 5.00h daily gap against Deloitte is expected and is what the CHECK flags show.',
             'Mapping rule: SN Project + SN Training reconcile to Deloitte Worked; SN Sick reconciles to Deloitte Absence; daily and weekly totals are identical except for the week ending 22-Aug noted above.',
             'Activity notes are drawn from the engagement work on SNOWUSEMTP-895 (Qualys CI lookup rules), SNOWUSEMTP-581 (AIT manual ingestion), SNOWUSEMTP-1003 (peer review on test records) and the Request Exception deferral limits.',
         ]),
    dict(file='BofA_USEM_Timecard_24Aug04Sep_2026.xlsx', weeks=[WEEK_3, WEEK_4],
         notes_footer='Week ending 29-Aug carries a single Project line Mon to Thu and a Holiday line on Fri 28-Aug (8.00h). '
                      'Week ending 05-Sep carries a Sick line on Mon 31-Aug (8.00h) and a single Project line Tue to Fri. '
                      'See the Reconciliation sheet for the line-by-line tie-out.',
         recon_intro='Deloitte is the system of record. Every daily and weekly total below is computed live and must read MATCH. '
                     'SN Project + SN Training = Deloitte Worked. SN Sick / Holiday = Deloitte Absence. Each week carries one absence day.',
         recon_notes=[
             'Source of record: Deloitte T&E timesheets, weeks ending 29-Aug-2026 and 05-Sep-2026 (both showing Timesheet is approved).',
             'Week ending 29-Aug: Mon to Thu 8.00h on the India Kolkata worked line, Fri 28-Aug 8.00h HOL Holiday; weekly 40.00, Worked 32.00, Absence 8.00.',
             'Week ending 05-Sep: Mon 31-Aug 8.00h SLV Sick Leave, Tue to Fri 8.00h on the India Kolkata worked line; weekly 40.00, Worked 32.00, Absence 8.00.',
             'Mapping rule: SN Project + SN Training reconcile to Deloitte Worked; SN Sick / Holiday reconciles to Deloitte Absence; daily and weekly totals are identical.',
             'Activity notes are drawn from the engagement work on the Trident resolve gate, SNOWUSEMTP-1420 (Trident closure governance), SNOWUSEMTP.26.P3.17 (weekly Vulnerabilities Summary) and SNOWUSEMTP-1625 (CDP remediation task payload).',
         ]),
    dict(file='BofA_USEM_Timecard_07Sep11Sep_2026.xlsx', weeks=[WEEK_5],
         notes_footer='Week ending 12-Sep carries a single Project line Mon to Fri (8.00h each). See the Reconciliation sheet for the '
                      'line-by-line tie-out; the Deloitte columns hold the planned 8.00h per day until the approved T&E is available.',
         recon_intro='Deloitte is the system of record. Every daily and weekly total below is computed live and must read MATCH. '
                     'SN Project + SN Training = Deloitte Worked. SN Sick = Deloitte Absence. The Deloitte columns hold the planned '
                     '8.00h per day for the week ending 12-Sep; replace them with the approved T&E figures when available.',
         recon_notes=[
             'Source of record: Deloitte T&E timesheet, week ending 12-Sep-2026 (Deloitte columns entered as the planned 8.00h per day; confirm against the approved timesheet).',
             'Week ending 12-Sep: Mon to Fri 8.00h on the India Kolkata worked line; weekly 40.00, Worked 40.00, Absence 0.00.',
             'Mapping rule: SN Project + SN Training reconcile to Deloitte Worked; SN Sick reconciles to Deloitte Absence; daily and weekly totals are identical.',
             'Activity notes are drawn from the engagement work on SNOWUSEMTP-895 (Qualys CI lookup rules), the Primary AIT resolution design and SNOWUSEMTP-1625 (CDP remediation task payload and Kafka producer).',
         ]),
    dict(file='BofA_USEM_Timecard_14Sep18Sep_2026.xlsx', weeks=[WEEK_6],
         notes_footer='Week ending 19-Sep carries a single Project line Mon to Fri (8.00h each). See the Reconciliation sheet for the '
                      'line-by-line tie-out; the Deloitte columns hold the planned 8.00h per day until the approved T&E is available.',
         recon_intro='Deloitte is the system of record. Every daily and weekly total below is computed live and must read MATCH. '
                     'SN Project + SN Training = Deloitte Worked. SN Sick = Deloitte Absence. The Deloitte columns hold the planned '
                     '8.00h per day for the week ending 19-Sep; replace them with the approved T&E figures when available.',
         recon_notes=[
             'Source of record: Deloitte T&E timesheet, week ending 19-Sep-2026 (Deloitte columns entered as the planned 8.00h per day; confirm against the approved timesheet).',
             'Week ending 19-Sep: Mon to Fri 8.00h on the India Kolkata worked line; weekly 40.00, Worked 40.00, Absence 0.00.',
             'Mapping rule: SN Project + SN Training reconcile to Deloitte Worked; SN Sick reconciles to Deloitte Absence; daily and weekly totals are identical.',
             'Activity notes are drawn from the engagement work on SNOWUSEMTP-895 (Qualys CI lookup rules and the load balancer refinements), SNOWUSEMTP-1552 (deferral kept on scanner reopen), SNOWUSEMTP-1825 (ignored CI classes) and SNOWUSEMTP-1804 (VAMP outbound payload).',
         ]),
    dict(file='BofA_USEM_Timecard_21Sep25Sep_2026.xlsx', weeks=[WEEK_7],
         notes_footer='Week ending 26-Sep carries a single Project line Mon to Fri (8.00h each). See the Reconciliation sheet for the '
                      'line-by-line tie-out; the Deloitte columns hold the planned 8.00h per day until the approved T&E is available.',
         recon_intro='Deloitte is the system of record. Every daily and weekly total below is computed live and must read MATCH. '
                     'SN Project + SN Training = Deloitte Worked. SN Sick = Deloitte Absence. The Deloitte columns hold the planned '
                     '8.00h per day for the week ending 26-Sep; replace them with the approved T&E figures when available.',
         recon_notes=[
             'Source of record: Deloitte T&E timesheet, week ending 26-Sep-2026 (Deloitte columns entered as the planned 8.00h per day; confirm against the approved timesheet).',
             'Week ending 26-Sep: Mon to Fri 8.00h on the India Kolkata worked line; weekly 40.00, Worked 40.00, Absence 0.00.',
             'Mapping rule: SN Project + SN Training reconcile to Deloitte Worked; SN Sick reconciles to Deloitte Absence; daily and weekly totals are identical.',
             'Activity notes are drawn from the engagement work on SNOWUSEMTP-895 (lookup rules demo deck), SNOWUSEMTP-1624 and SNOWUSEMTP-1625 (consequence outbound and the merged Kafka producer), SNOWUSEMTP-1804 (VAMP outbound), SNOWUSEMTP-1639 (VAMP inbound analysis) and SNOWUSEMTP-2125 (VAMP into Application Vulnerability Response).',
         ]),
]


# ---------------------------------------------------------------- styling helpers
def font(size=10, bold=False, color=BLACK):
    return Font(name='Arial', size=size, bold=bold, color=color)


def fill(rgb):
    return PatternFill(fill_type='solid', fgColor=rgb, bgColor=rgb)


def put(ws, ref, value=None, f=None, bg=None, h='left', v='center', wrap=False, border=False, numfmt=None):
    c = ws[ref]
    if value is not None:
        c.value = value
    c.font = f or font()
    if bg:
        c.fill = fill(bg)
    c.alignment = Alignment(horizontal=h, vertical=v, wrap_text=wrap)
    if border:
        c.border = BORDER
    if numfmt:
        c.number_format = numfmt
    return c


def band(ws, row, first, last, value=None, f=None, bg=None, h='left', wrap=False, border=False, merge=True):
    """Style every cell of a row span (and merge it) so a merged title / note row renders uniformly."""
    for col in range(first, last + 1):
        put(ws, '%s%d' % (get_column_letter(col), row), f=f, bg=bg, h=h, wrap=wrap, border=border)
    ws['%s%d' % (get_column_letter(first), row)].value = value
    if merge:
        ws.merge_cells(start_row=row, start_column=first, end_row=row, end_column=last)


def widths(ws, spec):
    for col, w in spec.items():
        ws.column_dimensions[col].width = w


def period_text(weeks):
    return '%s to %s' % (fmt(weeks[0]['days'][0]['date']), fmt(weeks[-1]['days'][-1]['date']))


def short_period(weeks):
    return '%s to %s' % (weeks[0]['days'][0]['date'].strftime('%d-%b'), weeks[-1]['days'][-1]['date'].strftime('%d-%b'))


# ---------------------------------------------------------------- sheet 1: Daily Notes
def sheet_notes(wb, spec):
    ws = wb.active
    ws.title = 'Daily Notes (Copy-Paste)'
    weeks = spec['weeks']
    band(ws, 1, 1, 5, 'ServiceNow Time Card  |  Daily Notes, one day per cell', font(14, True, WHITE), NAVY)
    band(ws, 2, 1, 5,
         'Period: %s   |   %s, %s   |   %s, AIT %s   |   JIRA: SNOWUSEMTP.  Format per ServiceNow time-card guidance: '
         '[Line] - [Outcome]. Copy a single cell into that day\'s time-card comment. Daily hours tie to the Deloitte system of record.'
         % (period_text(weeks), PERSON, ROLE, ENGAGEMENT, AIT), font(9), wrap=True)
    heads = ['Date', 'Day', 'Hours', 'Time Card Line', 'Time Card Note  (copy one cell per day into ServiceNow)']
    for i, hname in enumerate(heads, 1):
        put(ws, '%s4' % get_column_letter(i), hname, font(10, True, WHITE), NAVY, 'left' if i == 5 else 'center', wrap=True, border=True)
    r = 5
    for w in weeks:
        for i, d in enumerate(w['days']):
            bg = ALT if i % 2 else None
            put(ws, 'A%d' % r, fmt(d['date']), bg=bg, h='center', border=True)
            put(ws, 'B%d' % r, d['date'].strftime('%a'), bg=bg, h='center', border=True)
            put(ws, 'C%d' % r, d['project'] + d['training'] + d['sick'], bg=bg, h='center', border=True, numfmt='0.00')
            put(ws, 'D%d' % r, d['line'], bg=bg, wrap=True, border=True)
            put(ws, 'E%d' % r, d['note'], bg=bg, wrap=True, border=True)
            ws.row_dimensions[r].height = 57.75
            r += 1
    r += 1
    band(ws, r, 1, 5, spec['notes_footer'], font(8.5, color=GREY), wrap=True)
    ws.row_dimensions[r].height = 25.5
    ws.row_dimensions[1].height = 25.5
    ws.row_dimensions[2].height = 31.5
    ws.row_dimensions[4].height = 19.5
    widths(ws, {'A': 13, 'B': 7, 'C': 9, 'D': 22, 'E': 104})
    ws.freeze_panes = 'A5'
    return ws


# ---------------------------------------------------------------- sheet 2: Daily Timecard
def sheet_timecard(wb, spec):
    ws = wb.create_sheet('ServiceNow Daily Timecard')
    weeks = spec['weeks']
    band(ws, 1, 1, 7, 'ServiceNow Time Card  |  Daily Activity Log', font(14, True, WHITE), NAVY)
    band(ws, 2, 1, 7, 'Resource: %s   |   Role: Security Engineer III (L45), Kolkata   |   Engagement: %s   |   AIT: %s   |   Team: %s'
         % (PERSON, ENGAGEMENT, AIT, TEAM), font(9))
    band(ws, 3, 1, 7, 'Period: %s   |   JIRA Project: SNOWUSEMTP   |   Notes format per ServiceNow time-card guidance: [Line] - [Outcome]'
         % period_text(weeks), font(9))
    heads = ['Week Ending', 'Date', 'Day', 'Activity Type', 'Story / Reference', 'Hours', 'Timecard Notes']
    for i, hname in enumerate(heads, 1):
        put(ws, '%s5' % get_column_letter(i), hname, font(10, True, WHITE), NAVY, 'center', wrap=True, border=True)
    r = 6
    subtotal_rows = []
    for w in weeks:
        first = r
        for i, d in enumerate(w['days']):
            bg = ALT if i % 2 else None
            put(ws, 'A%d' % r, fmt(w['ending']), font(9.5), bg, wrap=True, border=True)
            put(ws, 'B%d' % r, fmt(d['date']), font(9.5), bg, 'center', border=True)
            put(ws, 'C%d' % r, d['date'].strftime('%a'), font(9.5), bg, 'center', border=True)
            put(ws, 'D%d' % r, d['kind'], font(9.5), bg, wrap=True, border=True)
            put(ws, 'E%d' % r, d['ref'], font(9.5), bg, wrap=True, border=True)
            put(ws, 'F%d' % r, d['project'] + d['training'] + d['sick'], font(9.5), bg, 'center', border=True, numfmt='0.00')
            put(ws, 'G%d' % r, d['note'], font(9.5), bg, wrap=True, border=True)
            ws.row_dimensions[r].height = 54
            r += 1
        for col in 'ABCDEFG':
            put(ws, '%s%d' % (col, r), f=font(10, True, NAVY_DARK), bg=BAND, border=True)
        put(ws, 'E%d' % r, 'Week ending %s  Subtotal' % fmt(w['ending']), font(10, True, NAVY_DARK), BAND, 'right', border=True)
        put(ws, 'F%d' % r, '=SUM(F%d:F%d)' % (first, r - 1), font(10, True, NAVY_DARK), BAND, 'center', border=True, numfmt='0.00')
        ws.row_dimensions[r].height = 18
        subtotal_rows.append(r)
        r += 2
    for col in 'ABCDEFG':
        put(ws, '%s%d' % (col, r), f=font(11, True, WHITE), bg=NAVY, border=True)
    put(ws, 'E%d' % r, 'GRAND TOTAL (%s)' % short_period(weeks), font(11, True, WHITE), NAVY, 'right', border=True)
    put(ws, 'F%d' % r, '=' + '+'.join('F%d' % s for s in subtotal_rows), font(11, True, WHITE), NAVY, 'center', border=True, numfmt='0.00')
    ws.row_dimensions[r].height = 21.75
    for row, hgt in ((1, 25.5), (2, 15), (3, 15), (5, 19.5)):
        ws.row_dimensions[row].height = hgt
    widths(ws, {'A': 15, 'B': 13, 'C': 7, 'D': 17, 'E': 26, 'F': 9, 'G': 92})
    ws.freeze_panes = 'A6'
    return ws


# ---------------------------------------------------------------- sheet 3: Deloitte Reconciliation
def sheet_recon(wb, spec):
    ws = wb.create_sheet('Deloitte Reconciliation')
    weeks = spec['weeks']
    holiday = any(d['kind'] == 'Holiday' for w in weeks for d in w['days'])
    band(ws, 1, 1, 10, 'Reconciliation:  Deloitte T&E  vs  ServiceNow Time Card', font(14, True, WHITE), NAVY)
    band(ws, 2, 1, 10, spec['recon_intro'], font(9), wrap=True)
    heads = ['Date', 'Day', 'Deloitte Worked\n(India Kolkata)', 'Deloitte\nAbsence', 'Deloitte\nTotal', 'SN Project',
             'SN Training', 'SN Sick /\nHoliday' if holiday else 'SN Sick', 'SN\nTotal', 'Match']
    for i, hname in enumerate(heads, 1):
        put(ws, '%s4' % get_column_letter(i), hname, font(9.5, True, WHITE), NAVY, 'center', wrap=True, border=True)
    r = 5
    subtotal_rows = []

    def match(row):
        return '=IF(AND(E{r}=I{r},C{r}=F{r}+G{r},D{r}=H{r}),"MATCH","CHECK")'.format(r=row)

    for w in weeks:
        band(ws, r, 1, 10, 'Week ending %s' % fmt(w['ending']), font(10, True, WHITE), NAVY_DARK)
        ws.row_dimensions[r].height = 18
        r += 1
        first = r
        for i, d in enumerate(w['days']):
            bg = ALT if i % 2 else None
            put(ws, 'A%d' % r, fmt(d['date']), font(9.5), bg, 'center', border=True)
            put(ws, 'B%d' % r, d['date'].strftime('%a'), font(9.5), bg, 'center', border=True)
            for col, val in (('C', d['worked']), ('D', d['absence']), ('E', '=C%d+D%d' % (r, r)),
                             ('F', d['project']), ('G', d['training']), ('H', d['sick']), ('I', '=F%d+G%d+H%d' % (r, r, r))):
                put(ws, '%s%d' % (col, r), val, font(9.5), bg, 'center', border=True, numfmt='0.00')
            put(ws, 'J%d' % r, match(r), font(9.5), bg, 'center', border=True)
            ws.row_dimensions[r].height = 15
            r += 1
        for col in 'ABCDEFGHIJ':
            put(ws, '%s%d' % (col, r), f=font(10, True, NAVY_DARK), bg=BAND, border=True)
        put(ws, 'A%d' % r, 'Subtotal', font(10, True, NAVY_DARK), BAND, 'right', border=True)
        for col in 'CDEFGHI':
            put(ws, '%s%d' % (col, r), '=SUM(%s%d:%s%d)' % (col, first, col, r - 1), font(10, True, NAVY_DARK), BAND, 'center', border=True, numfmt='0.00')
        put(ws, 'J%d' % r, match(r), font(10, True, NAVY_DARK), BAND, 'center', border=True)
        ws.row_dimensions[r].height = 18
        subtotal_rows.append(r)
        r += 1
    r += 1
    for col in 'ABCDEFGHIJ':
        put(ws, '%s%d' % (col, r), f=font(11, True, WHITE), bg=NAVY, border=True)
    put(ws, 'A%d' % r, 'GRAND TOTAL', font(11, True, WHITE), NAVY, 'right', border=True)
    for col in 'CDEFGHI':
        put(ws, '%s%d' % (col, r), '=' + '+'.join('%s%d' % (col, s) for s in subtotal_rows), font(11, True, WHITE), NAVY, 'center', border=True, numfmt='0.00')
    put(ws, 'J%d' % r, match(r), font(11, True, WHITE), NAVY, 'center', border=True)
    ws.row_dimensions[r].height = 21.75
    r += 2
    for text in spec['recon_notes']:
        band(ws, r, 1, 10, text, font(8.5, color=GREY), wrap=True)
        ws.row_dimensions[r].height = 13.5 if len(text) < 130 else 27
        r += 1
    ws.row_dimensions[1].height = 25.5
    ws.row_dimensions[2].height = 27.75
    ws.row_dimensions[4].height = 30
    widths(ws, {'A': 12, 'B': 7, 'C': 15, 'D': 11, 'I': 9, 'J': 11})
    ws.freeze_panes = 'A5'
    return ws


def build(spec):
    wb = Workbook()
    wb.properties.creator = PERSON
    wb.properties.lastModifiedBy = PERSON
    sheet_notes(wb, spec)
    sheet_timecard(wb, spec)
    sheet_recon(wb, spec)
    out = os.path.join(HERE, spec['file'])
    wb.save(out)
    return out


if __name__ == '__main__':
    import sys
    targets = sys.argv[1:]
    for spec in FILES:
        if not targets or spec['file'] in targets:
            print(build(spec))
