# Primary AIT resolution at scale

A design for keeping the Primary AIT of every discovered item and CI correct in near real time without walking the CMDB graph per record.

## 1. Why the current build is slow

Today the Primary AIT is derived per discovered item (DI), and it is derived by walking the CMDB graph:

    DI -> CI -> svc_ci_assoc (both ends) -> application services -> business applications -> AITs -> lowest RTO tier
                fallback: CI -> cmdb_rel_ci (both directions) -> the same walk again

That walk is the expensive unit of work. It costs tens of queries and, on a CMDB of production size, tens to hundreds of milliseconds per DI. The two mechanisms in place both multiply that unit:

| Mechanism | Unit of work | Times executed | Effect |
|---|---|---|---|
| Business rule on each DI table, on CI change | one graph walk | once per DI change (every import touches DIs) | import throughput drops; the walk runs inside the import transaction |
| Scheduled job | one graph walk | once per DI, every run | run time grows linearly with the DI count; hours for millions of DIs; the result is only as fresh as the last run |

The four options discussed (CI-level field with a validator; one big job in 500k chunks; a rule that detects an AIT change and a job for the affected DIs; the same job spread across nodes) all keep the graph walk as the unit and change only how often or how widely it runs. That is why none of them is both fast and current: parallelism and chunking divide a cost that is too large to begin with.

The rest of this document removes the cost first and parallelises second.

## 2. The principle

Three observations drive the design.

1. **The facts that decide a Primary AIT live above the DI.** Which services a CI belongs to, which business applications a service supports, which AIT an application belongs to, and what RTO tier that AIT has. A DI adds nothing to the decision except *which CI* it points at. Deriving the answer per DI recomputes the same result thousands of times (every DI of a CI, every CI of a service).
2. **Most changes are small and keyed.** A DI changes its CI (one DI). A CI joins or leaves a service (one CI). An application moves to another AIT (one application, its services, their CIs). An AIT changes tier (one AIT, its applications). Every change has a key that names exactly the records that can be affected. Anything not reachable from the key cannot have changed and must not be touched.
3. **The platform can select rows declaratively.** A GlideRecord query with a dot-walked condition is a join executed in the database. "All DIs whose CI now carries AIT X but which still store something else" is one statement, not a loop.

So: **compute once per key, at the level where the fact lives; propagate downward by key; stamp the leaves in sets; do nothing for records that did not change.** This is the pattern behind spreadsheet recalculation (only dirty cells recompute), incremental view maintenance in databases (a view is patched from the delta, not rebuilt), and social timelines (push the few common updates, batch the rare wide ones).

It is also the pattern the platform already uses for its own equivalent problem. Vulnerability Response keeps "impacted services" on vulnerable items and discovered items with exactly this machinery: a before rule sets a *pending* flag when the CI changes, a job processes only pending records grouped by CI (one walk per distinct CI), the result is written to a copy table of CI-to-service links, and the leaves are stamped per CI with `updateMultiple`. Heavy reads go to the read replica, and the walk itself is the platform's Java traversal (`CIUtils.servicesAffectedByCI`, bounded by depth and size properties). This design applies the same shape to the Primary AIT, one level higher.

## 3. Data model: fields only

No new tables. Every new element is a field on an existing table, indexed where it is queried.

| Table | Field | Type | Purpose |
|---|---|---|---|
| Application service (`cmdb_ci_service` and children) | `u_primary_ait` | reference to AIT | the lowest-tier AIT reachable from this service through its business applications |
| | `u_primary_ait_tier` | integer | copy of that AIT's RTO tier, so comparisons never dot-walk into the AIT table |
| | `u_ait_refresh` | true/false, indexed | dirty flag: the service must be recomputed |
| CI (`cmdb_ci`) | `u_primary_ait` | reference to AIT, indexed | the lowest-tier AIT over the services the CI belongs to (the level that already exists as option 1) |
| | `u_primary_ait_tier` | integer | copy of the tier, for the fast path in section 4.5 |
| | `u_primary_ait_source` | reference to service | which service supplied the winning AIT; lets a service change find only the CIs it can affect |
| | `u_ait_refresh` | true/false, indexed | dirty flag: the CI must be recomputed |
| Discovered item tables (`sn_sec_cmn_src_ci` and the other DI tables) | `u_primary_ait` | exists today | a copy of the CI's value |
| AIT (`x_boar_bofa_techad_ait`) | `u_rto_tier_previous` | integer | previous tier, written by the AIT rule so the fan-out knows whether the tier improved or worsened |

Indexes: `u_primary_ait` on CI and DI tables; composite `(u_ait_refresh, sys_id)` on service and CI so the dirty scans are index seeks; `svc_ci_assoc (ci_id)` and `(service_id)` and `cmdb_rel_ci (parent)`, `(child)` already exist.

Two existing platform assets are reused as indexes instead of walking:

- `svc_ci_assoc` is the authoritative CI-to-service index for mapped services (populated by Service Mapping; up to 10,000 CIs per service by platform limit).
- `sn_vul_m2m_ci_services` (label "Related Services") is the platform's own closure table of CI-to-service links, including relationship-derived ones, maintained by the daily "Set related CI services for VI" job. Where it is populated it replaces the relationship walk entirely; the walk remains only as the fallback for CIs that have no entry.

## 4. Algorithms

Levels are numbered from the source of truth down to the leaves. Each level is a pure function of the level above, which is what makes every step idempotent and safe to re-run.

### 4.1 Level 1, application service: primary AIT of a service

    candidates(service) = AITs of the business applications related to the service
                          (cmdb_rel_ci in both directions, application classes only)
    primary(service)    = the candidate with the lowest RTO tier (deterministic tie-break: AIT number)

This is a handful of indexed reads per service. It is recomputed only when its inputs change:

| Change | Rule | What it marks dirty |
|---|---|---|
| relationship service to application inserted, deleted or re-pointed | after rule on `cmdb_rel_ci`, condition: one end is a service and the other an application | that one service |
| application's AIT reference changes | after rule on the business application, condition: AIT changes | the services related to that application (one keyed query) |
| AIT RTO tier changes | after rule on the AIT, condition: tier changes | the services of every application of that AIT (one keyed query); also stores the previous tier |

Marking dirty is a single `updateMultiple` on the service table with `u_ait_refresh = true` for the keyed set. The rules never compute anything; they only name the work.

### 4.2 Level 2, CI: primary AIT of a CI

    services(ci) = svc_ci_assoc rows where ci_id = ci, plus rows where service_id = ci (the "both ends" case),
                   plus the Related Services closure rows for the CI;
                   if all three are empty: the bounded platform walk CIUtils.servicesAffectedByCI(ci, {maxDepth, maxSize})
    primary(ci)  = the service with the lowest u_primary_ait_tier; its u_primary_ait, tier and sys_id are written to the CI

The fallback walk is the only place the graph is traversed, it is the platform's Java traversal rather than script, it is bounded by the same two properties the platform uses (`sn_sec_cmn.services_affected_by_CI_max_depth`, `_max_size`), and it runs only for CIs that have no index entry at all.

| Change | Rule | What it marks dirty |
|---|---|---|
| `svc_ci_assoc` row inserted or deleted | after rule on `svc_ci_assoc` (insert and delete only) | the CI on the row (both ends if the CI end is itself a service) |
| `cmdb_rel_ci` row touching a non-service CI and a service or application | after rule on `cmdb_rel_ci` | that CI |
| service's primary AIT changed (level 1 wrote a new value) | the level 1 processor itself | the CIs of that service (section 4.5 decides between the fast path and a recompute) |

Service Mapping rewrites `svc_ci_assoc` in bulk when a service model is recalculated. The rule on that table therefore does one thing only, set a flag on one CI, so a mapping run of 10,000 rows costs 10,000 flag writes and no computation; the computation happens once per distinct CI afterwards.

### 4.3 Level 3, discovered item: a copy

    primary(di) = primary(di.cmdb_ci)

Two triggers, neither of which walks anything:

- **The DI's CI changes** (every import). A *before* rule on the DI tables copies the CI's value into the DI in the same write: `current.u_primary_ait = current.cmdb_ci.u_primary_ait`. One indexed read. This replaces the current business rule and removes the graph walk from the import path entirely.
- **The CI's primary AIT changes** (level 2 wrote a new value). The DIs of the affected CIs are stamped in sets, grouped by the new AIT value:

        DIs where cmdb_ci.u_primary_ait = X and (u_primary_ait != X or u_primary_ait is empty)  ->  set u_primary_ait = X

  One statement per distinct AIT value in the batch, however many CIs and DIs are behind it. This is the "club the AITs" idea from the discussion, made concrete: the grouping key is the *value being written*, so the number of statements is bounded by the number of AITs that changed, not by the number of records.

Note two platform behaviours that the statement must respect (both were confirmed by measurement): a `!=` condition does not match rows where the field is empty, so the `or empty` clause is mandatory; and clearing a value through `updateMultiple` requires the literal `NULL`.

### 4.4 The processing engine: dirty flags are the queue

There is no queue table because no queue table is needed: the dirty flags *are* the queue, and they are indexed. A short scheduled job (every 2 to 5 minutes, adjustable) does, in order:

1. Level 1: recompute every service with `u_ait_refresh = true`; for each service whose primary AIT actually changed, apply section 4.5 to its CIs; clear the flag.
2. Level 2: recompute every CI with `u_ait_refresh = true`; collect the CIs whose value actually changed; clear the flag.
3. Level 3: for each distinct new AIT value among the changed CIs, run one DI stamp statement per DI table.

Every step selects by an indexed flag and writes only rows whose value differs, so a run with nothing to do costs a few index seeks. A run after a large change costs the size of the change.

**Parallelism.** The job is partition-aware: it takes a partition parameter and adds `sys_idSTARTSWITH<hex>` to its dirty scans. Eight partitions on eight parallel job records run on whatever nodes have free scheduler workers; sixteen fit a larger cluster. Two platform mechanisms exist for this and both are available without new tables: the Security Support Common background job framework (`ThreadedBackgroundJobProcessor`, which splits a job into partition-aware child jobs on the existing `sn_sec_cmn_background_job` table), or the event Processing Framework with a custom queue in parallel mode (one job per node, scaling with the cluster). The partition key makes the work sets disjoint, so there is nothing to lock; and because every computation is a pure function of the source data, two workers touching neighbouring keys converge to the same values. That is the answer to the race-condition concern raised against multi-node processing: do not share state between workers, and make every write idempotent.

**Immediacy where it matters.** For the paths where minutes are too long, the same processor can be invoked by an event (`gs.eventQueue` on a custom queue) fired by the level 1 rules, so an AIT tier change starts propagating within seconds while the periodic job remains the safety net.

### 4.5 The fast path for AIT tier changes

A tier change is the widest fan-out (one AIT, all its applications, all their services, all their CIs, all their DIs). Because the stored value is a *minimum*, most of that fan-out needs no recomputation:

- **Tier improved (lower number).** Every CI of the affected services whose current tier is worse than the new tier now has this AIT as its primary, without looking at anything else: one statement per service, `CIs in the service with u_primary_ait_tier > newTier -> set u_primary_ait, u_primary_ait_tier, u_primary_ait_source`. CIs already at a better tier are untouched and correct.
- **Tier worsened (higher number).** Only CIs whose primary *is* this AIT can be affected (`u_primary_ait = thisAit`); they are flagged for a level 2 recompute, because another of their services may now win. CIs whose primary is a different AIT are untouched and correct.
- **Tier unchanged, application moved to another AIT.** The affected services are recomputed (level 1); the CIs then follow the two cases above.

This turns the worst case from "everything under the AIT" into "only the rows whose minimum can change", which is the same trick incremental aggregate maintenance uses for MIN and MAX.

### 4.6 Reconciliation and validation (the "something that validates" from option 1)

Derived data drifts when a rule is bypassed (imports with rules off, direct fixes, a failed job). Two cheap, idempotent jobs keep the store honest:

- **Nightly drift stamp.** For each AIT value (thousands, not millions): the section 4.3 statement. Rows already correct are excluded by the condition, so the job's cost is the drift, plus one indexed query per AIT. Measured at 1.4 seconds per AIT over 281,857 DIs when nothing is stale (section 5).
- **Rolling full verification.** Each night, recompute levels 1 and 2 from source for one sixteenth of the services and CIs (by `sys_id` prefix) and compare with the stored values. Every record is re-derived from scratch every sixteen days; disagreements are counted per AIT and fixed in place. This is the validator that option 1 asked for, spread so thinly that it never contends with daily work.
- **Drift report.** A count per AIT of DIs where `cmdb_ci.u_primary_ait = X` and the DI stores something else, published on a dashboard. Expected value after each nightly run: zero.

### 4.7 Fan-out on read: stop storing where you can

The cheapest propagation is the one that never happens. Everywhere a consumer can dot-walk (`cmdb_ci.u_primary_ait` in list views, reports, reference qualifiers, the outbound payload builder, the weekly summary), the value read through the CI is correct the instant the CI changes, with no DI write at all. The stored DI field remains for consumers that need a stored value (integrations that read the DI row, filters that must be indexed), fed by the set-based stamp. Choosing which consumers read through and which read the stored copy is a product decision; the design supports both, and every consumer moved to read-through removes writes.

## 5. Measured behaviour

The mechanics were measured on a developer instance holding 281,857 discovered items and 103,308 CIs. The graph on that instance is tiny (253 service associations), so the walk cost is a floor, not a production estimate.

| Measurement | Result |
|---|---|
| Platform walk CI to services (`CIUtils.servicesAffectedByCI`), 93 CIs | 21.6 ms per CI on a near-empty graph |
| Stamp a CI-level reference field on 100,001 CIs, rules off | 296 s (2.96 ms per row; CMDB tables update row by row because of the class hierarchy and audit) |
| Stamp 11,136 DIs from their CI's value, one statement, rules off | 25.6 s (2.29 ms per row; the DI table is audited, so the statement runs row by row) |
| The same statement when nothing is stale (idempotent re-run) | 1.4 s for the query over 281,857 rows, no writes |
| Drift count for one AIT | 1.4 s |
| Simulated AIT change: 2,001 CIs re-pointed, then their 2,004 DIs re-stamped | 6.2 s + 4.1 s |
| Per-record loop, rules off, 2,000 DIs | 3.9 s (1.96 ms per row) |
| Per-record loop, rules on, 300 DIs | 1.3 s (4.31 ms per row) |

What the numbers say:

- The set-based statement is not magic on an audited table: it costs the same 2 ms per row as a rules-off loop. Its value is that it selects only the stale rows in the database, carries no per-row script, and needs no graph walk per row. On a table that is not audited (or with the DI table's audit whitelist emptied for this field) the same statement becomes a single SQL update.
- Business rules double the per-row cost even when they do little. Keeping the DI before rule to a single dot-walk read is what keeps imports fast.
- Even on an almost empty graph the walk costs ten times a stamp. On a production CMDB the ratio is far larger, which is why the walk must run once per dirty CI, never per DI.
- Reconciliation over hundreds of thousands of rows is a matter of seconds when nothing changed, because the condition excludes correct rows before any write.

## 6. Cost model

W = cost of one graph walk (tens to hundreds of ms in production). N = number of DIs. A change of type T touches S services, C CIs and D DIs.

| Event | Current build | This design |
|---|---|---|
| DI changes its CI (every import) | W, inside the import | one indexed read, inside the import |
| CI joins or leaves a service | nothing until the job; then N × W | one flag write; C = 1 recompute; D stamps of 2 ms |
| Application moves to another AIT | nothing until the job; then N × W | S recomputes; C fast-path or recompute; D stamps, grouped by AIT value |
| AIT tier changes | nothing until the job; then N × W | S recomputes; only CIs whose minimum can change; D stamps; parallel across partitions |
| Nothing changed | N × W on every run | a few index seeks per partition |
| Nightly validation | N × W | one statement per AIT plus one sixteenth of the CIs re-derived |

Illustration at production-like scale, with assumed figures (to be replaced by real counts): 3,000,000 DIs, 500,000 CIs, 20,000 services, 5,000 AITs, W = 100 ms. The current full job is 3,000,000 × 100 ms, about 83 hours of single-threaded work, which is why it can only run in chunks and is never current. In this design an AIT tier change that reaches 10 services, 5,000 CIs and 30,000 DIs costs roughly 10 small recomputes, 5,000 CI writes (15 s) and 30,000 DI writes (60 s), about 75 s single-threaded and under 20 s across four partitions, starting within seconds of the change. A normal day of imports costs one indexed read per DI written and nothing else.

## 7. How this maps to the four options

| Option discussed | Verdict |
|---|---|
| 1. Keep the Primary AIT on each CI in the CMDB and validate it | Adopted as level 2, with the service level above it so the CI value is a one-level minimum, and with the rolling verification of section 4.6 as the validator |
| 2. Load all AITs and run one job, 500k records at a time | Replaced. A full recompute remains only as the sixteenth-per-night verification; the operational path never recomputes what did not change |
| 3. A rule that detects an AIT change and a job for the affected DIs | Generalised into keyed invalidation at every level (service, CI, DI), with the fast path for tier changes |
| 4. The same job spread across nodes | Adopted for the processor and for the DI stamps, after the work has been reduced; partitions by `sys_id` prefix make the workers independent |

## 8. Implementation outline

1. **Fields and indexes** (section 3). Create the CI-level and service-level fields; index them; add the previous-tier field on the AIT.
2. **Resolver script include** (`AitResolutionUtil`): `serviceCandidates(service)`, `resolveService(service)`, `ciServices(ci)`, `resolveCi(ci)`, `stampDiscoveredItems(aitIds)`, `processPartition(partition)`, `verifyPartition(partition)`. One try/catch per entry point, one error format. Lists (application classes, DI tables to stamp, walk depth and size, partitions, batch sizes) in system properties.
3. **Rules** (all after rules, all of them only set flags or copy one value): on `cmdb_rel_ci`, `svc_ci_assoc`, the business application, the AIT; the before rule on each DI table replacing the current one.
4. **Processor job** (every few minutes, N partitions) and **nightly jobs** (drift stamp, rolling verification, drift report). Where the background job framework is preferred, register the processor as a partition-aware job configuration and let it create the child jobs.
5. **Cut-over.** Run the nightly drift stamp once as the initial load (it fills empty values at 2 ms per row, partitioned), switch the DI rules, retire the old job, keep the old script include for a release as a manual fallback.
6. **Guardrails.** The statements bypass business rules and audit on purpose (derived data); no other rule may depend on the DI field changing. Conditions are null-safe. Clearing uses the literal `NULL`. A Service Mapping recalculation is recognised as a burst of flag writes and nothing else. Job run time and drift counts are the two health metrics.

## 9. Reference code

Before rule on each DI table (replaces the current rule; runs on insert and on CI change):

    (function executeRule(current, previous) {
        current.u_primary_ait = current.cmdb_ci.u_primary_ait;
    })(current, previous);

After rule on the AIT (condition: RTO tier changes):

    (function executeRule(current, previous) {
        current.u_rto_tier_previous = previous.rto_tier;      // the fan-out reads it
        var svc = new GlideRecord('cmdb_ci_service');
        svc.addEncodedQuery('sys_idIN' + new AitResolutionUtil().servicesOfAit(current.getUniqueValue()));
        svc.setValue('u_ait_refresh', true);
        svc.updateMultiple();
    })(current, previous);

Discovered item stamp, one statement per new AIT value and DI table:

    stampDiscoveredItems: function(aitId, table) {
        var di = new GlideRecord(table);
        di.addEncodedQuery('cmdb_ci.u_primary_ait=' + aitId + '^u_primary_ait!=' + aitId + '^ORu_primary_aitISEMPTY');
        di.setWorkflow(false);
        di.autoSysFields(false);
        di.setValue('u_primary_ait', aitId);
        di.updateMultiple();
    }

Fast path when a tier improves, one statement per service:

    promoteCis: function(serviceId, aitId, newTier) {
        var ci = new GlideRecord('cmdb_ci');
        ci.addEncodedQuery('sys_idIN' + this.ciIdsOfService(serviceId) + '^u_primary_ait_tier>' + newTier + '^ORu_primary_ait_tierISEMPTY');
        ci.setWorkflow(false);
        ci.autoSysFields(false);
        ci.setValue('u_primary_ait', aitId);
        ci.setValue('u_primary_ait_tier', newTier);
        ci.setValue('u_primary_ait_source', serviceId);
        ci.updateMultiple();
    }

Partitioned processor entry point (one job record per partition):

    processPartition: function(hex) {
        try {
            var changed = {};                                  // new AIT value -> true
            this._resolveDirty('cmdb_ci_service', hex, this.resolveService, changed);
            this._resolveDirty('cmdb_ci', hex, this.resolveCi, changed);
            for (var ait in changed)
                for (var t = 0; t < this.diTables.length; t++)
                    this.stampDiscoveredItems(ait, this.diTables[t]);
        } catch (e) {
            gs.error('AitResolutionUtil: partition ' + hex + ' not processed - ' + e.message);
        }
    }

Drift report query, one count per AIT:

    cmdb_ci.u_primary_ait=<AIT>^u_primary_ait!=<AIT>^ORu_primary_aitISEMPTY

## 10. Techniques borrowed from outside the platform

| Technique | Origin | Use here |
|---|---|---|
| Fan-out on write for common events, batched fan-out for rare wide ones | social timeline design (the "celebrity" problem) | DI and CI changes push immediately; AIT changes propagate in keyed batches |
| Dirty flags, recompute only what is marked | spreadsheet recalculation engines, game engines, browser layout | `u_ait_refresh` on services and CIs |
| Incremental view maintenance, patch from the delta | streaming databases | levels 1 to 3 are views over the relationship tables, maintained from changes |
| Incremental MIN maintenance | aggregate maintenance in databases | the fast path in section 4.5 |
| Closure table instead of traversal | hierarchical data in relational databases | `svc_ci_assoc` and the platform's Related Services table as the CI-to-service index |
| Bounded breadth-first search with a visited set | graph databases | the platform's own `servicesAffectedByCI`, only as the fallback |
| `UPDATE ... JOIN` | SQL | `updateMultiple` with a dot-walked condition |
| Partition by key, independent workers | distributed batch processing | `sys_id`-prefix partitions on parallel job records |
| Read replicas for heavy reads | database scaling | `setCategory` on the reconciliation reads where the secondary pool is licensed |

## 11. Assumptions to confirm

1. The AIT is referenced from the business application by a single reference field, and the RTO tier is a numeric field on the AIT (lower is more critical).
2. The DI tables in scope are the discovered item, discovered application and discovered container image tables; each has (or gets) `u_primary_ait`.
3. "Both ends" of `svc_ci_assoc` means the CI may appear as `service_id` when it is itself a service; the design treats both.
4. Real counts and daily change rates for DIs, CIs, services, applications and AITs, and the typical fan-out of one AIT (applications, services, CIs), to size partitions and cadence.
5. Whether the DI tables are audited in production, which decides whether the stamp runs as one SQL statement or row by row.
6. Whether the secondary database pool (read replica) and the event Processing Framework are licensed and active, which decides the exact engine for parallel processing (both fall back to partitioned scheduled jobs).
7. The acceptable staleness window for AIT-level changes (the design targets seconds by event and a few minutes by the periodic job).
