# SNOWUSEMTP-1825 – CI classes the lookup rules never match against

The Security Support Common property `sn_sec_cmn.ignoreCIClass` lists the CI classes that discovered items must
never be matched against. The platform reads it in `CIIdentify` (`_checkCIIgnored`: a CI returned by a rule is
dropped when its class is on the list; exact class names, no hierarchy) and the USEM rules read it into their
`sys_class_name NOT IN` searches.

Story text (JIRA SNOWUSEMTP-1825): discovered items are not matched against cmdb_ci_ip_address,
cmdb_ci_network_adapter, cmdb_ci_nic, cmdb_ci_vmware_nic, cmdb_ci_storage_volume, cmdb_ci_disk_partition,
cmdb_ci_lb, cmdb_ci_dns_name, cmdb_ci_file_system, cmdb_ci_vm_instance, cmdb_ci_vm_template,
cmdb_ci_vmware_instance, cmdb_ci_storage_pool, cmdb_ci_lb_pool_member, dscy_router_interface,
dscy_swtch_fwd_rule, cmdb_ci_endpoint_tcp, cmdb_ci_print_queue, cmdb_ci_certificate.

## Delivered (17 Sep)
Set `SNOWUSEMTP-1825_MS_Ignore CI Classes for Lookup Rules_V1.0`, application Security Support Common (the
property's own scope), one row, file `Ignore CI Classes for Lookup Rules - Update Set.xml` (on INC0010003).
`build_property.py` extends the value (the five classes already there kept first, the story's list appended,
`cmdb_ci_dns_name` already present) inside a set of that scope, run in that scope, and audits the captured row;
`export_property.py` completes, exports natively, scrubs, parses, proves the upload path and archives.

New value: `sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,
cmdb_ci_dns_name,cmdb_ci_ip_address,cmdb_ci_network_adapter,cmdb_ci_nic,cmdb_ci_vmware_nic,cmdb_ci_storage_volume,
cmdb_ci_disk_partition,cmdb_ci_lb,cmdb_ci_file_system,cmdb_ci_vm_instance,cmdb_ci_vm_template,
cmdb_ci_vmware_instance,cmdb_ci_storage_pool,cmdb_ci_lb_pool_member,dscy_router_interface,dscy_swtch_fwd_rule,
cmdb_ci_endpoint_tcp,cmdb_ci_print_queue,cmdb_ci_certificate`. Every class exists on the PDI.

## Effect on the Qualys rules (run after the change)
- `test_lb_member.py` 58 of 58, `test_v6.py` 50 of 50, `test_v3.py` 36 of 36: unchanged.
- Header sweep: the sample of 850 FQDN Name Broad Match (a `cmdb_ci_vm_instance`) is now dropped, no match.
- `test_evidence.py` 350 of 356: the three client hosts `sinpbt1dedcn01-bthcplb01b`, `sinpbt1uticn01-btutilb02b`,
  `sinpbt1uticn01-btutilb02a` (Ubuntu/Linux on `cmdb_ci_lb` records, matched by 410 through the appliance
  acceptance) no longer match while `cmdb_ci_lb` is on the list. Mihir's decision: ship the list as the story has it
  and tell the client the load balancer class carries real matches, to be taken off the property later.
- Exact class names only: `cmdb_ci_lb_bigip` devices are not covered by `cmdb_ci_lb`, and `cmdb_ci_vm_instance`
  covers that class alone (`cmdb_ci_vmware_instance` is listed separately). Rule 455 reads pool member records
  directly, so `cmdb_ci_lb_pool_member` on the list does not affect it.

## Certificate class, 17 Sep evening
Ravali's position settled on keeping `cmdb_ci_certificate` on the list; AIT logic is not available (the Primary AIT on a
discovered item comes from its CI). The 2,370 items on Unique Certificate records (2,328 by the broad-name rule 850, 42 by
the platform's NetBIOS rule; certificate named with the host's fqdn in 2,330) were analysed from bofadev exports on
INC0010003:
- Certificate Inventory and Management 3.14.0 is installed. Its Installed Certificate table
  (`sn_disco_certmgmt_cmdb_installed_certificate`) never sets `server` (0 rows instance-wide, confirmed by count); the rows
  hold the probed address (`source`) and port only. There is no `cmdb_certificate_instance` table; that name was wrong.
- `cmdb_rel_ci`: 346,068 "Used by::Uses" rows between certificates and hardware. `Certificate Relationships - Export
  Script.js` (story folder, on the incident; tested on the PDI with five fixture shapes, attachment path exercised) ran on
  bofadev and gave, per item: 1,714 relationships to non-devices (1,598 only `cmdb_ci_service_auto`), 311 no relationship,
  101 several live devices (shared certificates), 244 exactly one live device (195 `cmdb_ci_outofband_device`, 24
  `cmdb_ci_msd`), of which 196 carry the scanned host's name and 194 also its IP.
- `cmdb_ci_outofband_device` and `cmdb_ci_msd` extend `cmdb_ci_hardware`; on the PDI, iLO/iDRAC/HMC payloads against such
  records match through 410 (name), 450 (fqdn) or 705 (address) with no certificate involved. So the 194 were missed on
  bofadev because the device records were absent or shaped differently at evaluation time; re-evaluation with certificates
  ignored lands them through the existing rules.
- Decision recorded on the incident: no certificate rule; keep the class ignored; re-evaluate the 2,370 items with the
  list action "Reapply CI lookup rules" (re-runs selected items regardless of the rule flag); expect ~190-240 on real
  devices, ~100 shared-certificate hosts and the rest as placeholders (one per host; the CMDB work list by cause).
- Platform mechanics read for this: reapply job scope (`ci_lookup_ruleISEMPTY^ORci_lookup_ruleIN<flagged rules>`, 90-day
  scan window), `_processDiscoveredItem` handing unmatched items to the IRE placeholder, `sn_sec_cmn.update_on_ci_change`
  (default true: vulnerable items updated in place on a CI change; a duplicate VI on the new CI absorbs the detections and
  the old one closes as invalid CI), auto-promotion (`sn_sec_cmn.autoPromoteFields`, a reference field on the matched
  class, nothing for certificates).
