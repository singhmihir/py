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
