Subject: Qualys CI matching for load balancer addresses - how the two rules reach the CI, example by example

Hi Ravali,

Following our call, here is a record-by-record walk-through of how discovered items scanned on load balancer addresses are matched to a CI. I have taken examples from the development instance, and every step below carries a link to the record it refers to, so you can follow the same path yourself.

How the two rules fit together

Every Qualys host record first goes through the serial, name and address rules. A virtual IP has no serial number, no CI carries its DNS name, and the address rules deliberately refuse a load balancer device, so a virtual IP reaches the two load balancer rules with nothing matched:

1. BOFA Load Balancer Member Match runs first. It finds the Load Balancer Service record (the virtual server), follows Service -> Pool -> Pool Member, looks up each member address on the server records, and returns the real server only when the whole pool points at exactly one machine. Otherwise it declines.
2. BOFA Load Balancer Service Match runs next and attaches the Load Balancer Service record itself.

Both rules only run when the host record shows a virtual IP sign: the operating system text contains a load balancer product (f5, big-ip, big ip, netscaler), or the host name label contains a marker segment (vip, vs, also as vip1, vip2, vs1, or a segment ending in vip). Both rules then search the Load Balancer Service table with four clues in order: fqdn equal to the DNS name, name equal to the DNS name, name equal to the host label, and finally ip_address equal to the scanned IP. Each clue must find exactly one record; two records end the rule without a match.

On our instance the service records are named after the F5 object (for example /Common/ait73074-rvcpbt1-ctuapi-pb-443-vip) and carry no fqdn, so the three name clues find nothing and it is the fourth clue, the IP address, that identifies the virtual server in every example below.

Records used in the walk-through: Discovered Item (sn_sec_cmn_src_ci, the scanned host and its source data), Load Balancer Service (cmdb_ci_lb_service, the virtual server), Load Balancer Pool (cmdb_ci_lb_pool), Load Balancer Pool Member (cmdb_ci_lb_pool_member, one row per back-end server and port), and the server CI (cmdb_ci_linux_server / cmdb_ci_win_server).


=== BOFA Load Balancer Service Match (rule 460) ===

Example 1 - SDI000003028240

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003028240
Source data received: IP 171.159.246.128 | DNS (none) | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; no DNS name.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 171.159.246.128 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ait71454-pt1-mlonefeeui-443-vip (port 443, on balancer sveqbt1rp1lb02b)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=a029dc43931183d03854f05ea903d6b7
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dsveqbt1rp1lb02b
Pool behind it (the service record's Pool field): /Common/ait71454-pt1-mlonefeeui-443-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=5c29dc43931183d03854f05ea903d6b6
Pool members (Pool Member records whose Pool field is this pool): https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D5c29dc43931183d03854f05ea903d6b6
   /Common/ait71454-pt1-wva41bmsgsws01v-node | address 171.128.218.80 port 443  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=466c6ce02f1ec710f8fdb18e8ea4e3ef
Outcome: the pool holds one member address, 171.128.218.80. The member rule tags a server only when that address is found on a server record (its IP Address field), on a Network Adapter record, or on an IP Address record, and the record found is a server rather than a placeholder class. The item carries the virtual server record, so that lookup found no server for 171.128.218.80; the two lists below show what the CMDB holds for it today.
   servers: https://bofasecopsdev.service-now.com/cmdb_ci_hardware_list.do?sysparm_query=ip_address%3D171.128.218.80
   adapters: https://bofasecopsdev.service-now.com/cmdb_ci_network_adapter_list.do?sysparm_query=ip_address%3D171.128.218.80

Example 2 - SDI000003726690

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003726690
Source data received: IP 158.171.194.200 | DNS ctuapi-pb-va1-vip.gwim.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip" is a marker.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 158.171.194.200 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ait73074-rvcpbt1-ctuapi-pb-443-vip (port 443, on balancer svedbt1gwmlb01a)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=4a676071933d4b504cbaf137a803d6a2
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dsvedbt1gwmlb01a
Pool behind it (the service record's Pool field): /Common/ait73074-rvcpbt1-ctuapi-pb-443-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=99676831933d4b504cbaf137a803d6bf
Pool members (Pool Member records whose Pool field is this pool): https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D99676831933d4b504cbaf137a803d6bf
   /Common/ait73074-rvcpbt1-wva22bwvewas01v-node | address 171.134.180.169 port 443  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=3d676071933d4b504cbaf137a803d6a1
   /Common/ait73074-rvcpbt1-wva22bwvewas02v-node | address 171.134.180.168 port 443  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=ed676071933d4b504cbaf137a803d6a0
   /Common/ait73074-rvcpbt1-wva22bwvewas03v-node | address 171.134.180.159 port 443  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=25676831933d4b504cbaf137a803d6c1
   /Common/ait73074-rvcpbt1-wva22bwvewas04v-node | address 171.134.180.161 port 443  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=d5676831933d4b504cbaf137a803d6c0
Outcome: the pool fronts four different servers (four member addresses). The member rule declines by design, because the scanned finding belongs to one of four hosts and nothing in the CMDB says which; the service rule attached the virtual server record.

Example 3 - SDI000003726689

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003726689
Source data received: IP 158.171.194.201 | DNS ctundm-pb-va1-vip.gwim.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip" is a marker.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 158.171.194.201 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ait73074-rvcpbt1-ctundm-pb-1364-vip (port 1364, on balancer svedbt1gwmlb01a)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=fe96e43993f94b504cbaf137a803d61c
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dsvedbt1gwmlb01a
Pool behind it (the service record's Pool field): /Common/ait73074-rvcpbt1-ctundm-pb-1364-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=1a96e43993f94b504cbaf137a803d61a
Pool members (Pool Member records whose Pool field is this pool): https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D1a96e43993f94b504cbaf137a803d61a
   /Common/ait73074-rvcpbt1-wva22bwvewut01v-node | address 171.134.180.158 port 1364  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=b296e43993f94b504cbaf137a803d61c
   /Common/ait73074-rvcpbt1-wva22bwvewut02v-node | address 171.134.180.183 port 1364  https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member.do?sys_id=6696e43993f94b504cbaf137a803d61b
Outcome: two member addresses, two servers; the member rule declines and the service rule attached the virtual server record. Note the port: the service and its members listen on 1364, and the pool member records show the same port, which is how the pool can be read together with the service.

Example 4 - SDI000003506195

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003506195
Source data received: IP 165.40.145.228 | DNS sgcpbt1utigb01b-lsn1.asia.bankofamerica.com | OS F5 Big IP
Virtual IP sign: OS text contains "f5" and "big ip"; the host label carries no marker.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 165.40.145.228 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/vs_165_40_145_228_53_gtm_0 (port 53, on balancer sgcpbt1utigb01b)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=262557de93f9e65007a4f84958373c9f
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dsgcpbt1utigb01b
Pool behind it: none. The service record's Pool field is empty, no pool points at it and none is related to it.
Outcome: a DNS listener on a GTM device: the service record exists but has no pool, so there is no server to reach. The virtual server record is the only CI that models this address, and the service rule attached it. The host label (sgcpbt1utigb01b-lsn1) carries no marker; the OS text alone qualified the host.

Example 5 - SDI000002395438

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000002395438
Source data received: IP 165.47.76.142 | DNS caypap1pxylb12-vs1.network.emea.bankofamerica.com | OS (none)
Virtual IP sign: no load balancer word in the OS text; host label segment "vs1" is a marker.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 165.47.76.142 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/exp-pxy-vip (port 8080, on balancer caypap1pxylb12)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=0c6c8b523b3d2e50489ce5d964e45aee
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dcaypap1pxylb12
Pool behind it: none. The service record's Pool field is empty, no pool points at it and none is related to it.
Outcome: the scan reported no operating system at all; the host qualified through the label segment "vs1" (the marker "vs" followed by digits). The service record on 165.47.76.142 has no pool, so the virtual server record was attached. A second record of the same name, /Common/exp-pxy-vip, exists on caypap1pxylb11 at 165.47.76.141 (item SDI000002393798); the address clue keeps the two apart, each item lands on the record of its own address.

Example 6 - SDI000003084244

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003084244
Source data received: IP 171.159.246.185 | DNS (none) | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; no DNS name.
Clue that found the virtual server: fqdn and name clues find nothing (record named after the F5 object); ip_address = 171.159.246.185 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ait48001-pt1-dtlapp-va-443-vip (port 443, on balancer sveqbt1rp1lb02b)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=6a6c6828cf960b10becc38db5d851c5e
   balancer: https://bofasecopsdev.service-now.com/cmdb_ci_lb_list.do?sysparm_query=name%3Dsveqbt1rp1lb02b
Pool behind it (the service record's Pool field): /Common/ait48001-pt1-dtlapp-va-443-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=da6c6828cf960b10becc38db5d851c5d
Pool members (Pool Member records whose Pool field is this pool): https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3Dda6c6828cf960b10becc38db5d851c5d
Outcome: the service carries a pool, but in the data I extracted no Pool Member record points at that pool (the member list link above shows the current state). With no members there is no address to follow, so the member rule declines and the service rule attached the virtual server record. This is a discovery gap rather than a matching decision: once the pool members are discovered, the item is resolved through them.


=== BOFA Load Balancer Member Match (rule 455) ===

The same sign and the same four clues find the virtual server. The rule then reads the Pool field of the service record, collects the Pool Member records whose Pool field points at that pool, and looks each member address up in three places: the IP Address field of the server records, the Network Adapter records (their owning CI), and the IP Address records (their adapter's CI); a member related to a server through a CI relationship counts as well. Load balancer devices and placeholder classes are never accepted. When the pool leads to exactly one machine, that machine is returned; anything else declines and the service rule decides.

Example 1 - SDI000002418623

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000002418623
Source data received: IP 10.143.52.217 | DNS ccgw-l7-vip2.sit1.gwimnp.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip2" is a marker.
Clue that found the virtual server: ip_address = 10.143.52.217 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ihscore-sit1-ccgw-6011-vip (port 6011, on balancer svedpz1rp4lb10)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=be381f963bfd2e50489ce5d964e45a84
Pool (the service record's Pool field): /Common/ihscore-sit1-ccgw-6011-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=36381f963bfd2e50489ce5d964e45a84
Pool members: https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D36381f963bfd2e50489ce5d964e45a84
   the members of this pool point at one address, 10.143.72.200
Server found: the address 10.143.72.200 is the IP Address field of the server record lva71pwbolcc01v (Linux Server)
   https://bofasecopsdev.service-now.com/cmdb_ci_linux_server.do?sys_id=ddcdddf02b462294d50dffbdbe91bf9b
Outcome: one address, one server, so the member rule returned lva71pwbolcc01v; the discovered item now carries that server as its CI, not the balancer and not the virtual server record. The balancer svedpz1rp4lb10 is a separate CI and is never returned.

Example 2 - SDI000002411394

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000002411394
Source data received: IP 10.143.52.163 | DNS ccgw-l7-vip2.dev.gwimnp.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip2" is a marker.
Clue that found the virtual server: ip_address = 10.143.52.163 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ihscore-dev-ccgw-6011-vip (port 6011, on balancer svedpz1rp4lb10)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=b2381f963bfd2e50489ce5d964e45a86
Pool (the service record's Pool field): /Common/ihscore-dev-ccgw-6011-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=3a381f963bfd2e50489ce5d964e45a85
Pool members: https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D3a381f963bfd2e50489ce5d964e45a85
   the members of this pool point at one address, 10.143.72.198
Server found: the address 10.143.72.198 is the IP Address field of the server record lva68pwbolcc01v (Linux Server)
   https://bofasecopsdev.service-now.com/cmdb_ci_linux_server.do?sys_id=d78e25b82b8e2294d50dffbdbe91bf32
Outcome: one address, one server, so the member rule returned lva68pwbolcc01v; the discovered item now carries that server as its CI, not the balancer and not the virtual server record. Same application as example 1 in the dev environment: a different virtual server, a different pool, a different server.

Example 3 - SDI000002375027

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000002375027
Source data received: IP 10.143.52.154 | DNS multi-benefits-l7-vip2.dev.gwimnp.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip2" is a marker.
Clue that found the virtual server: ip_address = 10.143.52.154 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ihscore-dev-multilang_benefits-6011-vip (port 6011, on balancer svedpz1rp4lb10)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=be381f963bfd2e50489ce5d964e45a1d
Pool (the service record's Pool field): /Common/ihscore-dev-multilang_benefits-6011-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=36381f963bfd2e50489ce5d964e45a1d
Pool members: https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D36381f963bfd2e50489ce5d964e45a1d
   the members of this pool point at one address, 10.143.72.171
Server found: the address 10.143.72.171 is the IP Address field of the server record wva68pwbolts51v (Windows Server)
   https://bofasecopsdev.service-now.com/cmdb_ci_win_server.do?sys_id=813bd5383b0e6254a052e71864e45a35
Outcome: one address, one server, so the member rule returned wva68pwbolts51v; the discovered item now carries that server as its CI, not the balancer and not the virtual server record. The class of the server does not matter to the rule; it takes what the pool points at, here a Windows Server.

Example 4 - SDI000002993687

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000002993687
Source data received: IP 10.143.53.96 | DNS boluiv4-dev2-benefits-l7-vip1.dev.gwimnp.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; host label segment "vip1" is a marker.
Clue that found the virtual server: ip_address = 10.143.53.96 finds exactly one Load Balancer Service.
Load Balancer Service chosen: /Common/ihscore-dev2-boluiv4_benefits-6011-vip (port 6011, on balancer svedpz1rp1lb12)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service.do?sys_id=a966482d3b68c710ae0c4047f4e45ab3
Pool (the service record's Pool field): /Common/ihscore-dev2-boluiv4_benefits-6011-pool
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool.do?sys_id=3066482d3b68c710ae0c4047f4e45aac
Pool members: https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=pool%3D3066482d3b68c710ae0c4047f4e45aac
   the members of this pool point at one address, 171.184.193.14
Server found: the address 171.184.193.14 is the IP Address field of the server record lva62pwbolws51v (Linux Server)
   https://bofasecopsdev.service-now.com/cmdb_ci_linux_server.do?sys_id=f2130b8693966a107fb5f842ed03d653
Outcome: one address, one server, so the member rule returned lva62pwbolws51v; the discovered item now carries that server as its CI, not the balancer and not the virtual server record. The member address here is on a different network from the virtual address, which is normal: the pool member address is the server's own address, the virtual address belongs to the balancer.

Example 5 - SDI000003028419

Discovered item: https://bofasecopsdev.service-now.com/sn_sec_cmn_src_ci_list.do?sysparm_query=number%3DSDI000003028419
Source data received: IP 171.159.246.91 | DNS turbotmt-tx.pt2.pt2.gwimnp.rpg | OS F5 Networks Big-IP
Virtual IP sign: OS text contains "f5" and "big-ip"; the host label carries no marker.
Clue that found the virtual server: ip_address = 171.159.246.91 finds exactly one Load Balancer Service.
Load Balancer Service chosen: the one service record on 171.159.246.91 (open it through the address filter)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_service_list.do?sysparm_query=ip_address%3D171.159.246.91
Pool: open the service record above and follow its Pool field.
Pool members: the pool's members carry the address 171.128.217.213 (the Pool Member list filtered by that address shows them, with their pool)
   https://bofasecopsdev.service-now.com/cmdb_ci_lb_pool_member_list.do?sysparm_query=ip_address%3D171.128.217.213
Server found: the address 171.128.217.213 is the IP Address field of the server record wva41bwtmtas01v (Windows Server)
   https://bofasecopsdev.service-now.com/cmdb_ci_win_server.do?sys_id=602822843bcc8710ef3892e643e45a97
Outcome: one address, one server, so the member rule returned wva41bwtmtas01v; the discovered item now carries that server as its CI, not the balancer and not the virtual server record. The host label (turbotmt-tx) carries no marker; the OS text alone qualified the host. The service record is reached through the address filter link above.


How to check any item yourself

1. Open the discovered item and read IP, DNS and OS in its source data; confirm the sign (a load balancer word in OS, or a vip / vs segment in the label).
2. Open the Load Balancer Service list filtered by that IP address: exactly one record must come back.
3. Open that record and follow its Pool field to the pool; then open the Pool Member list filtered by that pool.
4. For each member address, search the server records (cmdb_ci_hardware) by IP Address. One server across all members means the member rule tags that server; several servers, or an address no server carries, means the member rule declines and the item shows the virtual server record from the service rule.

When a discovered item is evaluated again

An item that already holds a CI keeps it until it is evaluated again. That happens when its host arrives in a new import, when the rule that matched it carries the Reapply flag and the "Reapply CI lookup rules" job runs (the job takes the unmatched items plus the items matched by the flagged rules, scanned in the last 90 days), or when the item is selected in the Discovered Items list and "Reapply CI lookup rules" is chosen there. An item evaluated again is only written when the chain returns a different CI or a different rule.

What changes with the refinement set

The refinement set tightens the rules in the direction of never guessing, and the division of work stays as described above: the member rule finds the real server, the service rule attaches the virtual server record when the member rule cannot. The member rule will decline when any pool member cannot be placed on a server, so a partly known pool no longer tags the one server it happens to find. Records of one virtual server that exist on both devices of an HA pair are treated as one virtual server: a retired copy is set aside for the live record, and when both records are live neither rule picks one. The layered DNS rule stops returning a load balancer device when a virtual server's name resolves to it, so such hosts reach the two rules above. I will send the set with its notes for the development instance.

Happy to walk through any of these on a call.

Kind regards,
Mihir
