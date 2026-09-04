/* =================================================================================================
   RULE 730 - USEM IP Adapter Match
   =================================================================================================
   PURPOSE
   Match by an IP address recorded on a Network Adapter record rather than on the CI itself
   (multi-homed servers, discovery-populated CIs). The adapter leads to its owning CI.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field of that record -> "30.162.178.21"
   sourcePayload = the whole record above
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the CI that owns the adapter carrying "30.162.178.21", for
   example adapter "vmk0" of the ESX Server "vsdnac22xsdi009"; declined when adapters of two
   different CIs carry the address or when the owner is a load balancer.

   WHY THIS RULE SITS AT ORDER 730
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 700/705 looked for the address in the ip_address field of the CI record itself.
   - Reaches it: hosts whose address is stored on an adapter record only.
   - After it  : 740 (layered IP Address records) and then the last-resort name rule 850.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent an IP address
    2. Clean the address and reject addresses that identify nothing
    3. Read the list of CI classes that must never be matched
    4. The helper isLoadBalancer(id)
    5. Search the Network Adapter records for the address
    6. Collect the owning CIs
    7. Decide: one owner that is not a load balancer, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent an IP address
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "30.162.178.21" -> not empty -> the rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the address and reject addresses that identify nothing
    // What happens : '' + sourceValue turns the value into plain text and trim() removes blanks at
    //                both ends. Then the rule refuses loopback addresses (127.x.x.x) and link-local
    //                addresses (169.254.x.x).
    // Why          : every machine answers on 127.0.0.1, and 169.254.x.x addresses are
    //                self-assigned when no network is available, so neither can ever point at one
    //                CI.
    // Sample       : ip = "30.162.178.21" -> neither prefix matches -> carry on.
    // ---------------------------------------------------------------------------------------------
    var ip = ('' + sourceValue).trim();
    // -> ip = "30.162.178.21".
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;
    // -> indexOf("127.") == 0 would mean the text starts with "127."; for "30.162.178.21" both
    //    indexOf calls return -1 -> the condition is false -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Read the list of CI classes that must never be matched
    // What happens : reads the list of CI classes that must never be matched. Administrators keep
    //                it in the system property sn_sec_cmn.ignoreCIClass as comma separated class
    //                names. The framework may also hand the same list to the script as a variable
    //                called _ignoreClass; when that variable exists and is filled the script uses
    //                it, otherwise it reads the property directly.
    // Why          : placeholder and technical classes must never receive vulnerability findings:
    //                the unmatched CI placeholders that Security Operations creates, the Qualys
    //                staging CI class, Unclassed Hardware, incomplete IP records and DNS Name
    //                records. Keeping the list in one property means it can be changed without
    //                editing sixteen scripts.
    // Sample       : with the platform default the property holds
    //                "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name";
    //                an empty property gives ignore = "" and then no class filter is added to the
    //                searches below.
    // ---------------------------------------------------------------------------------------------
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name",
    //    one text, comma separated, ready for a NOT IN condition.
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - The helper isLoadBalancer(id)
    // What happens : defines a small helper used later: it reports true when the CI with the given
    //                sys_id is stored in the Load Balancer class (cmdb_ci_lb) or one of its
    //                sub-classes.
    // Why          : a load balancer answers on virtual addresses on behalf of the pool members
    //                behind it; a scanned address that belongs to such a virtual IP describes a
    //                pool member, not the balancer, so the balancer must never be returned.
    // Sample       : isLoadBalancer("8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f") = true when that sys_id is
    //                the Load Balancer "lb-sdi-core-01"; false for the ESX Server
    //                "vsdnac22xsdi009".
    // ---------------------------------------------------------------------------------------------
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        // -> lb = a search on the Load Balancer class; isValid() is false when that class is not
        //    installed
        return lb.isValid() && lb.get(id);
        // -> get(id) returns true only when a load balancer with that sys_id exists
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - Search the Network Adapter records for the address
    // What happens : searches the Network Adapter table for adapters whose ip_address equals the
    //                scanned address and that belong to a CI whose class is not on the ignore list.
    // Why          : discovery stores one adapter record per network card of a device; a server
    //                with several cards keeps its addresses there instead of on the CI record.
    // Sample       : adapter "vmk0" with ip_address "30.162.178.21" belongs to the ESX Server
    //                "vsdnac22xsdi009" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    // -> nic = a search on the Network Adapter table.
    nic.addQuery('ip_address', ip);
    // -> condition added: ip_address = "30.162.178.21".
    nic.addNotNullQuery('cmdb_ci');
    // -> condition added: cmdb_ci is not empty, so only adapters that belong to a CI are
    //    considered.
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    // -> condition added: the class of the owning CI is NOT IN (sn_sec_cmn_unmatched_ci,
    //    sn_vul_qualys_ci, cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    nic.query();
    // -> the search has run; each row is one adapter carrying the address.
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Collect the owning CIs
    // What happens : walks the adapters and records each distinct owning CI once.
    // Why          : one device can have two adapters on the same address (a bonded pair); it must
    //                count as one owner, while two different devices must count as two.
    // Sample       : one adapter -> owners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1,
    //                first = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // ---------------------------------------------------------------------------------------------
    var owners = {};
    var count = 0, first = null;
    // -> owners = {} (every CI seen, keyed by sys_id), count = 0, first = null.
    while (nic.next()) {
        // -> each pass of the loop looks at one adapter.
        var owner = nic.getValue('cmdb_ci');
        // -> owner = the sys_id of the CI that owns this adapter, for example
        //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        // -> the first time a CI is seen: owners gains it, count grows by one, and first remembers
        //    the very first CI. A second adapter of the same CI changes nothing.
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Decide: one owner that is not a load balancer, or decline
    // What happens : accepts the single owner when exactly one CI was collected and it is not a
    //                Load Balancer; declines otherwise.
    // Why          : two owners cannot be told apart by the address, and a load balancer answering
    //                on a virtual address is not the host that was scanned.
    // Sample       : count = 1 and isLoadBalancer("3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c") = false ->
    //                return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". count = 2, or the owner is the Load
    //                Balancer "lb-sdi-core-01" -> return null.
    // ---------------------------------------------------------------------------------------------
    if (count == 1 && !isLoadBalancer(first))
        return first;
    // -> exactly one owner and not a load balancer -> its sys_id goes back to the framework.
    return null;
    // -> no owner, several owners, or a load balancer -> decline; the host continues to rule 740.
})(rule, sourceValue, sourcePayload);
