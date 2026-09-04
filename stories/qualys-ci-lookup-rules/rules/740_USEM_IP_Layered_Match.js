/* =================================================================================================
   RULE 740 - USEM IP Layered Match
   =================================================================================================
   Match by IP address through the layered model that CMDB discovery maintains: an IP Address record
   belongs to a Network Adapter, and the adapter belongs to the CI.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field -> "30.162.178.21"
   sourcePayload = the whole record
   Expected for the sample: the CI at the end of the chain IP Address "30.162.178.21" -> adapter
   "vmk0" -> ESX Server "vsdnac22xsdi009"; declined for several owners or a load balancer.

   WHY THIS RULE SITS AT ORDER 740
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 730 looked for the address on Network Adapter records.
   - Reaches it: hosts whose address exists only as an IP Address record in the layered model.
   - After it  : 850, the last-resort broad name search; if that also declines, the out-of-box
                 Qualys rules (860 and above) get their turn.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.21"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // isLoadBalancer(id) is true when the CI is a Load Balancer. A balancer answers on virtual
    // addresses on behalf of its pool members, so it is never the host that was scanned.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }
    // ====== STAGE 1: Search the IP Address records for the address ===============================
    // What   : searches the IP Address table for records whose ip_address equals the scanned
    //          address and whose adapter (nic) belongs to a CI outside the ignored classes;
    //          nic.cmdb_ci reaches the CI two links away.
    // Why    : newer discovery writes each address as its own record linked to the adapter; rule
    //          730 cannot see those when the adapter record itself carries no address.
    // Sample : the IP Address record "30.162.178.21" belongs to adapter "vmk0", which belongs to
    //          the ESX Server "vsdnac22xsdi009" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // =============================================================================================
    var ipGr = new GlideRecord('cmdb_ci_ip_address');
    if (!ipGr.isValid())                          // layered model not installed -> decline
        return null;
    ipGr.addQuery('ip_address', ip);
    ipGr.addNotNullQuery('nic.cmdb_ci');          // the chain must end on a CI
    if (ignore)
        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    ipGr.query();
    // ====== STAGE 2: Collect the owning CIs and decide ===========================================
    // What   : walks the rows, counts each distinct owning CI once, and accepts the single owner
    //          when it is not a load balancer.
    // Why    : one device with two adapters on the address must count once, two devices must count
    //          twice; two owners cannot be told apart by the address, and a load balancer on a
    //          virtual address is not the scanned host.
    // Sample : one row -> owners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1 -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" (the ESX Server "vsdnac22xsdi009"). Two owners,
    //          or a load balancer -> return null and rule 850 gets its turn.
    // =============================================================================================
    var owners = {};
    var count = 0, first = null;
    while (ipGr.next()) {
        var owner = '' + ipGr.nic.cmdb_ci;
        if (!owners[owner]) {                     // count each CI once
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1 && !isLoadBalancer(first))
        return first;
    return null;
})(rule, sourceValue, sourcePayload);
