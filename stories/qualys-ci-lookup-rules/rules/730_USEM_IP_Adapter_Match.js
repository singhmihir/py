/* =================================================================================================
   RULE 730 - USEM IP Adapter Match
   =================================================================================================
   Match by an IP address recorded on a Network Adapter record rather than on the CI itself
   (multi-homed servers, discovery-populated CIs). The adapter leads to its owning CI.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field -> "30.162.178.21"
   sourcePayload = the whole record
   Expected for the sample: the CI that owns the adapter carrying "30.162.178.21", for example
   adapter "vmk0" of the ESX Server "vsdnac22xsdi009"; declined when adapters of two different CIs
   carry the address or the owner is a load balancer.

   WHY THIS RULE SITS AT ORDER 730
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 700/705 looked for the address in the ip_address field of the CI record itself.
   - Reaches it: hosts whose address is stored on an adapter record only.
   - After it  : 740 (layered IP Address records) and then the last-resort name rule 850.
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
    // ====== STAGE 1: Search the Network Adapter records for the address ==========================
    // What   : searches the Network Adapter table for adapters whose ip_address equals the scanned
    //          address and that belong to a CI outside the ignored classes.
    // Why    : discovery stores one adapter record per network card; a server with several cards
    //          keeps its addresses there instead of on the CI record.
    // Sample : adapter "vmk0" with ip_address "30.162.178.21" belongs to the ESX Server
    //          "vsdnac22xsdi009" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // =============================================================================================
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);
    nic.addNotNullQuery('cmdb_ci');               // the adapter must belong to a CI
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    nic.query();
    // ====== STAGE 2: Collect the owning CIs and decide ===========================================
    // What   : walks the rows, counts each distinct owning CI once, and accepts the single owner
    //          when it is not a load balancer.
    // Why    : one device with two adapters on the address must count once, two devices must count
    //          twice; two owners cannot be told apart by the address, and a load balancer on a
    //          virtual address is not the scanned host.
    // Sample : one row -> owners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1 -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" (the ESX Server "vsdnac22xsdi009"). Two owners,
    //          or a load balancer -> return null and rule 740 gets its turn.
    // =============================================================================================
    var owners = {};
    var count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');
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
