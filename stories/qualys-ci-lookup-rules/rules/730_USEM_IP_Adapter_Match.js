/* =====================================================================
   RULE 730 - USEM IP Adapter Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field  -> "30.162.178.21"
   sourcePayload = the whole record above

   WHY THIS RULE SITS AT ORDER 730
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 700/705 looked for the address in the ip_address field of the
                 CI record itself.
   - Reaches it: hosts whose address is recorded on a Network Adapter record
                 (multi-homed servers, discovery-populated CIs) rather than on
                 the CI; the adapter leads to its owning CI.
   - After it  : 740 (layered IP Address records) and then the last-resort name
                 rule 850.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no IP -> nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.21"
    // Loopback (127.x) and link-local (169.254.x) addresses are the same on
    // every machine and can never identify one CI.
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // A load balancer answers on virtual addresses on behalf of its pool
    // members; such an address must never be matched to the load balancer.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }

    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);               // adapter whose ip_address = "30.162.178.21"
    nic.addNotNullQuery('cmdb_ci');               // adapter must belong to a CI
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    nic.query();
    var owners = {};                              // distinct owning CIs
    var count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');      // the CI owning this adapter
        if (!owners[owner]) {                     // one CI with two adapters on the address still counts once
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1 && !isLoadBalancer(first))     // exactly one owner and it is not a load balancer -> match
        return first;
    return null;                                  // none, several, or a VIP -> decline
})(rule, sourceValue, sourcePayload);
