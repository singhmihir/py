/* =====================================================================
   RULE 740 - USEM IP Layered Match
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

   WHY THIS RULE SITS AT ORDER 740
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 730 looked for the address on Network Adapter records.
   - Reaches it: hosts whose address exists only as an IP Address record in the
                 layered model that CMDB discovery maintains (IP Address record
                 -> adapter -> owning CI).
   - After it  : 850, the last-resort broad name search; if that also declines,
                 the out-of-box Qualys rules (860 and above) get their turn.
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

    var ipGr = new GlideRecord('cmdb_ci_ip_address');
    if (!ipGr.isValid())                          // layered model not installed -> decline
        return null;
    ipGr.addQuery('ip_address', ip);              // IP Address record for "30.162.178.21"
    ipGr.addNotNullQuery('nic.cmdb_ci');          // ... attached to an adapter that belongs to a CI
    if (ignore)
        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    ipGr.query();
    var owners = {};                              // distinct owning CIs
    var count = 0, first = null;
    while (ipGr.next()) {
        var owner = '' + ipGr.nic.cmdb_ci;        // sys_id of the CI at the end of the chain
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1 && !isLoadBalancer(first))     // exactly one owner and not a load balancer -> match
        return first;
    return null;
})(rule, sourceValue, sourcePayload);
