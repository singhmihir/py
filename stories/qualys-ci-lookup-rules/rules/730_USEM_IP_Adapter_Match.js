/* USEM IP Adapter Match
   -------------------------------------------------------------------------------------------------
   Discovery stores one Network Adapter record per network card, and a multi-homed server keeps its
   addresses there rather than on the CI record. This rule finds the adapter carrying the scanned
   address and takes its owning CI.

   Input  : sourceValue is the IP field.
   Returns: the sys_id of the CI that owns the adapter carrying the scanned address; null when
            adapters of two different CIs carry it or the owner is a load balancer.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the address rules so far looked at the ip_address field of the CI record itself.
   Reaches: hosts whose address is stored on an adapter record only.
   After  : USEM IP Layered Match and then the last-resort name rule.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // e.g. "30.162.178.21"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // A load balancer answers on virtual addresses for the servers behind it, so it is never the
    // host that was scanned.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }
    // -- Adapters carrying the address ------------------------------------------------------------
    // Adapters with the scanned address that belong to a CI outside the ignored classes.
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);
    nic.addNotNullQuery('cmdb_ci');               // the adapter must belong to a CI
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    nic.query();
    // -- One owning CI, and not a load balancer ---------------------------------------------------
    // Each distinct owning CI is counted once, so one server with two adapters on the address
    // counts once and two servers count twice. Two different owners cannot be told apart by the
    // address and the rule declines; a single owner that is a load balancer is refused too, because
    // the address is then a virtual IP and the scanned host sits behind it.
    var owners = {};
    var count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');
        if (!owners[owner]) {
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
