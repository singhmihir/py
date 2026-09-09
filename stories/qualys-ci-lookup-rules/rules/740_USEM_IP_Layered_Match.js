/* USEM IP Layered Match
   -------------------------------------------------------------------------------------------------
   Newer discovery writes each address as its own IP Address record linked to the adapter, and the
   adapter record itself may carry no address. This rule reads those records: IP Address -> Network
   Adapter -> CI.

   Input  : sourceValue is the IP field.
   Returns: the sys_id of the CI at the end of the chain IP Address -> adapter -> CI; null for
            several owners or a load balancer.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM IP Adapter Match looked for the address on the adapter records.
   Reaches: hosts whose address exists only as an IP Address record.
   After  : USEM FQDN Name Broad Match, and after that the out-of-box Qualys rules.
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
    // -- IP Address records carrying the address --------------------------------------------------
    // nic.cmdb_ci reaches the CI two links away; the record must belong to an adapter that belongs
    // to a CI outside the ignored classes.
    var ipGr = new GlideRecord('cmdb_ci_ip_address');
    if (!ipGr.isValid())                          // layered model not installed here, decline
        return null;
    ipGr.addQuery('ip_address', ip);
    ipGr.addNotNullQuery('nic.cmdb_ci');          // the chain must end on a CI
    if (ignore)
        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    ipGr.query();
    // -- One owning CI, and not a load balancer ---------------------------------------------------
    // Each distinct owning CI is counted once, so one device with two address records counts once
    // and two devices count twice. Two different owners cannot be told apart by the address and the
    // rule declines; a single owner that is a load balancer is refused too, because the address is
    // then a virtual IP and the scanned host sits behind it.
    var owners = {};
    var count = 0, first = null;
    while (ipGr.next()) {
        var owner = '' + ipGr.nic.cmdb_ci;
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
