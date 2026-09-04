/* =====================================================================
   RULE 350 - USEM Layered DNS Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "42773078",
     "IP": "167.202.60.26",
     "TRACKING_METHOD": "IP",
     "OS": "Red Hat Enterprise Linux Server 7.9",
     "DNS": "hklvteqoradbp3.hk.baml.com",
     "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"
   }

   sourceValue   = the DNS field  -> "hklvteqoradbp3.hk.baml.com"
   sourcePayload = the whole record above (IP is read from it)

   WHY THIS RULE SITS AT ORDER 350
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 250-310 looked at name fields stored on the CI record itself.
   - Reaches it: hosts whose name is not stored on the CI but in the layered
                 network model that CMDB discovery maintains: DNS Name record ->
                 IP Address record -> Network Adapter -> owning CI. This also
                 resolves aliases (a name that points at an address of the
                 device).
   - After it  : 400/410 (short hostname alone) and 450 (CI named with the full
                 FQDN).
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "hklvteqoradbp3.hk.baml.com"
    if (fqdn.indexOf('.') == -1)                  // bare label -> hostname rules handle it
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "167.202.60.26" - tie-breaker only

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // Walk the chain DNS name -> IP address -> adapter -> owning CI.
    // cmdb_ip_address_dns_name links a DNS Name record to an IP Address record;
    // the IP Address record knows its adapter (nic), and the adapter knows the CI.
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    if (!gr.isValid())                            // layered model not installed -> decline
        return null;
    gr.addQuery('dns_name.name', fqdn);           // DNS Name record named "hklvteqoradbp3.hk.baml.com"
    gr.addNotNullQuery('ip_address.nic.cmdb_ci'); // ... whose address sits on an adapter that belongs to a CI
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    gr.query();
    var owners = {};                              // distinct owning CIs, keyed by sys_id
    var ipOwners = {};                            // owners whose linked address is also the scanned IP
    var count = 0, first = null;
    while (gr.next()) {
        var owner = '' + gr.ip_address.nic.cmdb_ci;   // sys_id of the CI at the end of the chain
        if (!owners[owner]) {                     // count each CI once even if it has several addresses
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        if (ip && ('' + gr.ip_address.ip_address) == ip)   // this chain runs through 167.202.60.26
            ipOwners[owner] = true;
    }
    if (count == 1)                               // one CI answers to that name -> match
        return first;
    if (count > 1) {                              // several CIs: accept the single one confirmed by the scanned IP
        var confirmed = Object.keys(ipOwners);
        if (confirmed.length == 1)
            return confirmed[0];
    }
    return null;                                  // none, or an unresolved tie -> decline
})(rule, sourceValue, sourcePayload);
