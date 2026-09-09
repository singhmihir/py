/* USEM Layered DNS Match
   -------------------------------------------------------------------------------------------------
   Discovery keeps names and addresses as their own records linked to the device: a DNS Name record
   is tied to an IP Address record, the IP Address record belongs to a Network Adapter, and the
   adapter belongs to the CI. This rule follows that chain, which is the only way to find a host
   whose name is not written on the CI record at all, and it resolves aliases to the real machine.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "42773078",
     "IP": "167.202.60.26",
     "TRACKING_METHOD": "IP",
     "OS": "Red Hat Enterprise Linux Server 7.9",
     "DNS": "hklvteqoradbp3.hk.baml.com",
     "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"
   }
   Input  : sourceValue is the DNS field, "hklvteqoradbp3.hk.baml.com"; the rule also reads the IP
            from sourcePayload.
   Returns: the sys_id of the CI at the end of the chain DNS Name -> IP Address -> adapter -> CI;
            when several CIs answer to the name, the one whose chain runs through the scanned IP;
            null otherwise.
   Sample : the Linux Server "hklvteqoradbp3", reached through DNS Name "hklvteqoradbp3.hk.baml.com"
            -> IP Address "167.202.60.26" -> adapter "eth0".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the FQDN and hostname-plus-domain rules looked at name fields stored on the CI record
            itself.
   Reaches: hosts whose name lives only in the discovery DNS records, and aliases that point at an
            address of the device.
   After  : the plain hostname rules and USEM FQDN Name Hardware Match.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "hklvteqoradbp3.hk.baml.com"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "167.202.60.26", only used to break a tie
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Follow the chain DNS Name -> IP Address -> adapter -> CI ---------------------------------
    // cmdb_ip_address_dns_name ties one DNS Name record to one IP Address record; dot-walking
    // reaches the rest: dns_name.name is the name on the DNS Name record and ip_address.nic.cmdb_ci
    // is the CI owning the adapter that holds the address. Because the chain ends on whatever
    // device holds the address, an alias resolves to the real machine.
    // Sample: the DNS Name record "hklvteqoradbp3.hk.baml.com" is linked to the IP Address record
    //         "167.202.60.26", which belongs to the adapter "eth0" of the Linux Server
    //         "hklvteqoradbp3"; that is the one row the query returns.
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    if (!gr.isValid())                            // layered model not installed here, decline
        return null;
    gr.addQuery('dns_name.name', fqdn);           // "hklvteqoradbp3.hk.baml.com"
    gr.addNotNullQuery('ip_address.nic.cmdb_ci'); // the chain must end on a CI
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    gr.query();
    // -- One CI at the end of the chain, scanned IP as the tie-break ------------------------------
    // Each distinct CI is counted once, and the CIs reached through the scanned address are noted.
    // One CI is the match. A name that resolves to two devices (an alias moved between hosts, an
    // old and a new record) is taken only when exactly one of them is reached through the scanned
    // IP; otherwise the rule declines.
    // Sample: one row, so count is 1 and the sys_id of "hklvteqoradbp3" is returned. Were the name
    //         also linked to an address of a second device, ipOwners would hold only the CI reached
    //         through "167.202.60.26" and that one would be returned.
    var owners = {}, ipOwners = {};
    var count = 0, first = null;
    while (gr.next()) {
        var owner = '' + gr.ip_address.nic.cmdb_ci;
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        if (ip && ('' + gr.ip_address.ip_address) == ip)   // this chain runs through the scanned IP
            ipOwners[owner] = true;
    }
    if (count == 1)
        return first;
    if (count > 1) {
        var confirmed = Object.keys(ipOwners);
        if (confirmed.length == 1)
            return confirmed[0];
    }
    return null;
})(rule, sourceValue, sourcePayload);
