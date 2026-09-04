/* =================================================================================================
   RULE 350 - USEM Layered DNS Match
   =================================================================================================
   Match through the layered network model that CMDB discovery maintains: a DNS Name record is
   linked to an IP Address record, the IP Address record belongs to a Network Adapter, and the
   adapter belongs to the CI. Finds hosts whose name is not written on the CI record at all, and
   resolves aliases.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "42773078",
     "IP": "167.202.60.26",
     "TRACKING_METHOD": "IP",
     "OS": "Red Hat Enterprise Linux Server 7.9",
     "DNS": "hklvteqoradbp3.hk.baml.com",
     "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"
   }

   sourceValue   = the DNS field -> "hklvteqoradbp3.hk.baml.com"
   sourcePayload = the whole record; the rule also reads the IP from it
   Expected for the sample: the CI at the end of the chain DNS Name "hklvteqoradbp3.hk.baml.com" ->
   IP Address "167.202.60.26" -> adapter "eth0" -> Linux Server "hklvteqoradbp3"; when several CIs
   answer to the name, the one whose chain runs through the scanned IP.

   WHY THIS RULE SITS AT ORDER 350
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 250 to 310 looked at name fields stored on the CI record itself.
   - Reaches it: hosts whose name lives only in the layered DNS records, and aliases that point at
                 an address of the device.
   - After it  : 400/410 (short hostname alone) and 450 (CI named with the full FQDN).
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "hklvteqoradbp3.hk.baml.com"
    if (fqdn.indexOf('.') == -1)                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "167.202.60.26", used only to break ties
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Search the chain DNS Name -> IP Address -> adapter -> CI ====================
    // What   : searches the link table cmdb_ip_address_dns_name, whose rows tie one DNS Name record
    //          to one IP Address record. Dot-walking reaches the rest of the chain: dns_name.name
    //          is the name on the DNS Name record, ip_address.nic.cmdb_ci is the CI owning the
    //          adapter that holds the IP Address record.
    // Why    : discovery writes names and addresses as separate records linked to the device; this
    //          is the only rule that can see them, and because the chain ends on whatever device
    //          holds the address, an alias resolves to the real machine.
    // Sample : DNS Name "hklvteqoradbp3.hk.baml.com" <-> IP Address "167.202.60.26" -> adapter
    //          "eth0" -> Linux Server "hklvteqoradbp3" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    if (!gr.isValid())                            // layered model not installed -> decline
        return null;
    gr.addQuery('dns_name.name', fqdn);           // the DNS Name record is named "hklvteqoradbp3.hk.baml.com"
    gr.addNotNullQuery('ip_address.nic.cmdb_ci'); // the chain must end on a CI
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    gr.query();
    // ====== STAGE 2: Collect the owning CIs and decide ===========================================
    // What   : counts each distinct CI at the end of a chain once and notes which of them are
    //          reached through the scanned IP. One CI -> match. Several CIs but exactly one reached
    //          through the scanned IP -> that one. Otherwise null.
    // Why    : a name that resolves to two devices (an alias moved between hosts, an old and a new
    //          record) must not be guessed; the scanned address is the extra evidence that makes
    //          the choice safe.
    // Sample : one row -> count = 1 -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". Two CIs with
    //          ipOwners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true} -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". Two CIs and no single IP confirmation -> null
    //          and rule 400 gets its turn.
    // =============================================================================================
    var owners = {}, ipOwners = {};
    var count = 0, first = null;
    while (gr.next()) {
        var owner = '' + gr.ip_address.nic.cmdb_ci;   // sys_id of the CI at the end of the chain
        if (!owners[owner]) {                     // count each CI once
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
