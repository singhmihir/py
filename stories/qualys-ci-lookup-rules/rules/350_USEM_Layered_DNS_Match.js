/* =================================================================================================
   RULE 350 - USEM Layered DNS Match
   =================================================================================================
   PURPOSE
   Match through the layered network model that CMDB discovery maintains: a DNS Name record is
   linked to an IP Address record, the IP Address record belongs to a Network Adapter, and the
   adapter belongs to the CI. This finds hosts whose name is not written on the CI record at all,
   and it also resolves aliases.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "42773078",
     "IP": "167.202.60.26",
     "TRACKING_METHOD": "IP",
     "OS": "Red Hat Enterprise Linux Server 7.9",
     "DNS": "hklvteqoradbp3.hk.baml.com",
     "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"
   }

   sourceValue   = the DNS field of that record -> "hklvteqoradbp3.hk.baml.com"
   sourcePayload = the whole record above; the rule also reads the IP from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the CI at the end of the chain DNS Name
   "hklvteqoradbp3.hk.baml.com" -> IP Address "167.202.60.26" -> adapter "eth0" -> Linux Server
   "hklvteqoradbp3"; when several CIs answer to the name, the one whose chain runs through the
   scanned IP is taken.

   WHY THIS RULE SITS AT ORDER 350
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 250 to 310 looked at name fields stored on the CI record itself.
   - Reaches it: hosts whose name lives only in the layered DNS records, and aliases that point at
                 an address of the device.
   - After it  : 400/410 (short hostname alone) and 450 (CI named with the full FQDN).

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and require a domain part
    3. Note the scanned IP address for tie-breaks
    4. Read the list of CI classes that must never be matched
    5. Search the chain DNS Name -> IP Address -> adapter -> CI
    6. Collect the owning CIs
    7. Decide: one owner, or the owner confirmed by the scanned IP
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "hklvteqoradbp3.hk.baml.com" -> not empty -> the rule carries
    //                on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the DNS name and require a domain part
    // What happens : '' + sourceValue turns the value into plain text, trim() removes blanks at
    //                both ends and toLowerCase() lowers it. Then the rule requires at least one dot
    //                in the name.
    // Why          : DNS names are case-insensitive and CMDB values are stored in mixed case, so
    //                both sides are compared in lower case. A name without a dot is a bare
    //                hostname, which the hostname rules (400 and above) look after.
    // Sample       : fqdn = "hklvteqoradbp3.hk.baml.com"; indexOf(".") finds a dot -> carry on. A
    //                bare label "hklvteqoradbp3" has no dot -> indexOf(".") = -1 -> decline.
    // ---------------------------------------------------------------------------------------------
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    // -> fqdn = "hklvteqoradbp3.hk.baml.com".
    if (fqdn.indexOf('.') == -1)
        return null;
    // -> indexOf(".") = 14 for the sample (the position of the first dot) -> not -1 -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Note the scanned IP address for tie-breaks
    // What happens : copies the IP field of the payload into plain text, or an empty text when the
    //                payload has none.
    // Why          : the IP is not used to search; it is only used later to choose between two CIs
    //                that both carry the scanned name.
    // Sample       : ip = "167.202.60.26".
    // ---------------------------------------------------------------------------------------------
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';
    // -> ip = "167.202.60.26" (or "" when the payload has no IP field).
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - Read the list of CI classes that must never be matched
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
    // STAGE 5 - Search the chain DNS Name -> IP Address -> adapter -> CI
    // What happens : searches the link table cmdb_ip_address_dns_name, whose rows tie one DNS Name
    //                record to one IP Address record. Through dot-walking (field.field.field) the
    //                conditions reach the other records of the chain: dns_name.name is the name on
    //                the DNS Name record, ip_address.nic.cmdb_ci is the CI that owns the adapter
    //                that holds the IP Address record. Rows whose chain ends nowhere, or on an
    //                ignored class, are left out.
    // Why          : discovery writes names and addresses as separate records linked to the device
    //                instead of on the device record; this is the only rule that can see those, and
    //                because the chain ends on whatever device actually holds the address, an alias
    //                resolves to the real machine.
    // Sample       : the link row DNS Name "hklvteqoradbp3.hk.baml.com" <-> IP Address
    //                "167.202.60.26"; the IP Address record belongs to adapter "eth0"; adapter
    //                "eth0" belongs to the Linux Server "hklvteqoradbp3" (sys_id
    //                3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    // -> gr = a search on the IP Address to DNS Name link table.
    if (!gr.isValid())
        return null;
    // -> the layered model is not installed on this instance -> decline rather than fail.
    gr.addQuery('dns_name.name', fqdn);
    // -> condition added: the linked DNS Name record is named "hklvteqoradbp3.hk.baml.com".
    gr.addNotNullQuery('ip_address.nic.cmdb_ci');
    // -> condition added: the linked IP Address record belongs to an adapter (nic) that belongs to
    //    a CI (cmdb_ci); chains that stop early are left out.
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    // -> condition added: the class of the CI at the end of the chain is NOT IN
    //    (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci, cmdb_ci_unclassed_hardware,
    //    cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    gr.query();
    // -> the search has run; each row of the result is one name-to-address link whose chain ends on
    //    a CI.
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Collect the owning CIs
    // What happens : walks the result rows and records each distinct CI at the end of a chain;
    //                separately, records which of those CIs are reached through the scanned IP
    //                address.
    // Why          : one device with several addresses appears once per address, so each CI must be
    //                counted once; the IP bookkeeping prepares the tie-break of the next stage.
    // Sample       : one row -> owners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1,
    //                first = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"; because the row's IP Address
    //                record is "167.202.60.26", ipOwners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c":
    //                true}.
    // ---------------------------------------------------------------------------------------------
    var owners = {};
    var ipOwners = {};
    var count = 0, first = null;
    // -> owners = {} (every CI seen, keyed by sys_id), ipOwners = {} (the CIs reached through the
    //    scanned IP), count = 0, first = null.
    while (gr.next()) {
        // -> each pass of the loop looks at one link row.
        var owner = '' + gr.ip_address.nic.cmdb_ci;
        // -> owner = the sys_id of the CI at the end of this row's chain, for example
        //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        // -> the first time a CI is seen: owners gains it, count grows by one, and first remembers
        //    the very first CI. A second row for the same CI changes nothing.
        if (ip && ('' + gr.ip_address.ip_address) == ip)
            ipOwners[owner] = true;
        // -> when this row's IP Address record equals the scanned IP "167.202.60.26", the CI is
        //    noted in ipOwners.
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Decide: one owner, or the owner confirmed by the scanned IP
    // What happens : accepts the single CI when exactly one was collected. When several CIs answer
    //                to the name, accepts the one CI that was reached through the scanned IP,
    //                provided there is exactly one such CI. Otherwise declines.
    // Why          : a name that resolves to two devices (an alias moved between hosts, an old and
    //                a new record) must not be guessed; the scanned address is the additional
    //                evidence that makes the choice safe.
    // Sample       : count = 1 -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". count = 2 with
    //                ipOwners = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true} -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". count = 2 with ipOwners empty or holding
    //                both -> return null.
    // ---------------------------------------------------------------------------------------------
    if (count == 1)
        return first;
    // -> one CI at the end of every chain -> its sys_id goes back to the framework.
    if (count > 1) {
        var confirmed = Object.keys(ipOwners);
        // -> confirmed = the list of CIs reached through the scanned IP, for example
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"].
        if (confirmed.length == 1)
            return confirmed[0];
        // -> exactly one CI confirmed by the address -> return it.
    }
    return null;
    // -> no CI, or several without a single IP confirmation -> decline; the host continues to rule
    //    400.
})(rule, sourceValue, sourcePayload);
