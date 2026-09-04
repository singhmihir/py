/* =================================================================================================
   RULE 200 - USEM Cisco IP Phone MAC
   =================================================================================================
   PURPOSE
   Match Cisco IP phones. Cisco Unified Communications Manager names every phone "SEP" followed by
   the phone's MAC address, and Qualys reports that name as the DNS host label. The rule turns the
   label back into a MAC address and looks for exactly one IP Phone CI that carries it.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "41277345",
     "IP": "30.144.62.108",
     "TRACKING_METHOD": "IP",
     "OS": "Cisco IP Phone",
     "DNS": "sep64f69dd5c9b0.voip.bankofamerica.com"
   }

   sourceValue   = the DNS field of that record -> "sep64f69dd5c9b0.voip.bankofamerica.com"
   sourcePayload = the whole record above
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the IP Phone CI whose network adapter, mac_address field or name
   carries the MAC 64:F6:9D:D5:C9:B0, for example the phone named "SEP64F69DD5C9B0"; its sys_id is
   returned. Any DNS name that does not follow the SEP pattern makes the rule decline at once.

   WHY THIS RULE SITS AT ORDER 200
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 175 and 180 handled serial numbers (phones report none).
   - Reaches it: only hosts whose DNS label reads SEP plus twelve hexadecimal characters; every
                 other host passes through untouched.
   - After it  : 250 and above are the name rules. Phones are resolved here first so a phone label
                 can never be mistaken for a server name, and so a MAC address clash can never pull
                 in a server or a switch: this rule only ever searches IP Phone CIs.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Take the first label of the DNS name
    3. Recognise the SEP pattern and extract the MAC address
    4. Spell the MAC address the four ways CMDBs store it
    5. Read the list of CI classes that must never be matched
    6. Attempt 1: a network adapter with that MAC that belongs to an IP phone
    7. Attempt 2: the MAC stored on the IP phone record itself
    8. Attempt 3: an IP phone named with its Unified CM device name
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "sep64f69dd5c9b0.voip.bankofamerica.com" -> not empty -> the
    //                rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Take the first label of the DNS name
    // What happens : splits the DNS name at the dots, keeps the first part and lowers it.
    // Why          : the phone identity is in the first label only; the rest
    //                ("voip.bankofamerica.com") is the telephony domain shared by every phone.
    // Sample       : "sep64f69dd5c9b0.voip.bankofamerica.com" -> split(".") = ["sep64f69dd5c9b0",
    //                "voip", "bankofamerica", "com"] -> [0] = "sep64f69dd5c9b0".
    // ---------------------------------------------------------------------------------------------
    var label = ('' + sourceValue).split('.')[0].toLowerCase();
    // -> label = "sep64f69dd5c9b0".
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Recognise the SEP pattern and extract the MAC address
    // What happens : checks the label against the pattern "sep" followed by exactly twelve
    //                hexadecimal characters (0 to 9, a to f) and nothing else. When it fits, the
    //                twelve characters are kept as the MAC address.
    // Why          : a server named "sepulveda01" must not be treated as a phone, so the pattern is
    //                strict: exactly "sep", exactly twelve hex characters, from the start to the
    //                end of the label.
    // Sample       : "sep64f69dd5c9b0" fits -> hex = "64f69dd5c9b0". "wsaoi01zeapd1" does not fit
    //                -> the rule declines and the host goes on to the name rules.
    // ---------------------------------------------------------------------------------------------
    var m = label.match(/^sep([0-9a-f]{12})$/);
    // -> m = ["sep64f69dd5c9b0", "64f69dd5c9b0"] (the whole match and the captured twelve
    //    characters), or null when the label does not fit.
    if (!m)
        return null;
    // -> m is null for every host that is not a phone -> decline; for the sample m is filled ->
    //    carry on.
    var hex = m[1];
    // -> hex = "64f69dd5c9b0".
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - Spell the MAC address the four ways CMDBs store it
    // What happens : cuts the twelve characters into six pairs, joins them with colons, and
    //                prepares four spellings: colon-separated upper case, colon-separated lower
    //                case, plain upper case and plain lower case.
    // Why          : different discovery tools write MAC addresses differently; searching all four
    //                spellings at once means the phone is found whichever tool created its record.
    // Sample       : pairs = ["64", "f6", "9d", "d5", "c9", "b0"]; colon = "64:f6:9d:d5:c9:b0";
    //                candidates = ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0",
    //                "64f69dd5c9b0"].
    // ---------------------------------------------------------------------------------------------
    var pairs = [];
    // -> pairs = [] (empty list to start with).
    for (var i = 0; i < 12; i += 2)
        pairs.push(hex.substr(i, 2));
    // -> i takes the values 0, 2, 4, 6, 8, 10; substr(i, 2) cuts two characters at each position ->
    //    pairs = ["64", "f6", "9d", "d5", "c9", "b0"].
    var colon = pairs.join(':');
    // -> colon = "64:f6:9d:d5:c9:b0".
    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];
    // -> candidates = ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"].
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - Read the list of CI classes that must never be matched
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
    // STAGE 6 - Attempt 1: a network adapter with that MAC that belongs to an IP phone
    // What happens : searches the Network Adapter table for adapters whose mac_address is one of
    //                the four spellings and that belong to a CI, then keeps only the owners that
    //                really are IP Phone CIs, each counted once.
    // Why          : discovery tools usually store the MAC on the adapter record, not on the phone
    //                itself. Checking that the owner is an IP Phone guarantees that a switch or
    //                server adapter with a colliding MAC is never returned.
    // Sample       : adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone
    //                "SEP64F69DD5C9B0" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c) -> phones =
    //                {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1, first =
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // ---------------------------------------------------------------------------------------------
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    // -> nic = a search on the Network Adapter table.
    nic.addQuery('mac_address', 'IN', candidates.join(','));
    // -> condition added: mac_address IN ("64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0",
    //    "64f69dd5c9b0").
    nic.addNotNullQuery('cmdb_ci');
    // -> condition added: cmdb_ci is not empty, so only adapters that belong to a CI are
    //    considered.
    nic.query();
    // -> the search has run; nic sits before the first adapter of the result.
    var phones = {};
    var count = 0, first = null;
    // -> phones = {} (phone CIs already counted, keyed by sys_id), count = 0, first = null.
    while (nic.next()) {
        // -> each pass of the loop looks at one adapter carrying the MAC.
        var owner = nic.getValue('cmdb_ci');
        // -> owner = the sys_id of the CI that owns the adapter, for example
        //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
        var phone = new GlideRecord('cmdb_ci_ip_phone');
        if (phone.get(owner) && !phones[owner]) {
            // -> phone.get(owner) is true only when that CI is an IP Phone; !phones[owner] is true
            //    the first time this phone is seen.
            phones[owner] = true;
            count++;
            if (count == 1)
                first = owner;
            // -> phones = {"3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c": true}, count = 1, first =
            //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" after the first phone; a second, different
            //    phone would make count = 2.
        }
        // -> an adapter owned by a server or a switch is skipped here, so it can never be counted.
    }
    if (count == 1)
        return first;
    // -> exactly one phone owns an adapter with this MAC -> return its sys_id
    //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". Zero phones -> attempt 2. Two phones -> attempt 2 as
    //    well, the record itself may settle it.
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Attempt 2: the MAC stored on the IP phone record itself
    // What happens : searches the IP Phone table for phones whose own mac_address field is one of
    //                the four spellings (ignored classes left out) and accepts the phone only when
    //                it is the single one.
    // Why          : some loads write the MAC on the phone record instead of an adapter record;
    //                this attempt covers them without ever leaving the IP Phone class.
    // Sample       : the IP Phone "SEP64F69DD5C9B0" with mac_address = "64F69DD5C9B0" -> byMac =
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" and no second row -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // ---------------------------------------------------------------------------------------------
    var ph = new GlideRecord('cmdb_ci_ip_phone');
    // -> ph = a search on the IP Phone class.
    ph.addQuery('mac_address', 'IN', candidates.join(','));
    // -> condition added: mac_address IN (the four spellings).
    if (ignore)
        ph.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    ph.query();
    // -> the search has run.
    if (ph.next()) {
        // -> at least one phone carries the MAC on its record.
        var byMac = ph.getUniqueValue();
        // -> byMac = the sys_id of that phone, for example "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
        if (!ph.hasNext())
            return byMac;
        // -> no second phone -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". A second phone with the
        //    same MAC -> fall through to attempt 3.
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 8 - Attempt 3: an IP phone named with its Unified CM device name
    // What happens : searches the IP Phone table for a phone whose name is the label in upper case
    //                ("SEP64F69DD5C9B0"), the device name Unified CM assigns, and accepts it only
    //                when it is the single one.
    // Why          : a phone loaded from the call manager export has no MAC on either record, but
    //                it is named exactly like the DNS label; this attempt catches those without
    //                loosening any check.
    // Sample       : the IP Phone named "SEP64F69DD5C9B0" -> named =
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" and no second row -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No phone at all -> return null and the
    //                host continues to rule 250.
    // ---------------------------------------------------------------------------------------------
    var byName = new GlideRecord('cmdb_ci_ip_phone');
    // -> byName = a search on the IP Phone class.
    byName.addQuery('name', label.toUpperCase());
    // -> condition added: name = "SEP64F69DD5C9B0".
    if (ignore)
        byName.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    byName.query();
    // -> the search has run.
    if (!byName.next())
        return null;
    // -> no phone with that name -> decline; the host goes on to the name rules, which will not
    //    recognise a SEP label either, so it ends up unmatched for review.
    var named = byName.getUniqueValue();
    // -> named = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    if (byName.hasNext())
        return null;
    // -> two phones with the same device name -> ambiguous -> decline.
    return named;
    // -> exactly one phone -> its sys_id goes back to the framework.
})(rule, sourceValue, sourcePayload);
