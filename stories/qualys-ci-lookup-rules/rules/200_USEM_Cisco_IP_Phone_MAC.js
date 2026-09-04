/* =================================================================================================
   RULE 200 - USEM Cisco IP Phone MAC
   =================================================================================================
   Match Cisco IP phones. Cisco Unified Communications Manager names every phone "SEP" followed by
   its MAC address, and Qualys reports that name as the DNS host label. The rule turns the label
   back into a MAC address and looks for exactly one IP Phone CI that carries it.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "41277345",
     "IP": "30.144.62.108",
     "TRACKING_METHOD": "IP",
     "OS": "Cisco IP Phone",
     "DNS": "sep64f69dd5c9b0.voip.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "sep64f69dd5c9b0.voip.bankofamerica.com"
   sourcePayload = the whole record
   Expected for the sample: the IP Phone CI whose network adapter, mac_address field or name carries
   the MAC 64:F6:9D:D5:C9:B0, for example the phone "SEP64F69DD5C9B0". Any DNS name that does not
   follow the SEP pattern makes the rule decline at once.

   WHY THIS RULE SITS AT ORDER 200
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 175 and 180 handled serial numbers (phones report none).
   - Reaches it: only hosts whose DNS label reads SEP plus twelve hexadecimal characters; every
                 other host passes through untouched.
   - After it  : 250 and above are the name rules. Phones are resolved first so a phone label can
                 never be mistaken for a server name, and a MAC clash can never pull in a server or
                 a switch: this rule only searches IP Phone CIs.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    // ====== STAGE 1: Recognise the SEP label and rebuild the MAC address =========================
    // What   : takes the first label of the DNS name, checks it against the strict pattern "sep"
    //          plus exactly twelve hexadecimal characters, and rebuilds the MAC in the four
    //          spellings CMDBs use.
    // Why    : a server named "sepulveda01" must not be treated as a phone, hence the strict
    //          pattern; different discovery tools write MACs differently, hence the four spellings.
    // Sample : "sep64f69dd5c9b0.voip.bankofamerica.com" -> label "sep64f69dd5c9b0" -> hex
    //          "64f69dd5c9b0" -> candidates ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0",
    //          "64F69DD5C9B0", "64f69dd5c9b0"].
    // =============================================================================================
    var label = ('' + sourceValue).split('.')[0].toLowerCase();   // "sep64f69dd5c9b0"
    var m = label.match(/^sep([0-9a-f]{12})$/);  // null for anything that is not a phone label
    if (!m)
        return null;
    var hex = m[1];                               // "64f69dd5c9b0"
    var pairs = [];
    for (var i = 0; i < 12; i += 2)
        pairs.push(hex.substr(i, 2));             // ["64", "f6", "9d", "d5", "c9", "b0"]
    var colon = pairs.join(':');                  // "64:f6:9d:d5:c9:b0"
    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 2: Attempt 1: a network adapter with that MAC owned by an IP phone =============
    // What   : searches the Network Adapter table for adapters carrying one of the four spellings
    //          and belonging to a CI, keeps only owners that really are IP Phone CIs, each counted
    //          once, and accepts a single phone.
    // Why    : discovery tools usually store the MAC on the adapter, not on the phone. Checking
    //          that the owner is an IP Phone guarantees a switch or server adapter with a colliding
    //          MAC is never returned.
    // Sample : adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone
    //          "SEP64F69DD5C9B0" -> count = 1 -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // =============================================================================================
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('mac_address', 'IN', candidates.join(','));
    nic.addNotNullQuery('cmdb_ci');
    nic.query();
    var phones = {}, count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');
        var phone = new GlideRecord('cmdb_ci_ip_phone');
        if (phone.get(owner) && !phones[owner]) { // only IP phones count, once each
            phones[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1)
        return first;
    // ====== STAGE 3: Attempt 2: the MAC stored on the IP phone record itself =====================
    // What   : searches the IP Phone class for a phone whose own mac_address field is one of the
    //          four spellings and accepts it when it is the only one; otherwise attempt 3 runs.
    // Why    : some loads write the MAC on the phone record instead of an adapter record.
    // Sample : the IP Phone "SEP64F69DD5C9B0" with mac_address "64F69DD5C9B0" and no second row ->
    //          return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // =============================================================================================
    var ph = new GlideRecord('cmdb_ci_ip_phone');
    ph.addQuery('mac_address', 'IN', candidates.join(','));
    if (ignore)
        ph.addQuery('sys_class_name', 'NOT IN', ignore);
    ph.query();
    if (ph.next()) {
        var byMac = ph.getUniqueValue();
        if (!ph.hasNext())                        // exactly one phone -> match
            return byMac;
    }
    // ====== STAGE 4: Attempt 3: an IP phone named with its Unified CM device name ================
    // What   : searches the IP Phone class for a phone named "SEP64F69DD5C9B0" (the label in upper
    //          case) and accepts it when it is the only one.
    // Why    : a phone loaded from the call manager export carries no MAC on either record but is
    //          named exactly like the DNS label.
    // Sample : the IP Phone named "SEP64F69DD5C9B0" and no second row -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No phone at all -> null.
    // =============================================================================================
    var byName = new GlideRecord('cmdb_ci_ip_phone');
    byName.addQuery('name', label.toUpperCase());  // "SEP64F69DD5C9B0"
    if (ignore)
        byName.addQuery('sys_class_name', 'NOT IN', ignore);
    byName.query();
    if (!byName.next())
        return null;
    var named = byName.getUniqueValue();
    if (byName.hasNext())                         // two phones with one device name -> never guess
        return null;
    return named;
})(rule, sourceValue, sourcePayload);
