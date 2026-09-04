/* =====================================================================
   RULE 200 - USEM Cisco IP Phone MAC
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "41277345",
     "IP": "30.144.62.108",
     "TRACKING_METHOD": "IP",
     "OS": "Cisco IP Phone",
     "DNS": "sep64f69dd5c9b0.voip.bankofamerica.com"
   }

   sourceValue   = the DNS field  -> "sep64f69dd5c9b0.voip.bankofamerica.com"
   sourcePayload = the whole record above

   WHY THIS RULE SITS AT ORDER 200
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 175/180 handled serial numbers.
   - Reaches it: Cisco phones only: Cisco Unified Communications Manager names
                 every phone "SEP" + its MAC address and Qualys reports that
                 name as the DNS host label. The rule recognises the SEP pattern
                 and leaves every other DNS name untouched.
   - After it  : 250 and above are the hostname rules; phones are resolved here
                 first so a phone label can never be mistaken for a server name,
                 and a MAC clash can never pull in a server or a switch.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    // Keep only the first label of the DNS name, in lower case:
    // "sep64f69dd5c9b0.voip.bankofamerica.com" -> "sep64f69dd5c9b0"
    var label = ('' + sourceValue).split('.')[0].toLowerCase();
    // Does the label read "sep" followed by exactly 12 hexadecimal characters?
    var m = label.match(/^sep([0-9a-f]{12})$/);  // yes -> m[1] captures "64f69dd5c9b0"
    if (!m)                                       // "wsaoi01zeapd1" does not fit the pattern -> not a phone, decline
        return null;
    var hex = m[1];                               // "64f69dd5c9b0"
    var pairs = [];
    for (var i = 0; i < 12; i += 2)               // cut the 12 characters into 6 pairs: 64 f6 9d d5 c9 b0
        pairs.push(hex.substr(i, 2));
    var colon = pairs.join(':');                  // "64:f6:9d:d5:c9:b0"
    // The CMDB may store the MAC in any of these four spellings:
    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];
    // -> "64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // Attempt 1: the MAC sits on a network adapter that belongs to an IP phone CI
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('mac_address', 'IN', candidates.join(','));   // mac_address is one of the four spellings
    nic.addNotNullQuery('cmdb_ci');               // adapter must belong to a CI
    nic.query();
    var phones = {};                              // distinct phone CIs found, keyed by sys_id
    var count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');      // the CI owning the adapter
        var phone = new GlideRecord('cmdb_ci_ip_phone');
        if (phone.get(owner) && !phones[owner]) { // count it only if that CI really is an IP phone, once per phone
            phones[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1)                               // exactly one phone owns an adapter with this MAC -> match
        return first;

    // Attempt 2: the MAC is stored directly on the phone CI record
    var ph = new GlideRecord('cmdb_ci_ip_phone');
    ph.addQuery('mac_address', 'IN', candidates.join(','));    // mac_address is one of the four spellings
    if (ignore)
        ph.addQuery('sys_class_name', 'NOT IN', ignore);
    ph.query();
    if (ph.next()) {                              // at least one phone carries the MAC
        var byMac = ph.getUniqueValue();
        if (!ph.hasNext())                        // and it is the only one -> match
            return byMac;
    }                                             // none, or two phones sharing one MAC -> try the device name next

    // Attempt 3: the phone CI is named after its Unified CM device name
    var byName = new GlideRecord('cmdb_ci_ip_phone');
    byName.addQuery('name', label.toUpperCase());              // name = "SEP64F69DD5C9B0"
    if (ignore)
        byName.addQuery('sys_class_name', 'NOT IN', ignore);
    byName.query();
    if (!byName.next())                           // no phone named like that -> decline
        return null;
    var named = byName.getUniqueValue();
    if (byName.hasNext())                         // several phones with that name -> decline
        return null;
    return named;
})(rule, sourceValue, sourcePayload);
