/* USEM Cisco IP Phone MAC
   -------------------------------------------------------------------------------------------------
   Cisco Unified Communications Manager names every phone "SEP" followed by its MAC address, and
   Qualys reports that name as the DNS label (under voip.bankofamerica.com in our feed). The rule
   turns the label back into a MAC address and looks for exactly one IP Phone CI that carries it.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "41277345",
     "IP": "30.144.62.108",
     "TRACKING_METHOD": "IP",
     "OS": "Cisco IP Phone",
     "DNS": "sep64f69dd5c9b0.voip.bankofamerica.com"
   }
   Input  : sourceValue is the DNS field, "sep64f69dd5c9b0.voip.bankofamerica.com".
   Returns: the sys_id of the IP Phone CI whose network adapter, mac_address field or name carries
            that MAC; null for any label that is not a phone label, and when no phone or two phones
            carry the MAC.
   Sample : the IP Phone CI "SEP64F69DD5C9B0", found through the adapter that carries the MAC
            64:F6:9D:D5:C9:B0.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the serial number rules (phones report none).
   Reaches: only hosts whose DNS label is "sep" plus twelve hexadecimal characters; every other host
            passes through untouched.
   After  : the FQDN and hostname rules. Phones are resolved before them so a phone label is never
            tried as a server name, and because only IP Phone CIs are searched a MAC clash can never
            pull in a switch or a server.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    // -- Recognise the phone label and rebuild the MAC address ------------------------------------
    // The first label of the DNS name must be exactly "sep" plus twelve hex characters; a server
    // called "sepulveda01" must not be treated as a phone. The MAC is rebuilt in the four spellings
    // the CMDB holds, because discovery tools and the call manager export write it differently.
    // Sample: "sep64f69dd5c9b0.voip.bankofamerica.com" gives the label "sep64f69dd5c9b0", the hex
    //         "64f69dd5c9b0" and candidates ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0",
    //         "64F69DD5C9B0", "64f69dd5c9b0"].
    var label = ('' + sourceValue).split('.')[0].toLowerCase();   // "sep64f69dd5c9b0"
    var m = label.match(/^sep([0-9a-f]{12})$/);
    if (!m)
        return null;
    var hex = m[1];                               // "64f69dd5c9b0"
    var pairs = [];
    for (var i = 0; i < 12; i += 2)
        pairs.push(hex.substr(i, 2));             // ["64", "f6", "9d", "d5", "c9", "b0"]
    var colon = pairs.join(':');                  // "64:f6:9d:d5:c9:b0"
    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Find the one phone that carries the MAC --------------------------------------------------
    // Three places are tried in turn: a network adapter with that MAC whose owner is an IP Phone CI
    // (discovery usually stores the MAC on the adapter), the mac_address field on the phone record
    // itself, and finally a phone named with the Unified CM device name. Each place must yield
    // exactly one phone; two phones on one MAC or one device name is never guessed. Checking that
    // the adapter owner really is an IP Phone is what keeps a switch or server adapter with a
    // colliding MAC out.
    // Sample: the adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone
    //         "SEP64F69DD5C9B0"; count is 1, so that phone is returned from the first attempt. A
    //         phone with the MAC on its own record, or one simply named "SEP64F69DD5C9B0", would be
    //         found by the second or third attempt.
    var nic = new GlideRecord('cmdb_ci_network_adapter');   // 1. adapter with that MAC, owned by an IP phone
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
    var ph = new GlideRecord('cmdb_ci_ip_phone');           // 2. the MAC stored on the phone record
    ph.addQuery('mac_address', 'IN', candidates.join(','));
    if (ignore)
        ph.addQuery('sys_class_name', 'NOT IN', ignore);
    ph.query();
    if (ph.next()) {
        var byMac = ph.getUniqueValue();
        if (!ph.hasNext())
            return byMac;
    }
    var byName = new GlideRecord('cmdb_ci_ip_phone');       // 3. the phone named with its device name
    byName.addQuery('name', label.toUpperCase());  // "SEP64F69DD5C9B0"
    if (ignore)
        byName.addQuery('sys_class_name', 'NOT IN', ignore);
    byName.query();
    if (!byName.next())
        return null;
    var named = byName.getUniqueValue();
    if (byName.hasNext())
        return null;
    return named;
})(rule, sourceValue, sourcePayload);
