/* USEM Network Interface Name Match
   -------------------------------------------------------------------------------------------------
   Network devices are scanned through their interface and VLAN addresses, and each of those carries
   a DNS label made of the device name plus an interface tail ("-cz04-hsrp-vlan705", "-atm1-v201",
   "-aom"), while the device CI is named with the leading part only. The rule walks the label from
   the longest prefix to the shortest and takes the first prefix that names exactly one network
   device.

   Input  : sourceValue is the DNS field; the rule also reads the OS from sourcePayload.
   Returns: the sys_id of the one Network Gear or Load Balancer device CI named with a prefix of the
            label; null when the host shows no interface evidence, when no prefix names a device, or
            when a prefix names two.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hostname rules tried the whole label and USEM Management Interface Match looked for
            a controller suffix.
   Reaches: hosts whose DNS domain is an interface domain (".network." in our feed, property
            usem.ci_lookup.interface_domains) or whose label contains an interface marker segment
            such as "vlan705", "v201", "hsrp", "aom" (property usem.ci_lookup.interface_markers).
   After  : USEM FQDN Name Hardware Match and USEM Load Balancer Service Match.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // e.g. "uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com"
    var label = full.split('.')[0];
    var segments = label.split('-');              // ["uspaltwrr01drm0119", "cz04", "hsrp", "vlan705"]
    if (segments.length < 2)                      // no hyphen, no interface tail
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // list() reads a comma separated system property into a lower-cased list, falling back to the
    // default shipped with the rule; the lists are tuned in the properties, not in the script.
    function list(name, fallback) {
        var parts = ('' + gs.getProperty(name, fallback)).split(',');
        var out = [];
        for (var i = 0; i < parts.length; i++) {
            var item = parts[i].trim().toLowerCase();
            if (item)
                out.push(item);
        }
        return out;
    }
    // isMarker() says whether one hyphen segment of the label is a listed marker: the word itself
    // ("vlan"), the word followed by digits only ("vlan705", "v201"), or, for words of three
    // letters or more, a segment ending in the word ("multihostvip").
    function isMarker(segment, words) {
        for (var i = 0; i < words.length; i++) {
            var w = words[i];
            if (segment == w)
                return true;
            if (segment.indexOf(w) == 0 && /^[0-9]+$/.test(segment.substring(w.length)))
                return true;
            if (w.length >= 3 && segment.length > w.length && segment.substring(segment.length - w.length) == w)
                return true;
        }
        return false;
    }
    // -- Interface evidence first -----------------------------------------------------------------
    // The rule goes on only when the DNS domain contains a listed interface domain or one of the
    // segments after the first is a listed marker. Plenty of ordinary server names contain hyphens
    // ("ah-1047132-001"); without this check the prefix walk would strip real hostnames and could
    // land on an unrelated device.
    var domains = list('usem.ci_lookup.interface_domains', '.network.');
    var markers = list('usem.ci_lookup.interface_markers', 'vlan,v,hsrp,vrrp,po,eth,gi,te,lo,mgmt,aom,vs,fab');
    var evidence = false;
    for (var d = 0; d < domains.length; d++)
        if (full.indexOf(domains[d]) != -1)
            evidence = true;
    for (var s = 1; s < segments.length; s++)
        if (isMarker(segments[s], markers))
            evidence = true;
    if (!evidence)
        return null;
    // -- Walk the prefixes from the longest to the shortest ---------------------------------------
    // One segment is dropped from the right at a time and the prefix is searched as a device name.
    // The device name is the leading part of the label but its length varies by site, and trying
    // the longest prefix first keeps "site-device-01" from being cut down to "site" when a CI with
    // the longer name exists. The first prefix that finds anything decides: one CI is the match,
    // two CIs mean the rule declines. Network devices live in two branches of the CMDB, Network
    // Gear (switches, routers, firewalls) and Load Balancer, which the platform files under Server;
    // both are searched and the hits are counted together.
    var tables = ['cmdb_ci_netgear', 'cmdb_ci_lb'];
    for (var k = segments.length - 1; k >= 1; k--) {
        var base = segments.slice(0, k).join('-');   // longest prefix first, e.g. "uspaltwrr01drm0119-cz04-hsrp"
        var hits = [];
        for (var t = 0; t < tables.length; t++) {
            var gr = new GlideRecord(tables[t]);
            if (!gr.isValid())
                continue;
            gr.addQuery('name', base);
            if (ignore)
                gr.addQuery('sys_class_name', 'NOT IN', ignore);
            gr.query();
            while (gr.next() && hits.length < 2)
                hits.push(gr.getUniqueValue());
        }
        if (hits.length == 0)                     // nothing named like this, try a shorter prefix
            continue;
        if (hits.length > 1)                      // two devices carry this name, never guess
            return null;
        return hits[0];
    }
    return null;
})(rule, sourceValue, sourcePayload);
