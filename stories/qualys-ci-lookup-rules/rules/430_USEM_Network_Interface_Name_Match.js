/* =================================================================================================
   RULE 430 - USEM Network Interface Name Match
   =================================================================================================
   Match a network device scanned through one of its interface or VLAN addresses. Such addresses
   carry a DNS label made of the device name plus an interface tail ("-cz04-hsrp-vlan705",
   "-atm1-v201", "-aom"), and the device CI is named by the leading part only. The rule walks the
   label from the longest prefix to the shortest and accepts the first prefix that names exactly one
   Network Gear CI.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "1187423005",
     "IP": "171.149.3.49",
     "TRACKING_METHOD": "IP",
     "OS": "Linux 2.6",
     "DNS": "uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the OS from it
   Expected for the sample: the network device named "uspaltwrr01drm0119" (an IP Switch, router,
   firewall or load balancer device); null when no prefix names a device or when a prefix names two.

   WHY THIS RULE SITS AT ORDER 430
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 400/410 tried the whole label as a hostname; 420 looked for a management controller
                 suffix.
   - Reaches it: hosts whose DNS domain is an interface domain (".network." by default, property
                 usem.ci_lookup.interface_domains) or whose label contains an interface marker
                 segment such as "vlan705", "v201", "hsrp", "aom" (property
                 usem.ci_lookup.interface_markers).
   - After it  : 450 (CI named with the full FQDN) and 460 (load balancer services).
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com"
    var label = full.split('.')[0];               // "uspaltwrr01drm0119-cz04-hsrp-vlan705"
    var segments = label.split('-');              // ["uspaltwrr01drm0119", "cz04", "hsrp", "vlan705"]
    if (segments.length < 2)                      // no hyphen -> no interface tail -> decline
        return null;
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // list() reads a comma separated system property into a lower-cased list, falling back to the
    // default shipped with the rule. Administrators tune the rule by editing the property, not the
    // script.
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
    // isMarker() reports whether one hyphen segment of the label is a listed marker: the word
    // itself ("vlan"), the word followed by digits only ("vlan705", "v201"), or, for words of three
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
    // ====== STAGE 1: Require interface evidence ==================================================
    // What   : the rule goes on only when the DNS domain contains a listed interface domain, or one
    //          of the segments after the first is a listed interface marker.
    // Why    : plenty of ordinary server names contain hyphens ("ah-1047132-001"); without the
    //          interface evidence the prefix walk would strip real hostnames and could land on an
    //          unrelated device.
    // Sample : ".network." is found in the sample name -> evidence.
    //          "gtcmmrlpa05a-vlan10.corp.bankofamerica.com" -> segment "vlan10" is a marker ->
    //          evidence. "ah-1047132-001.corp.bankofamerica.com" -> neither -> decline.
    // =============================================================================================
    var domains = list('usem.ci_lookup.interface_domains', '.network.');
    var markers = list('usem.ci_lookup.interface_markers', 'vlan,v,hsrp,vrrp,po,eth,gi,te,lo,mgmt,aom,vs,fab');
    var evidence = false;
    for (var d = 0; d < domains.length; d++)
        if (full.indexOf(domains[d]) != -1)
            evidence = true;
    for (var s = 1; s < segments.length; s++)
        if (isMarker(segments[s], markers))
            evidence = true;
    // -> evidence = true for the sample (the domain contains ".network." and "vlan705" is a marker)
    if (!evidence)
        return null;
    // ====== STAGE 2: Walk the prefixes from the longest to the shortest against Network Gear =====
    // What   : drops one segment at a time from the right and searches Network Gear (switches,
    //          routers, firewalls) and Load Balancer devices for a CI with exactly that name. The
    //          first prefix that finds anything decides: one CI is the match, two CIs mean the rule
    //          declines.
    // Why    : the device name is the leading part of the label but its length varies by site;
    //          trying the longest prefix first keeps "site-device-01" from being cut down to "site"
    //          when a CI named with the longer form exists.
    // Sample : prefixes tried: "uspaltwrr01drm0119-cz04-hsrp" (none), "uspaltwrr01drm0119-cz04"
    //          (none), "uspaltwrr01drm0119" (the IP Switch "uspaltwrr01drm0119") -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". Two switches named "ustxrdnwl01rsm004z" -> null.
    // =============================================================================================
    // Network devices live in two branches of the CMDB: Network Gear (switches, routers, firewalls)
    // and Load Balancer, which the platform files under Server. Both are searched; the hits are
    // counted together.
    var tables = ['cmdb_ci_netgear', 'cmdb_ci_lb'];
    for (var k = segments.length - 1; k >= 1; k--) {
        var base = segments.slice(0, k).join('-');   // "uspaltwrr01drm0119-cz04-hsrp", then "uspaltwrr01drm0119-cz04", then "uspaltwrr01drm0119"
        var hits = [];                            // sys_ids of the devices named exactly like this prefix
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
        if (hits.length == 0)                     // nothing named like this -> try a shorter prefix
            continue;
        if (hits.length > 1)                      // two devices carry this name -> never guess
            return null;
        return hits[0];
    }
    return null;
    // -> no prefix names a device -> decline; the host continues to rule 450
})(rule, sourceValue, sourcePayload);
