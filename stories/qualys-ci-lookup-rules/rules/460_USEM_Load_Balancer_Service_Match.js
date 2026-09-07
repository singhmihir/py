/* =================================================================================================
   RULE 460 - USEM Load Balancer Service Match
   =================================================================================================
   Match a virtual IP answered by a load balancer to the Load Balancer Service CI that models it.
   The hardware rules deliberately refuse the balancer device, because a VIP is not the balancer;
   this rule gives such hosts their proper CI instead of leaving them unmatched. It runs on the IP
   field so that VIPs without a DNS name are covered too.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "1202267231",
     "IP": "171.203.142.26",
     "TRACKING_METHOD": "IP",
     "OS": "F5 Big IP",
     "DNS": "crisp-tx.bankofamerica.com"
   }

   sourceValue   = the IP field -> "171.203.142.26"
   sourcePayload = the whole record; the rule also reads the OS and the DNS name from it
   Expected for the sample: the Load Balancer Service CI whose fqdn is "crisp-tx.bankofamerica.com"
   (or, failing that, whose name is the DNS name or its label, or whose ip_address is
   "171.203.142.26"); null without VIP evidence, without a service, or when two services carry the
   value.

   WHY THIS RULE SITS AT ORDER 460
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 175 to 450 searched the hardware tree and declined: a VIP has no serial, its name
                 is not a server name, and the address belongs to a load balancer device, which
                 those rules refuse.
   - Reaches it: hosts with VIP evidence: an OS text naming a load balancer product (property
                 usem.ci_lookup.vip_os_markers) or a DNS label with a VIP marker segment such as
                 "-vip", "vs1" (property usem.ci_lookup.vip_markers).
   - After it  : 700 and above (IP address rules) for hosts that are not VIPs.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var ip = ('' + sourceValue).trim();           // "171.203.142.26"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();   // "crisp-tx.bankofamerica.com" or ""
    var label = dns.split('.')[0];                // "crisp-tx"
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // "f5 big ip"
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
    // ====== STAGE 1: Require VIP evidence ========================================================
    // What   : the rule goes on only when the OS text contains a listed load balancer product word,
    //          or one of the label segments is a listed VIP marker.
    // Why    : a Load Balancer Service must never be returned for an ordinary server that happens
    //          to share an address with a VIP; the evidence keeps this rule to the hosts that
    //          really are VIPs.
    // Sample : "f5 big ip" contains "f5" -> evidence. "rbps-dev3-sve-vip.ecommnp.rpg" with OS
    //          "Linux 2.6" -> segment "vip" -> evidence. "ah-1047132-001" with OS "Red Hat
    //          Enterprise Linux 9.8" -> neither -> decline.
    // =============================================================================================
    var osMarkers = list('usem.ci_lookup.vip_os_markers', 'f5,big-ip,big ip,netscaler');
    var labelMarkers = list('usem.ci_lookup.vip_markers', 'vip,vs');
    var evidence = false;
    for (var m = 0; m < osMarkers.length; m++)
        if (os.indexOf(osMarkers[m]) != -1)
            evidence = true;
    var segments = label ? label.split('-') : [];
    for (var s = 0; s < segments.length; s++)
        if (isMarker(segments[s], labelMarkers))
            evidence = true;
    // -> evidence = true for the sample
    if (!evidence)
        return null;
    // ====== STAGE 2: Find the one Load Balancer Service by fqdn, then by name, then by address ===
    // What   : searches cmdb_ci_lb_service (and its sub-classes) for the scanned DNS name in the
    //          fqdn field, then in the name field, then for the label in the name field, then for
    //          the scanned address in ip_address. Each step accepts exactly one service; a step
    //          that finds two services ends the rule with null, a step that finds nothing hands
    //          over to the next step.
    // Why    : the most specific evidence is tried first, and an ambiguous answer is never skipped
    //          over to a weaker one, because the weaker evidence could pick a different service.
    // Sample : fqdn = "crisp-tx.bankofamerica.com" finds the Load Balancer Service "crisp-tx" ->
    //          return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". A VIP with two services on the same
    //          address and no DNS -> null.
    // =============================================================================================
    function one(field, value) {
        if (!value)
            return undefined;                     // no value to search -> next step
        var gr = new GlideRecord('cmdb_ci_lb_service');
        if (!gr.isValid())
            return null;                          // class not installed -> decline
        gr.addQuery(field, value);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        if (!gr.next())
            return undefined;                     // nothing found -> next step
        var id = gr.getUniqueValue();
        if (gr.hasNext())
            return null;                          // two services -> never guess
        return id;
    }
    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];
    for (var t = 0; t < steps.length; t++) {
        var found = one(steps[t][0], steps[t][1]);
        if (found === null)                       // ambiguous at this step -> decline
            return null;
        if (found)                                // exactly one service -> match
            return found;
    }
    return null;
    // -> no service for any of the evidence -> decline; the host continues to rule 700
})(rule, sourceValue, sourcePayload);
