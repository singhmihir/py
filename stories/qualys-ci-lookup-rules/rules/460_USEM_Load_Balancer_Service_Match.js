/* USEM Load Balancer Service Match
   -------------------------------------------------------------------------------------------------
   A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the
   balancer device on purpose. Such hosts belong to the Load Balancer Service CI that models the
   VIP, and this rule finds it. It runs on the IP field so that VIPs without a DNS name are covered
   too.

   Input  : sourceValue is the IP field; the rule also reads the OS and the DNS name from
            sourcePayload.
   Returns: the sys_id of the one Load Balancer Service CI found by fqdn, then by name, then by
            address; null when the host shows no VIP evidence, when no service matches, or when two
            services carry the value.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hardware rules declined: a VIP has no serial, its name is not a server name, and the
            address belongs to a load balancer device.
   Reaches: hosts with VIP evidence: an OS text naming a load balancer product (property
            usem.ci_lookup.vip_os_markers) or a DNS label with a VIP marker segment such as "-vip"
            or "vs1" (property usem.ci_lookup.vip_markers).
   After  : the IP address rules, for hosts that are not VIPs.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // e.g. "171.203.142.26"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();   // e.g. "crisp-tx.bankofamerica.com", may be empty
    var label = dns.split('.')[0];
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // e.g. "f5 big ip"
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
    // -- VIP evidence first -----------------------------------------------------------------------
    // The rule goes on only when the OS text contains a listed load balancer word or one of the
    // label segments is a listed VIP marker. A Load Balancer Service must never be returned for an
    // ordinary server that happens to share an address with a VIP; this check keeps the rule to the
    // hosts that really are VIPs ("f5 big ip", "rbps-dev3-sve-vip").
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
    if (!evidence)
        return null;
    // -- The one service, by fqdn, then name, then address ----------------------------------------
    // The scanned DNS name is tried in the fqdn field, then in the name field, then the label in
    // the name field, then the scanned address in ip_address. Each step accepts exactly one
    // service; a step that finds two ends the rule with null, because a weaker piece of evidence
    // could otherwise pick a different service; a step that finds nothing hands over to the next.
    function one(field, value) {
        if (!value)
            return undefined;                     // nothing to search, next step
        var gr = new GlideRecord('cmdb_ci_lb_service');
        if (!gr.isValid())
            return null;                          // class not installed here, decline
        gr.addQuery(field, value);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        if (!gr.next())
            return undefined;                     // nothing found, next step
        var id = gr.getUniqueValue();
        if (gr.hasNext())
            return null;                          // two services, never guess
        return id;
    }
    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];
    for (var t = 0; t < steps.length; t++) {
        var found = one(steps[t][0], steps[t][1]);
        if (found === null)
            return null;
        if (found)
            return found;
    }
    return null;
})(rule, sourceValue, sourcePayload);
