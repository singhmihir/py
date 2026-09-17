/* USEM Load Balancer Service Match
   -------------------------------------------------------------------------------------------------
   A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the
   balancer device on purpose. Such hosts belong to the Load Balancer Service CI that models the
   VIP, and this rule finds it. It runs on the IP field so that VIPs without a DNS name are covered
   too.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "1202267231",
     "IP": "171.203.142.26",
     "TRACKING_METHOD": "IP",
     "OS": "F5 Big IP",
     "DNS": "crisp-tx.bankofamerica.com"
   }
   Input  : sourceValue is the IP field, "171.203.142.26"; the rule also reads the OS and the DNS
            name from sourcePayload.
   Returns: the sys_id of the one Load Balancer Service CI found by fqdn, then by name, then by
            address (a retired copy of the record found is set aside); null when the host shows no
            VIP evidence, when no service matches, when two differently named services carry the
            value, or when two live records of one virtual server compete.
   Sample : the Load Balancer Service CI "crisp-tx", whose fqdn is "crisp-tx.bankofamerica.com".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hardware rules declined: a VIP has no serial, "crisp-tx" is not a server name, and
            the address belongs to a load balancer device.
   Reaches: hosts with VIP evidence: an OS text naming a load balancer product, or a DNS label with
            a VIP marker segment such as "-vip" or "vs1"; both lists are declared in the script, at
            the top of the matching stage.
   After  : the IP address rules, for hosts that are not VIPs.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "171.203.142.26"
    // loopback and link-local identify nothing
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;
    // "crisp-tx.bankofamerica.com", may be empty
    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();
    var label = dns.split('.')[0];                // "crisp-tx"
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();  // "f5 big ip"

    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

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
    // hosts that really are VIPs.
    // Sample: "f5 big ip" contains "f5", so evidence is true. "rbps-dev3-sve-vip.ecommnp.rpg" with
    //         OS "Linux 2.6" would qualify through the segment "vip"; "ah-1047132-001" with OS "Red
    //         Hat Enterprise Linux 9.8" has neither and the rule would decline.
    //
    // The load balancer products looked for in the OS text, and the label segments that mark a
    // virtual IP. Extend these two lists when a site uses another naming habit.
    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'];
    var labelMarkers = ['vip', 'vs'];
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

    // retired() is the platform's own test for a decommissioned CI: install status Retired,
    // operational status Retired, or a Retired life cycle stage.
    function retired(ci) {
        return ci.getValue('install_status') == '7' || ci.getValue('operational_status') == '6' ||
            ci.life_cycle_stage_status.getDisplayValue() == 'Retired';
    }

    // narrow() keeps the records carrying a flag when any does, so a record answering on the
    // scanned address, or a live record, is preferred to the others without dropping the only
    // records there are.
    function narrow(list, flag) {
        var out = [];
        for (var i = 0; i < list.length; i++)
            if (list[i][flag])
                out.push(list[i]);
        return out.length ? out : list;
    }

    // -- The one service, by fqdn, then name, then address ----------------------------------------
    // The scanned DNS name is tried in the fqdn field, then in the name field, then the label in
    // the name field, then the scanned address in ip_address. Each step accepts one virtual server.
    // Several records carrying one name are the same virtual server recorded more than once (an HA
    // pair keeps the same object on both devices; a test leaves a copy): the records answering on
    // the scanned address are kept, then the live ones, and the one record left is returned. Two
    // records still standing, both devices of a pair live, are an ambiguity nothing here can
    // settle, so the rule declines; two different names on the same value decline as well, because
    // a weaker piece of evidence could otherwise pick a different service. A step that finds
    // nothing hands over to the next.
    // Sample: the first step, fqdn "crisp-tx.bankofamerica.com", finds the Load Balancer Service
    //         "crisp-tx" and no second row, so its sys_id is returned. Two live records named
    //         "crisp-tx" on "171.203.142.26", one per balancer of the pair, would make the rule
    //         decline; were one of them retired, the live one would be returned. A VIP without a
    //         DNS name and two differently named services on "171.203.142.26" would reach the last
    //         step and decline there.
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
        var rows = [], names = {};
        while (gr.next()) {
            names[('' + (gr.getValue('name') || '')).trim().toLowerCase()] = true;
            rows.push({id: gr.getUniqueValue(), here: gr.getValue('ip_address') == ip,
                live: !retired(gr)});
        }
        if (!rows.length)
            return undefined;                     // nothing found, next step
        if (Object.keys(names).length > 1)
            return null;                          // two different services, never guess
        rows = narrow(rows, 'here');              // the records answering on the scanned address
        if (rows.length > 1)
            rows = narrow(rows, 'live');          // the live records, a retired copy set aside
        if (rows.length > 1)
            return null;                          // two records still compete, never guess
        return rows[0].id;
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
