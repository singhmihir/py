/* USEM Load Balancer Service Match
   -------------------------------------------------------------------------------------------------
   A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the
   balancer device on purpose. When the member rule could not name the one machine behind the
   virtual server, the Load Balancer Service CI that models the VIP can stand for the host, but only
   when the CMDB does not show several servers behind it: a pool with several member addresses, or
   members resolving to several machines, means the finding belongs to one of several hosts and
   nothing here can say which, so the host is left unmatched. This rule finds the virtual server the
   way the member rule does, walks the same pool, and attaches the record when the pool is unknown,
   empty, or fronts one server. It runs on the IP field so that VIPs without a DNS name are covered
   too.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "1202267244",
     "IP": "171.203.142.40",
     "TRACKING_METHOD": "IP",
     "OS": "F5 Big IP",
     "DNS": "horizon-vip.bankofamerica.com"
   }
   Input  : sourceValue is the IP field, "171.203.142.40"; the rule also reads the OS and the DNS
            name from sourcePayload.
   Returns: the sys_id of the one Load Balancer Service CI found by fqdn, then by name, then by
            address (a retired copy of the record set aside), when its pool is unknown, empty, or
            fronts one server; null when the host shows no VIP evidence, no service matches, two
            live records or two different names carry the value, or the pool shows several servers.
   Sample : the Load Balancer Service CI "horizon-vip", whose fqdn is
            "horizon-vip.bankofamerica.com" and which carries no pool in the CMDB.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hardware rules declined: a VIP has no serial, "horizon-vip" is not a server name,
            and the address belongs to a load balancer device; USEM Load Balancer Member Match found
            no pool to walk.
   Reaches: hosts with VIP evidence (an OS text naming a load balancer product, or a DNS label with
            a VIP marker segment such as "-vip" or "vs1"; both lists are declared in the script)
            whose real server the CMDB cannot name.
   After  : the IP address rules, for hosts that are not VIPs.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "171.203.142.40"
    // loopback and link-local identify nothing
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;
    // "horizon-vip.bankofamerica.com", may be empty
    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();
    var label = dns.split('.')[0];                // "horizon-vip"
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

    // -- VIP sign first ---------------------------------------------------------------------------
    // The rule goes on only when the OS text contains a listed load balancer word or one of the
    // label segments is a listed VIP marker. An ordinary server that shares an address with a
    // virtual IP is never treated as a VIP.
    // Sample: "f5 big ip" contains "f5" and the label segment "vip" is a marker, so evidence is
    //         true. "rbps-dev3-sve-vip.ecommnp.rpg" with OS "Linux 2.6" would qualify through the
    //         segment alone; "ah-1047132-001" with OS "Red Hat Enterprise Linux 9.8" has neither
    //         and the rule would decline.
    //
    // The load balancer products looked for in the OS text, and the label segments that mark a
    // virtual IP. Keep both lists the same in the member rule and the service rule.
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

    // -- The one virtual server, by fqdn, then name, then address ---------------------------------
    // The scanned DNS name in the fqdn field, then in the name field, then the label in the name
    // field, then the scanned address in ip_address. Each step accepts one virtual server. Several
    // records carrying one name are the same virtual server recorded more than once (an HA pair
    // keeps the same object on both devices; a test leaves a copy): the records answering on the
    // scanned address are kept, then the live ones. Two different names on the same value end the
    // rule; a step that finds nothing hands over to the next.
    // Sample: the first step, fqdn "horizon-vip.bankofamerica.com", finds the Load Balancer Service
    //         "horizon-vip" and no second row, so twins holds that one record and service its
    //         sys_id. Two live records named "horizon-vip" on "171.203.142.40", one per balancer of
    //         the pair, would both be kept and the rule would decline just below; a retired copy
    //         beside a live one would be set aside.
    var twins = [];                               // every record kept of the virtual server found
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
        twins = [];
        for (var w = 0; w < rows.length; w++)
            twins.push(rows[w].id);
        return twins[0];
    }
    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];
    var service = null;
    for (var t = 0; t < steps.length && !service; t++) {
        var found = one(steps[t][0], steps[t][1]);
        if (found === null)
            return null;
        if (found)
            service = found;
    }
    if (!service)
        return null;

    // -- One record left --------------------------------------------------------------------------
    // Two records still standing, both devices of a pair live, are an ambiguity nothing here can
    // settle: the rule declines rather than pick one.
    // Sample: twins holds the one record "horizon-vip", so the rule goes on.
    if (twins.length > 1)
        // two live records of one virtual server compete, never guess
        return null;

    // isRealServer() says whether a CI can be the machine behind the virtual server: a record in
    // the Hardware tree that is neither a load balancer nor of an ignored class. related() collects
    // the CIs tied to a record by a relationship in either direction, kept to one class and its
    // sub-classes; a mapping loaded as relationships instead of reference fields is read the same
    // way.
    function isRealServer(id) {
        var hw = new GlideRecord('cmdb_ci_hardware');
        if (!hw.get(id))
            return false;
        var cls = ',' + hw.getValue('sys_class_name') + ',';
        if (ignore && (',' + ignore + ',').indexOf(cls) != -1)
            return false;
        var lb = new GlideRecord('cmdb_ci_lb');
        return !(lb.isValid() && lb.get(id));
    }
    function related(id, table) {
        var out = [];
        var rel = new GlideRecord('cmdb_rel_ci');
        rel.addQuery('parent', id).addOrCondition('child', id);
        rel.query();
        while (rel.next()) {
            var other = rel.getValue('parent') == id ?
                rel.getValue('child') : rel.getValue('parent');
            var g = new GlideRecord(table);
            if (g.isValid() && g.get(other))
                out.push(other);
        }
        return out;
    }

    // -- The pool behind the virtual server -------------------------------------------------------
    // The same walk as the member rule: the pool field on the service, pools whose service field
    // points at the service, and pools related to the service. Without a pool the CMDB shows
    // nothing behind the virtual server, and its record is the best CI there is: it is returned.
    // Sample: the service "horizon-vip" carries no pool, no pool points at it and none is related
    //         to it, so poolIds is empty and the sys_id of "horizon-vip" is returned.
    var pools = {};
    for (var w = 0; w < twins.length; w++) {
        var svc = new GlideRecord('cmdb_ci_lb_service');
        svc.get(twins[w]);
        if (svc.getValue('pool'))
            pools[svc.getValue('pool')] = true;
        var byService = new GlideRecord('cmdb_ci_lb_pool');
        if (byService.isValid()) {
            byService.addQuery('service', twins[w]);
            byService.query();
            while (byService.next())
                pools[byService.getUniqueValue()] = true;
        }
        var relPools = related(twins[w], 'cmdb_ci_lb_pool');
        for (var r1 = 0; r1 < relPools.length; r1++)
            pools[relPools[r1]] = true;
    }
    var poolIds = Object.keys(pools);
    if (!poolIds.length)
        return service;

    // -- The pool members and their addresses -----------------------------------------------------
    // Members are the records whose pool field points at one of the pools, plus the members related
    // to a pool. Each member is kept with its address, an empty one as an empty string so that no
    // address search runs for it; a member without an address can still lead to a server through a
    // relationship.
    // Sample: not reached for the sample. A pool "horizon-vip-pool" with the members
    //         "horizon-vip-pool_10.10.30.11_443" and "horizon-vip-pool_10.10.30.12_443" would put
    //         two entries in members. A pool without members returns the virtual server record, as
    //         an absent pool does.
    var members = {};
    var mem = new GlideRecord('cmdb_ci_lb_pool_member');
    if (mem.isValid()) {
        mem.addQuery('pool', 'IN', poolIds.join(','));
        mem.query();
        while (mem.next())
            members[mem.getUniqueValue()] = '' + (mem.getValue('ip_address') || '');
    }
    for (var p1 = 0; p1 < poolIds.length; p1++) {
        var relMembers = related(poolIds[p1], 'cmdb_ci_lb_pool_member');
        for (var r2 = 0; r2 < relMembers.length; r2++) {
            if (members[relMembers[r2]] !== undefined)
                continue;
            var mg = new GlideRecord('cmdb_ci_lb_pool_member');
            mg.get(relMembers[r2]);
            members[relMembers[r2]] = '' + (mg.getValue('ip_address') || '');
        }
    }
    var memberIds = Object.keys(members);
    if (!memberIds.length)
        return service;

    // -- Several servers behind the virtual server: never one CI ----------------------------------
    // The members are placed exactly as in the member rule, and the distinct member identities
    // (addresses, or the record for a member without one) and the machines they lead to are
    // counted. One machine that every member leads to is the case the member rule already handles;
    // the virtual server record stands for it here only when that rule left it (two live records of
    // the machine). Several identities or several machines mean the finding belongs to one of
    // several hosts, and the rule declines: the host stays unmatched rather than carry a CI that is
    // not its own. One identity that the CMDB cannot place is one server the CMDB does not hold,
    // and the virtual server record stands for it.
    // Sample: not reached for the sample. The two members "10.10.30.11" and "10.10.30.12" would be
    //         two identities, owned by "usvahorizon01" and "usvahorizon02" or by nobody, and the
    //         rule would decline; a single member "10.10.30.11" that no CI carries would return the
    //         record "horizon-vip".
    var servers = {};                             // sys_id -> first label of the name
    // distinct member addresses; an address-less member by record
    var identities = {};
    var unresolved = 0;                           // members that lead to no server in the CMDB
    function keep(id) {
        if (!id)
            return false;
        if (servers[id] !== undefined)
            return true;
        if (!isRealServer(id))
            return false;
        var ci = new GlideRecord('cmdb_ci_hardware');
        ci.get(id);
        servers[id] = ('' + (ci.getValue('name') || '')).trim().toLowerCase().split('.')[0] || id;
        return true;
    }
    for (var k = 0; k < memberIds.length; k++) {
        var addr = members[memberIds[k]];
        var led = false;                          // whether this member led to a server
        identities[addr || memberIds[k]] = true;
        if (addr) {
            var hw = new GlideRecord('cmdb_ci_hardware');
            hw.addQuery('ip_address', addr);
            hw.query();
            while (hw.next())
                led = keep(hw.getUniqueValue()) || led;
            var nic = new GlideRecord('cmdb_ci_network_adapter');
            nic.addQuery('ip_address', addr);
            nic.addNotNullQuery('cmdb_ci');
            nic.query();
            while (nic.next())
                led = keep(nic.getValue('cmdb_ci')) || led;
            var ipr = new GlideRecord('cmdb_ci_ip_address');
            if (ipr.isValid()) {
                ipr.addQuery('ip_address', addr);
                ipr.addNotNullQuery('nic.cmdb_ci');
                ipr.query();
                while (ipr.next())
                    led = keep('' + ipr.nic.cmdb_ci) || led;
            }
        }
        var relServers = related(memberIds[k], 'cmdb_ci_hardware');
        for (var r3 = 0; r3 < relServers.length; r3++)
            led = keep(relServers[r3]) || led;
        if (!led)
            unresolved++;
    }
    var ids = Object.keys(servers);
    var machines = {};                            // name label -> its records
    for (var n = 0; n < ids.length; n++)
        machines[servers[ids[n]]] = (machines[servers[ids[n]]] || []).concat(ids[n]);
    var labels = Object.keys(machines);
    if (labels.length == 1 && !unresolved)
        return service;                           // one machine every member leads to
    if (labels.length > 1 || Object.keys(identities).length > 1)
        // several servers behind the virtual server, never guess
        return null;
    return service;
})(rule, sourceValue, sourcePayload);
