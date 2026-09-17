/* USEM Load Balancer Member Match
   -------------------------------------------------------------------------------------------------
   A virtual server usually fronts several real servers, but many front exactly one. When the CMDB
   holds the pool behind the virtual server and every member of it leads to one and the same
   machine, the findings scanned on the virtual address belong to that machine. This rule finds the
   virtual server the way the service rule does, walks Load Balancer Service to Pool to Pool Member
   to server, and returns the machine only when the whole pool points at it. With several machines,
   a member the CMDB cannot place, or no pool data, it declines; the service rule then decides
   whether the virtual server record can stand for the host.

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
   Returns: the sys_id of the one real server behind the virtual server (a machine recorded more
            than once counts once, its live record standing for it); null when the host shows no VIP
            sign, no virtual server matches or two differently named ones carry the value, the
            virtual server has no pool or no members, a member leads to no server in the CMDB, two
            or more machines sit behind it, or two live records of the one machine compete.
   Sample : the Linux Server "usvacrispweb01", the only member of the pool "crisp-tx-pool" behind
            the Load Balancer Service "crisp-tx", reached through the member address "10.10.20.31".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hardware rules declined: a VIP has no serial, "crisp-tx" is not a server name, and
            the address belongs to a load balancer device.
   Reaches: virtual servers whose pool, fully known to the CMDB, holds exactly one real server.
   After  : USEM Load Balancer Service Match, which attaches the virtual server record when the CMDB
            does not show several servers behind it.
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

    // -- VIP sign first ---------------------------------------------------------------------------
    // The rule goes on only when the OS text contains a listed load balancer word or one of the
    // label segments is a listed VIP marker. An ordinary server that shares an address with a
    // virtual IP is never treated as a VIP.
    // Sample: "f5 big ip" contains "f5", so sign is true. "rbps-dev3-sve-vip.ecommnp.rpg" with OS
    //         "Linux 2.6" would qualify through the segment "vip"; "ah-1047132-001" with OS "Red
    //         Hat Enterprise Linux 9.8" has neither and the rule would decline.
    //
    // The load balancer products looked for in the OS text, and the label segments that mark a
    // virtual IP. Keep both lists the same in the member rule and the service rule.
    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'];
    var labelMarkers = ['vip', 'vs'];
    var sign = false;
    for (var m = 0; m < osMarkers.length; m++)
        if (os.indexOf(osMarkers[m]) != -1)
            sign = true;
    var segments = label ? label.split('-') : [];
    for (var s = 0; s < segments.length; s++)
        if (isMarker(segments[s], labelMarkers))
            sign = true;
    if (!sign)
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
    // Sample: the first step, fqdn "crisp-tx.bankofamerica.com", finds the Load Balancer Service
    //         "crisp-tx" and no second row, so twins holds that one record. Two live records named
    //         "crisp-tx" on "171.203.142.26", one per balancer of the pair, would both be kept and
    //         the pool of each walked below; a retired copy beside a live one would be set aside.
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
    // A pool is reached three ways for each record kept, because the load balancer model can be
    // loaded either through reference fields or through relationships: the pool field on the
    // service, pools whose service field points at the service, and pools related to the service.
    // Without a pool the rule declines and the service rule takes over.
    // Sample: the service "crisp-tx" carries the pool "crisp-tx-pool" in its pool field; poolIds
    //         holds that one sys_id.
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
        return null;

    // -- The pool members and their addresses -----------------------------------------------------
    // Members are the records whose pool field points at one of the pools, plus the members related
    // to a pool. Each member is kept with its address, an empty one as an empty string so that no
    // address search runs for it; a member without an address can still lead to a server through a
    // relationship.
    // Sample: the pool "crisp-tx-pool" has one member, "crisp-tx-pool_10.10.20.31_443", with
    //         ip_address "10.10.20.31"; members holds that one entry.
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
        return null;

    // -- The real servers: every member placed, one machine, one live record ----------------------
    // Each member address is looked for on device records, on network adapters and on IP Address
    // records, and each member is followed through its relationships to hardware; load balancer
    // devices and ignored classes are left out. Every server found is kept with the first label of
    // its name, and a member that leads to no server is counted as unplaced. Several records of one
    // name are one machine recorded more than once (a rebuilt server whose old record was retired,
    // a copy left by a test): its live record stands for it when it is the only live one. The
    // machine is the match only when every member leads to it. An unplaced member leaves the pool
    // partly unknown and the rule declines: the one server found may not be the one that was
    // scanned. No server, two differently named machines, or two live records of the one machine
    // decline as well, leaving the host to the service rule.
    // Sample: the Linux Server "usvacrispweb01" carries "10.10.20.31" in its ip_address field, so
    //         the one member is placed, servers holds one entry and its sys_id is returned. A
    //         retired Server record also named "usvacrispweb01" would be set aside for the live
    //         Linux Server; two live records of that name, a second member on "10.10.20.32" that no
    //         CI carries, or one owned by "usvacrispweb02", would make the rule decline.
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
    if (unresolved || labels.length != 1)
        return null;                              // an unplaced member, no server, or two machines
    var records = machines[labels[0]];
    if (records.length == 1)
        return records[0];
    var live = [];                                // one machine recorded more than once
    for (var f = 0; f < records.length; f++) {
        var ci = new GlideRecord('cmdb_ci_hardware');
        ci.get(records[f]);
        if (!retired(ci))
            live.push(records[f]);
    }
    return live.length == 1 ? live[0] : null;     // two live records compete, never guess
})(rule, sourceValue, sourcePayload);
