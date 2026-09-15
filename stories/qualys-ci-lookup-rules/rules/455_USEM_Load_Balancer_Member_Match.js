/* USEM Load Balancer Member Match
   -------------------------------------------------------------------------------------------------
   A virtual server usually fronts several real servers, but many front exactly one. When the CMDB
   holds the pool behind the virtual server and exactly one real server sits in it, the findings
   scanned on the virtual address belong to that server. This rule finds the virtual server the way
   the service rule does, walks Load Balancer Service to Pool to Pool Member to server, and returns
   the server only when it is the single one. With several servers, or without pool data, it
   declines and the service rule attaches the virtual server record instead.

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
   Returns: the sys_id of the one real server behind the virtual server; null when the host shows no
            VIP sign, no single service matches, the service has no pool or no members, or two or
            more servers sit behind it.
   Sample : the Linux Server "usvacrispweb01", the only member of the pool "crisp-tx-pool" behind
            the Load Balancer Service "crisp-tx", reached through the member address "10.10.20.31".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hardware rules declined: a VIP has no serial, "crisp-tx" is not a server name, and
            the address belongs to a load balancer device.
   Reaches: virtual servers whose pool holds exactly one real server in the CMDB.
   After  : USEM Load Balancer Service Match, which attaches the virtual server record itself when
            this rule declines.
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
    // label segments is a listed VIP marker, exactly as the service rule does. An ordinary server
    // that shares an address with a virtual IP is never walked through a pool.
    // Sample: "f5 big ip" contains "f5", so sign is true. "rbps-dev3-sve-vip.ecommnp.rpg" with OS
    //         "Linux 2.6" would qualify through the segment "vip"; "ah-1047132-001" with OS "Red
    //         Hat Enterprise Linux 9.8" has neither and the rule would decline.
    //
    // The load balancer products looked for in the OS text, and the label segments that mark a
    // virtual IP. Keep both lists the same as in the service rule.
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

    // -- The one virtual server, by fqdn, then name, then address ---------------------------------
    // The same search as the service rule: the scanned DNS name in the fqdn field, then in the name
    // field, then the label in the name field, then the scanned address in ip_address. Each step
    // accepts exactly one service; a step that finds two ends the rule; a step that finds nothing
    // hands over to the next.
    // Sample: the first step, fqdn "crisp-tx.bankofamerica.com", finds the Load Balancer Service
    //         "crisp-tx" and no second row, so service holds its sys_id.
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
    // A pool is reached three ways, because the load balancer model can be loaded either through
    // reference fields or through relationships: the pool field on the service, pools whose service
    // field points at the service, and pools related to the service. Without a pool the rule
    // declines and the service rule attaches the virtual server.
    // Sample: the service "crisp-tx" carries the pool "crisp-tx-pool" in its pool field; poolIds
    //         holds that one sys_id.
    var pools = {};
    var svc = new GlideRecord('cmdb_ci_lb_service');
    svc.get(service);
    if (svc.getValue('pool'))
        pools[svc.getValue('pool')] = true;
    var byService = new GlideRecord('cmdb_ci_lb_pool');
    if (byService.isValid()) {
        byService.addQuery('service', service);
        byService.query();
        while (byService.next())
            pools[byService.getUniqueValue()] = true;
    }
    var relPools = related(service, 'cmdb_ci_lb_pool');
    for (var r1 = 0; r1 < relPools.length; r1++)
        pools[relPools[r1]] = true;
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

    // -- The real servers, exactly one ------------------------------------------------------------
    // Each member address is looked for on device records, on network adapters and on IP Address
    // records, and each member is followed through its relationships to hardware; load balancer
    // devices and ignored classes are left out. The distinct servers found are counted. One server
    // is the match; none, or two or more, and the rule declines, leaving the virtual server record
    // to the service rule. A member address carried by two device records is two servers and
    // declines as well.
    // Sample: the Linux Server "usvacrispweb01" carries "10.10.20.31" in its ip_address field, so
    //         servers holds one entry and its sys_id is returned. A second member on "10.10.20.32"
    //         owned by another server would make the rule decline and the service rule attach
    //         "crisp-tx".
    var servers = {};
    function keep(id) {
        if (id && isRealServer(id))
            servers[id] = true;
    }
    for (var k = 0; k < memberIds.length; k++) {
        var addr = members[memberIds[k]];
        if (addr) {
            var hw = new GlideRecord('cmdb_ci_hardware');
            hw.addQuery('ip_address', addr);
            hw.query();
            while (hw.next())
                keep(hw.getUniqueValue());
            var nic = new GlideRecord('cmdb_ci_network_adapter');
            nic.addQuery('ip_address', addr);
            nic.addNotNullQuery('cmdb_ci');
            nic.query();
            while (nic.next())
                keep(nic.getValue('cmdb_ci'));
            var ipr = new GlideRecord('cmdb_ci_ip_address');
            if (ipr.isValid()) {
                ipr.addQuery('ip_address', addr);
                ipr.addNotNullQuery('nic.cmdb_ci');
                ipr.query();
                while (ipr.next())
                    keep('' + ipr.nic.cmdb_ci);
            }
        }
        var relServers = related(memberIds[k], 'cmdb_ci_hardware');
        for (var r3 = 0; r3 < relServers.length; r3++)
            keep(relServers[r3]);
    }
    var ids = Object.keys(servers);
    if (ids.length == 1)
        return ids[0];
    return null;
})(rule, sourceValue, sourcePayload);
