var AitResolver = Class.create();
AitResolver.prototype = {

    /**
     * Configuration from the usem.ait.* properties: the AIT table and its tier field, the business
     * application table and its AIT reference, the discovered item tables with their CI and AIT
     * fields, the service sources and the fallback, the stamp chunk and the event queue.
     * @returns {void}
     */
    initialize: function() {
        this.AIT_TABLE = gs.getProperty('usem.ait.ait_table', '');
        this.TIER_FIELD = gs.getProperty('usem.ait.tier_field', 'rto_tier');
        this.APP_TABLE = gs.getProperty('usem.ait.app_table', 'cmdb_ci_business_app');
        this.APP_AIT_FIELD = gs.getProperty('usem.ait.app_ait_field', 'u_primary_ait');
        this.SERVICE_TABLE = 'cmdb_ci_service';
        this.DI_TABLES = this._diTables(gs.getProperty('usem.ait.di_tables', ''));
        this.SOURCES = this._flags(gs.getProperty('usem.ait.sources', 'assoc,self,related'));
        this.FALLBACK = gs.getProperty('usem.ait.fallback', 'neighbours');
        this.CHUNK = parseInt(gs.getProperty('usem.ait.stamp_chunk', '200'));
        this.QUEUE = gs.getProperty('usem.ait.event_queue', 'usem_ait');
        this.EVENT = 'usem.ait.refresh';
        this.WALK_DEPTH = parseInt(gs.getProperty('sn_sec_cmn.services_affected_by_CI_max_depth', '10'));
        this.WALK_SIZE = parseInt(gs.getProperty('sn_sec_cmn.services_affected_by_CI_max_size', '1000'));
        this.serviceMemo = {};
        this.ciMemo = {};
    },

    /**
     * Writes the Primary AIT of a discovered item from its CI, for the before rules on the
     * discovered item tables; nothing is stored anywhere else.
     * @param {GlideRecord} current - the discovered item being written
     * @returns {void}
     */
    resolveRecord: function(current) {
        try {
            var config = this.DI_TABLES[current.getTableName()];
            current.setValue(config.aitField, this.ciAit(current.getValue(config.ciField)));
        } catch (e) {
            gs.error(this.type + ': primary AIT not resolved for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (e.message || e));
        }
    },

    /**
     * Queues one keyed refresh for the processor; the rules on the source tables call this and
     * compute nothing themselves.
     * @param {String} kind - ait, app, service, ci (membership changed) or rel (relationship changed)
     * @param {String} ids - comma-separated sys_ids of that kind
     * @returns {void}
     */
    enqueue: function(kind, ids) {
        gs.eventQueue(this.EVENT, null, kind, ids, this.QUEUE);
    },

    /**
     * Queues the refresh for one relationship: a link between a business application and a
     * service refreshes that service, any other link refreshes its two ends.
     * @param {String} parent - sys_id of the parent CI
     * @param {String} child - sys_id of the child CI
     * @returns {void}
     */
    enqueueRelationship: function(parent, child) {
        var apps = this._members(this.APP_TABLE, [parent, child]);
        var services = this._members(this.SERVICE_TABLE, [parent, child]);
        if (apps.length == 1 && services.length == 1)
            this.enqueue('service', services[0]);
        else
            this.enqueue('rel', parent + ',' + child);
    },

    /**
     * Processes one keyed refresh: expands the key down to the CIs it can affect, resolves each
     * CI once and stamps the discovered items in sets grouped by the value written.
     * @param {String} kind - ait, app, service, ci or rel
     * @param {String} ids - comma-separated sys_ids of that kind
     * @returns {void}
     */
    refresh: function(kind, ids) {
        try {
            var list = String(ids || '').split(',');
            if (kind == 'ait') {
                list = this._appsOfAits(list);
                kind = 'app';
            }
            if (kind == 'app') {
                list = this._servicesOfApps(list);
                kind = 'service';
            }
            if (kind == 'service') {
                list = this._cisOfServices(list);
                kind = 'ci';
            }
            if (kind == 'ci' && this.FALLBACK == 'neighbours')
                list = list.concat(this._neighbours(list));
            this.refreshCis(list);
        } catch (e) {
            gs.error(this.type + ': refresh not applied for ' + kind + ' ' + ids + ' - ' + (e.message || e));
        }
    },

    /**
     * Resolves each CI once, groups the CIs by the AIT found and stamps every discovered item
     * table once per group; rows that already hold the value are left untouched.
     * @param {Array} ciIds - sys_ids of the CIs to refresh
     * @returns {void}
     */
    refreshCis: function(ciIds) {
        var groups = {};
        var seen = {};
        for (var i = 0; i < ciIds.length; i++) {
            var ci = ciIds[i];
            if (!ci || seen[ci])
                continue;
            seen[ci] = true;
            var ait = this.ciAit(ci);
            (groups[ait] = groups[ait] || []).push(ci);
        }
        for (var value in groups)
            for (var table in this.DI_TABLES)
                this._stamp(table, groups[value], value);
    },

    /**
     * Re-derives every discovered item of one table whose CI sys_id starts with the prefix, for
     * the nightly pass and for an initial load; one partition per call.
     * @param {String} table - a discovered item table from usem.ait.di_tables
     * @param {String} prefix - first characters of the CI sys_id, empty for the whole table
     * @returns {void}
     */
    reconcile: function(table, prefix) {
        try {
            var config = this.DI_TABLES[table];
            var ids = [];
            var ga = new GlideAggregate(table);
            ga.addNotNullQuery(config.ciField);
            if (prefix)
                ga.addQuery(config.ciField + '.sys_id', 'STARTSWITH', prefix);
            ga.addAggregate('COUNT');
            ga.groupBy(config.ciField);
            ga.query();
            while (ga.next()) {
                ids.push(ga.getValue(config.ciField));
                if (ids.length == 5000)
                    this.refreshCis(ids.splice(0, ids.length));
            }
            this.refreshCis(ids);
        } catch (e) {
            gs.error(this.type + ': reconcile not completed for ' + table + ' prefix "' + prefix + '" - ' + (e.message || e));
        }
    },

    /**
     * Clears the Primary AIT of the discovered items of one table that no longer point at a CI.
     * @param {String} table - a discovered item table from usem.ait.di_tables
     * @returns {void}
     */
    clearOrphans: function(table) {
        try {
            var config = this.DI_TABLES[table];
            var orphan = new GlideRecord(table);
            orphan.addNullQuery(config.ciField);
            orphan.addNotNullQuery(config.aitField);
            orphan.setWorkflow(false);
            orphan.autoSysFields(false);
            this._clear(orphan, config.aitField);
        } catch (e) {
            gs.error(this.type + ': orphans not cleared for ' + table + ' - ' + (e.message || e));
        }
    },

    /**
     * The Primary AIT of a CI: the lowest tier among the AITs of the services the CI belongs to,
     * ties broken by AIT number.
     * @param {String} ciId - sys_id of the CI
     * @returns {String} sys_id of the AIT, empty when none
     */
    ciAit: function(ciId) {
        if (!ciId)
            return '';
        if (this.ciMemo.hasOwnProperty(ciId))
            return this.ciMemo[ciId];
        var best = null;
        var services = this.ciServices(ciId);
        for (var i = 0; i < services.length; i++) {
            var candidate = this.serviceAit(services[i]);
            if (candidate && (!best || this._better(candidate, best)))
                best = candidate;
        }
        return (this.ciMemo[ciId] = best ? best.ait : '');
    },

    /**
     * The services a CI belongs to, from the configured sources (service associations in both
     * directions, the CI itself when it is a service, the Related Services links); when they
     * are empty, the configured fallback: the same sources on the CIs related to it, or the
     * platform's bounded impact walk.
     * @param {String} ciId - sys_id of the CI
     * @returns {Array} sys_ids of the services, distinct
     */
    ciServices: function(ciId) {
        var found = this._directServices([ciId]);
        if (!found.length && this.FALLBACK == 'neighbours')
            found = this._directServices(this._neighbours([ciId]));
        if (!found.length && this.FALLBACK == 'walk')
            found = new global.CIUtils().servicesAffectedByCI(ciId, { maxDepth: this.WALK_DEPTH, maxSize: this.WALK_SIZE }).map(String);
        return found;
    },

    /**
     * The Primary AIT of a service: the lowest tier among the AITs of the business applications
     * related to it in either direction; memoised for the life of the instance.
     * @param {String} serviceId - sys_id of the service
     * @returns {Object} {ait, tier, number} or null when no related application carries an AIT
     */
    serviceAit: function(serviceId) {
        if (this.serviceMemo.hasOwnProperty(serviceId))
            return this.serviceMemo[serviceId];
        var best = null;
        var aits = this._aitsOfApps(this._neighbours([serviceId]));
        if (aits.length) {
            var ait = new GlideRecord(this.AIT_TABLE);
            ait.addQuery('sys_id', 'IN', aits.join(','));
            ait.query();
            while (ait.next()) {
                var candidate = { ait: ait.getUniqueValue(), tier: parseInt(ait.getValue(this.TIER_FIELD)), number: '' + ait.getValue('number') };
                if (!best || this._better(candidate, best))
                    best = candidate;
            }
        }
        return (this.serviceMemo[serviceId] = best);
    },

    _better: function(a, b) {
        var tierA = isNaN(a.tier) ? Infinity : a.tier;
        var tierB = isNaN(b.tier) ? Infinity : b.tier;
        if (tierA != tierB)
            return tierA < tierB;
        return a.number < b.number;
    },

    _directServices: function(ciIds) {
        var found = {};
        for (var start = 0; start < ciIds.length; start += this.CHUNK) {
            var chunk = ciIds.slice(start, start + this.CHUNK).join(',');
            if (this.SOURCES.assoc) {
                var assoc = new GlideRecord('svc_ci_assoc');
                assoc.addQuery('ci_id', 'IN', chunk).addOrCondition('service_id', 'IN', chunk);
                assoc.query();
                while (assoc.next())
                    found[assoc.getValue('service_id')] = true;
            }
            if (this.SOURCES.related) {
                var related = new GlideRecord('sn_vul_m2m_ci_services');
                related.addQuery('item', 'IN', chunk);
                related.query();
                while (related.next())
                    found[related.getValue('service')] = true;
            }
            if (this.SOURCES.self) {
                var service = new GlideRecord(this.SERVICE_TABLE);
                service.addQuery('sys_id', 'IN', chunk);
                service.query();
                while (service.next())
                    found[service.getUniqueValue()] = true;
            }
        }
        return Object.keys(found);
    },

    _neighbours: function(ciIds) {
        var ends = {};
        for (var start = 0; start < ciIds.length; start += this.CHUNK) {
            var chunk = ciIds.slice(start, start + this.CHUNK).join(',');
            var rel = new GlideRecord('cmdb_rel_ci');
            rel.addQuery('parent', 'IN', chunk).addOrCondition('child', 'IN', chunk);
            rel.query();
            while (rel.next()) {
                ends[rel.getValue('parent')] = true;
                ends[rel.getValue('child')] = true;
            }
        }
        return Object.keys(ends);
    },

    _members: function(table, ids) {
        var members = [];
        var gr = new GlideRecord(table);
        gr.addQuery('sys_id', 'IN', ids.join(','));
        gr.query();
        while (gr.next())
            members.push(gr.getUniqueValue());
        return members;
    },

    _aitsOfApps: function(appIds) {
        var aits = {};
        if (!appIds.length)
            return [];
        var app = new GlideRecord(this.APP_TABLE);
        app.addQuery('sys_id', 'IN', appIds.join(','));
        app.addNotNullQuery(this.APP_AIT_FIELD);
        app.query();
        while (app.next())
            aits[app.getValue(this.APP_AIT_FIELD)] = true;
        return Object.keys(aits);
    },

    _appsOfAits: function(aitIds) {
        var apps = [];
        var app = new GlideRecord(this.APP_TABLE);
        app.addQuery(this.APP_AIT_FIELD, 'IN', aitIds.join(','));
        app.query();
        while (app.next())
            apps.push(app.getUniqueValue());
        return apps;
    },

    _servicesOfApps: function(appIds) {
        return this._members(this.SERVICE_TABLE, this._neighbours(appIds));
    },

    _cisOfServices: function(serviceIds) {
        var cis = {};
        for (var start = 0; start < serviceIds.length; start += this.CHUNK) {
            var chunk = serviceIds.slice(start, start + this.CHUNK).join(',');
            if (this.SOURCES.assoc) {
                var assoc = new GlideRecord('svc_ci_assoc');
                assoc.addQuery('service_id', 'IN', chunk);
                assoc.query();
                while (assoc.next())
                    cis[assoc.getValue('ci_id')] = true;
            }
            if (this.SOURCES.related) {
                var related = new GlideRecord('sn_vul_m2m_ci_services');
                related.addQuery('service', 'IN', chunk);
                related.query();
                while (related.next())
                    cis[related.getValue('item')] = true;
            }
        }
        for (var i = 0; i < serviceIds.length; i++)
            cis[serviceIds[i]] = true;
        return Object.keys(cis);
    },

    /**
     * One set-based statement per chunk of CIs: the rows of the table whose CI is in the chunk
     * and whose AIT field does not already hold the value; rules and audit left aside because
     * the value is derived. Clearing is done row by row, the only way that empties a reference
     * on every table regardless of how the platform executes the multi-row update.
     */
    _stamp: function(table, ciIds, value) {
        var config = this.DI_TABLES[table];
        for (var start = 0; start < ciIds.length; start += this.CHUNK) {
            var di = new GlideRecord(table);
            di.addQuery(config.ciField, 'IN', ciIds.slice(start, start + this.CHUNK).join(','));
            di.setWorkflow(false);
            di.autoSysFields(false);
            if (value) {
                di.addEncodedQuery(config.aitField + '!=' + value + '^OR' + config.aitField + 'ISEMPTY');
                di.setValue(config.aitField, value);
                di.updateMultiple();
            } else {
                di.addNotNullQuery(config.aitField);
                this._clear(di, config.aitField);
            }
        }
    },

    _clear: function(di, field) {
        di.query();
        while (di.next()) {
            di.setValue(field, '');
            di.update();
        }
    },

    _diTables: function(value) {
        var tables = {};
        var entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var parts = entries[i].split('=');
            if (parts.length == 3 && parts[0].trim())
                tables[parts[0].trim()] = { ciField: parts[1].trim(), aitField: parts[2].trim() };
        }
        return tables;
    },

    _flags: function(value) {
        var flags = {};
        var entries = value.split(',');
        for (var i = 0; i < entries.length; i++)
            if (entries[i].trim())
                flags[entries[i].trim()] = true;
        return flags;
    },

    type: 'AitResolver'
};
