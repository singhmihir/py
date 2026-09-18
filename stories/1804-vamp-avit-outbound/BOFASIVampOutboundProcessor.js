var BOFASIVampOutboundProcessor = Class.create();
BOFASIVampOutboundProcessor.prototype = {

    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_verification_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.ELEMENTS_KEY = 'findings';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.SECTIONS_PROPERTY = 'x_boar_bofa_usem_1.usem.vamp.avit.sections';
        this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.vamp.avit.fields.';
        this.TASK_KEY = 'remediation_task';
        this.GROUP_ITEM_TABLE = 'sn_vul_app_m2m_vul_group_item';
        this.GROUP_ITEM_FIELD = 'sn_vul_app_vulnerable_item';
        this.GROUP_FIELD = 'sn_vul_app_vulnerability';
    },

    buildPayload: function(record) {
        try {
            var payload = {
                envelope: this._buildEnvelope(this._activity(record))
            };
            payload[this.ELEMENTS_KEY] = [this._buildElement(record)];
            var message = JSON.stringify(payload);
            gs.addInfoMessage('VAMP payload for ' + record.getValue('number') + ': ' + message)
            return message;
        } catch (e) {
            gs.error(this.type + ': payload not built for ' + record.getTableName() + ' ' + record.getUniqueValue() + ' - ' + (e.message || e));
            return '';
        }
    },

    _activity: function(record) {
        var operation = String(record.operation() || '').toUpperCase();
        if (operation)
            return operation;
        return parseInt(record.getValue('sys_mod_count')) > 0 ? 'UPDATE' : 'INSERT';
    },

    _buildEnvelope: function(activity) {
        return {
            type: 'record',
            topic_name: this.TOPIC_NAME,
            namespace: this.NAMESPACE,
            core_version: this.CORE_VERSION,
            outbound_version: this.OUTBOUND_VERSION,
            event_id: this._newEventId(),
            event_timestamp: this._utcTimestamp(),
            element_count: 1,
            element_activity: activity
        };
    },

    _buildElement: function(record) {
        var element = {};
        var task = this._remediationTask(record);
        var sections = this._pairs(gs.getProperty(this.SECTIONS_PROPERTY, ''));
        for (var i = 0; i < sections.length; i++)
            element[sections[i].name] = this._buildSection(this._sectionRecord(record, task, sections[i].value), sections[i].name);
        return element;
    },

    _buildSection: function(target, section) {
        var fields = this._pairs(gs.getProperty(this.FIELDS_PROPERTY_PREFIX + section, ''));
        var values = {};
        for (var i = 0; i < fields.length; i++)
            values[fields[i].value || fields[i].name] = this._fieldValue(target, fields[i].name);
        return values;
    },

    _sectionRecord: function(record, task, path) {
        if (!path)
            return record;
        if (path == this.TASK_KEY)
            return task;
        var root = record;
        if (path.indexOf(this.TASK_KEY + '.') == 0) {
            root = task;
            path = path.substring(this.TASK_KEY.length + 1);
        }
        return root ? root.getElement(path).getRefRecord() : null;
    },

    _remediationTask: function(record) {
        var item = new GlideRecord(this.GROUP_ITEM_TABLE);
        item.addQuery(this.GROUP_ITEM_FIELD, record.getUniqueValue());
        item.orderByDesc('sys_created_on');
        item.query();
        return item.next() ? item.getElement(this.GROUP_FIELD).getRefRecord() : null;
    },

    _pairs: function(value) {
        var pairs = [];
        var entries = String(value).split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var pair = entries[i].split('=');
            var name = pair[0].trim();
            if (name)
                pairs.push({ name: name, value: pair.length > 1 ? pair[1].trim() : '' });
        }
        return pairs;
    },

    _fieldValue: function(record, field) {
        if (!record || !record.isValidRecord() || !record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null || element.nil())
            return '';
        return this._renderElement(element);
    },

    _renderElement: function(element) {
        switch (String(element.getED().getInternalType())) {
            case 'glide_date_time':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'journal_input':
                return String(element.getJournalEntry(1)).trim();
            case 'reference':
            case 'glide_list':
            case 'boolean':
            case 'glide_duration':
            case 'timer':
            case 'domain_id':
            case 'sys_class_name':
            case 'integer':
            case 'string':
                return String(element.getDisplayValue());
            default:
                return String(element.getValue());
        }
    },

    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'BOFASIVampOutboundProcessor'
};
