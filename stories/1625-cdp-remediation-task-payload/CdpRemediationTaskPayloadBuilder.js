var CdpRemediationTaskPayloadBuilder = Class.create();
CdpRemediationTaskPayloadBuilder.prototype = Object.extendsObject(RemediationTaskPayloadBuilder, {
    initialize: function() {
        RemediationTaskPayloadBuilder.prototype.initialize.call(this);
        this.EXCEPTION_TABLE = 'sn_sec_exception_change_approval';
        this.EXCEPTION_STATES = '1,4';
        this.DISPLAY_TYPES = ['reference', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'integer'];
        // [JSON field name, ServiceNow field] from the mapping sheet 'Outbound to CDP (RemTask)'
        this.COMMON_FIELDS = [
            ['assigned_to',                                'assigned_to'],
            ['assignment_group',                           'assignment_group'],
            ['assignment_type',                            'assignment_type'],
            ['backup_state',                               'backup_state'],
            ['business_duration',                          'business_duration'],
            ['business_service',                           'business_service'],
            ['calendar_duration',                          'calendar_duration'],
            ['close_notes',                                'close_notes'],
            ['closed_at',                                  'closed_at'],
            ['closed_by',                                  'closed_by'],
            ['cmdb_ci',                                    'cmdb_ci'],
            ['comments',                                   'comments'],
            ['company',                                    'company'],
            ['contact_type',                               'contact_type'],
            ['contract',                                   'contract'],
            ['correlation_display',                        'correlation_display'],
            ['correlation_id',                             'correlation_id'],
            ['defer_extend_count',                         'defer_extend_count'],
            ['delivery_plan',                              'delivery_plan'],
            ['delivery_task',                              'delivery_task'],
            ['description',                                'description'],
            ['due_date',                                   'due_date'],
            ['effort',                                     'effort'],
            ['escalation',                                 'escalation'],
            ['expected_start',                             'expected_start'],
            ['follow_up',                                  'follow_up'],
            ['group_key',                                  'group_key'],
            ['group_list',                                 'group_list'],
            ['ignore_date',                                'ignore_date'],
            ['ignore_expiration',                          'ignore_expiration'],
            ['until',                                      'ignore_expiration_dt_tm'],
            ['ignore_expiration_for_risk_reduction',       'ignore_expiration_for_risk_reduction'],
            ['ignore_expiration_for_risk_reduction_dt_tm', 'ignore_expiration_for_risk_reduction_dt_tm'],
            ['ignored_by',                                 'ignored_by'],
            ['impact',                                     'impact'],
            ['knowledge',                                  'knowledge'],
            ['location',                                   'location'],
            ['number',                                     'number'],
            ['opened_at',                                  'opened_at'],
            ['opened_by',                                  'opened_by'],
            ['order',                                      'order'],
            ['parent',                                     'parent'],
            ['priority',                                   'priority'],
            ['reassignment_count',                         'reassignment_count'],
            ['rejection_goto',                             'rejection_goto'],
            ['remediation_commitment_dt_tm',               'remediation_commitment_dt_tm'],
            ['remediation_plan',                           'remediation_plan'],
            ['resolution_date',                            'resolution_date'],
            ['resolution_reason',                          'resolution_reason'],
            ['resolved_by',                                'resolved_by'],
            ['risk_rating',                                'risk_rating'],
            ['risk_score',                                 'risk_score'],
            ['route_reason',                               'route_reason'],
            ['service_offering',                           'service_offering'],
            ['short_description',                          'short_description'],
            ['state',                                      'state'],
            ['status_updated_on',                          'status_updated_on'],
            ['substate',                                   'substate'],
            ['class_name',                                 'sys_class_name'],
            ['created_by',                                 'sys_created_by'],
            ['created_on',                                 'sys_created_on'],
            ['sys_domain',                                 'sys_domain'],
            ['sys_domain_path',                            'sys_domain_path'],
            ['sys_id',                                     'sys_id'],
            ['sys_mod_count',                              'sys_mod_count'],
            ['updated_by',                                 'sys_updated_by'],
            ['updated_on',                                 'sys_updated_on'],
            ['table',                                      'table'],
            ['task_effective_number',                      'task_effective_number'],
            ['time_worked',                                'time_worked'],
            ['total_cis',                                  'total_cis'],
            ['ttr_status',                                 'ttr_status'],
            ['ttr_target_date',                            'ttr_target_date'],
            ['u_confidential',                             'u_confidential'],
            ['urgency',                                    'urgency'],
            ['watch_list',                                 'watch_list'],
            ['work_end',                                   'work_end'],
            ['work_start',                                 'work_start']
        ];
        this.TABLES = {
            sn_vul_vulnerability: {
                fields: [
                    ['active_nd_vis',            'active_nd_vis'],
                    ['auto_vi_refresh',          'auto_vi_refresh'],
                    ['business_criticality',     'business_criticality'],
                    ['cisa_exists',              'cisa_exists'],
                    ['count_active_vi',          'count_active_vi'],
                    ['cr_count',                 'cr_count'],
                    ['defer_count',              'defer_count'],
                    ['duplicate_vi_exists',      'duplicate_vi_exists'],
                    ['duplicate_vi_refresh',     'duplicate_vi_refresh'],
                    ['duplicate_vi_updated',     'duplicate_vi_updated'],
                    ['epss_percentile',          'epss_percentile'],
                    ['filter_group',             'filter_group'],
                    ['filter_type',              'filter_type'],
                    ['ignore_reason',            'ignore_reason'],
                    ['max_risk_score',           'max_risk_score'],
                    ['patch_miss_target',        'patch_miss_target'],
                    ['patch_not_sch',            'patch_not_sch'],
                    ['patch_sch',                'patch_sch'],
                    ['percent_nd_vi_complete',   'percent_nd_vi_complete'],
                    ['percent_vi_complete',      'percent_vi_complete'],
                    ['ransomware',               'ransomware'],
                    ['sn_vul_entry',             'sn_vul_entry'],
                    ['total_nd_vis',             'total_nd_vis'],
                    ['total_vis',                'total_vis'],
                    ['total_vulnerabilities',    'total_vulnerabilities'],
                    ['vi_condition',             'vi_condition'],
                    ['vulnerability_group_rule', 'vulnerability_group_rule']
                ],
                changes: { table: 'sn_vul_m2m_vg_change_request', field: 'sn_vul_vulnerability' }
            },
            sn_vul_app_vulnerability: {
                fields: [
                    ['active_nd_vis',               'active_nd_vis'],
                    ['application_release',         'application_release'],
                    ['auto_vi_refresh',             'auto_vi_refresh'],
                    ['business_criticality',        'business_criticality'],
                    ['cisa_exists',                 'cisa_exists'],
                    ['count_active_vi',             'count_active_vi'],
                    ['cr_count',                    'cr_count'],
                    ['defer_count',                 'defer_count'],
                    ['epss_percentile',             'epss_percentile'],
                    ['filter_group',                'filter_group'],
                    ['filter_type',                 'filter_type'],
                    ['ignore_reason',               'ignore_reason'],
                    ['max_risk_score',              'max_risk_score'],
                    ['percent_nd_vi_complete',      'percent_nd_vi_complete'],
                    ['percent_vi_complete',         'percent_vi_complete'],
                    ['ransomware',                  'ransomware'],
                    ['remediation_commitment_date', 'remediation_commitment_date'],
                    ['sn_vul_entry',                'sn_vul_entry'],
                    ['total_nd_vis',                'total_nd_vis'],
                    ['total_vis',                   'total_vis'],
                    ['total_vulnerabilities',       'total_vulnerabilities'],
                    ['u_avul_record_url',           'u_avul_record_url'],
                    ['u_verification_status',       'u_verification_status'],
                    ['vi_condition',                'vi_condition'],
                    ['vulnerability_group_rule',    'vulnerability_group_rule']
                ],
                changes: { table: 'sn_vul_app_m2m_vg_change_request', field: 'sn_vul_app_vulnerability' }
            },
            sn_vul_container_vulnerability: {
                fields: [
                    ['active_nd_vis',            'active_nd_vis'],
                    ['auto_vi_refresh',          'auto_vi_refresh'],
                    ['business_criticality',     'business_criticality'],
                    ['cisa_exists',              'cisa_exists'],
                    ['count_active_vi',          'count_active_vi'],
                    ['cr_count',                 'cr_count'],
                    ['epss_percentile',          'epss_percentile'],
                    ['filter_type',              'filter_type'],
                    ['ignore_reason',            'ignore_reason'],
                    ['max_risk_score',           'max_risk_score'],
                    ['percent_nd_vi_complete',   'percent_nd_vi_complete'],
                    ['percent_vi_complete',      'percent_vi_complete'],
                    ['ransomware',               'ransomware'],
                    ['sn_vul_entry',             'sn_vul_entry'],
                    ['total_nd_vis',             'total_nd_vis'],
                    ['total_vis',                'total_vis'],
                    ['total_vulnerabilities',    'total_vulnerabilities'],
                    ['vi_condition',             'vi_condition'],
                    ['vulnerability_group_rule', 'vulnerability_group_rule']
                ],
                changes: { table: 'sn_vul_container_m2m_remediation_task_change_request', field: 'sn_vul_container_vulnerability' }
            },
            sn_vulc_result_group: {
                fields: [
                    ['active_nd_test_results', 'active_nd_test_results'],
                    ['active_test_results',    'active_test_results'],
                    ['change_request',         'change_request'],
                    ['condition',              'condition'],
                    ['control',                'control'],
                    ['defer_count',            'defer_count'],
                    ['defer_reason',           'defer_reason'],
                    ['historical_risk_score',  'historical_risk_score'],
                    ['manually_modified',      'manually_modified'],
                    ['method',                 'method'],
                    ['percent_nd_tr_complete', 'percent_nd_tr_complete'],
                    ['percent_tr_complete',    'percent_tr_complete'],
                    ['total_nd_test_results',  'total_nd_test_results'],
                    ['total_test_results',     'total_test_results'],
                    ['total_tests',            'total_tests'],
                    ['vulc_group_rule',        'vulc_group_rule']
                ],
                changes: { table: 'sn_vulc_m2m_trg_change_request', field: 'result_group' }
            }
        };
    },

    _buildRemediationTask: function(gr) {
        var config = this.TABLES[gr.getTableName()];
        if (!config)
            throw new Error('table ' + gr.getTableName() + ' is not a remediation task table');
        var task = {};
        this._addFields(task, gr, this.COMMON_FIELDS);
        this._addFields(task, gr, config.fields);
        task.change_requests = this._changeRequests(gr, config.changes);
        task.exception_requests = this._exceptionRequests(gr);
        return task;
    },

    _addFields: function(task, gr, fields) {
        for (var i = 0; i < fields.length; i++) {
            var jsonName = fields[i][0];
            var fieldName = fields[i][1];
            task[jsonName] = gr.isValidField(fieldName) ? this._renderElement(gr.getElement(fieldName)) : '';
        }
    },

    _renderElement: function(element) {
        if (element.nil())
            return '';
        var type = String(element.getED().getInternalType());
        if (type === 'glide_date_time')
            return this._formatDateTime(element.getValue());
        if (type === 'glide_date')
            return this._formatDate(element.getValue());
        if (type === 'journal_input')
            return String(element.getJournalEntry(1)).trim();
        if (this.DISPLAY_TYPES.indexOf(type) > -1)
            return String(element.getDisplayValue());
        return String(element.getValue());
    },

    _changeRequests: function(gr, link) {
        var numbers = [];
        var m2m = new GlideRecord(link.table);
        m2m.addQuery(link.field, gr.getUniqueValue());
        m2m.addNotNullQuery('change_request');
        m2m.orderBy('change_request.number');
        m2m.query();
        while (m2m.next())
            numbers.push(m2m.getDisplayValue('change_request'));
        return numbers.join(',');
    },

    _exceptionRequests: function(gr) {
        var numbers = [];
        var exception = new GlideRecord(this.EXCEPTION_TABLE);
        exception.addQuery('table', gr.getTableName());
        exception.addQuery('record', gr.getUniqueValue());
        exception.addQuery('approval_state', 'IN', this.EXCEPTION_STATES);
        exception.orderBy('number');
        exception.query();
        while (exception.next())
            numbers.push(exception.getValue('number'));
        return numbers.join(',');
    },

    type: 'CdpRemediationTaskPayloadBuilder'
});
