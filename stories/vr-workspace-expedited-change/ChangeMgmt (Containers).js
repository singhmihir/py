var ChangeMgmt = Class.create();
ChangeMgmt.prototype = Object.extendsObject(sn_vul_container.ChangeMgmtBase, {

    EXPEDITED: 'expedited',

    /**
     * Create Change action of a container remediation task. An Expedited change needs an active change model that
     * presets the Expedited type; without one the action ends in error before anything is created or linked. Everything
     * else runs as in ChangeMgmtBase.
     * @param {GlideRecord} actionCreate - sn_vul_container_action_create_cr record
     * @returns {Object} result of ChangeMgmtBase.actionCreateChange, null on error
     */
    actionCreateChange: function(actionCreate) {
        if (actionCreate.getValue('change_request_type') == this.EXPEDITED && !new sn_vul.ChangeMgmt().getExpeditedChangeModel()) {
            gs.error('ChangeMgmt: change creation failed for sn_vul_container_action_create_cr ' + actionCreate.getUniqueValue() + ' - no active change model presets type ' + this.EXPEDITED);
            actionCreate.error_message = gs.getMessage('No active change model presets the Expedited type.');
            actionCreate.status = this.VG_CR_STATUS.ERROR;
            return null;
        }
        return sn_vul_container.ChangeMgmtBase.prototype.actionCreateChange.call(this, actionCreate);
    },

    /**
     * Creates the change request of a Create Change action: an Expedited change from the Expedited change model through
     * the change API, every other type as ChangeMgmtBase creates it.
     * @param {GlideRecord} actionCreate - sn_vul_container_action_create_cr record
     * @param {string} parentId - sys_id of the container remediation task
     * @returns {string} sys_id of the change request
     */
    createNewChangeRequest: function(actionCreate, parentId) {
        if (actionCreate.getValue('change_request_type') != this.EXPEDITED)
            return sn_vul_container.ChangeMgmtBase.prototype.createNewChangeRequest.call(this, actionCreate, parentId);

        var change = global.ChangeRequest.newChange(new sn_vul.ChangeMgmt().getExpeditedChangeModel()).getGlideRecord();
        change.setValue('parent', parentId);
        change.setValue('implementation_plan', actionCreate.implementation_plan);
        change.setValue('description', actionCreate.description);
        change.setValue('short_description', actionCreate.short_description);
        change.setValue('assigned_to', actionCreate.assigned_to);
        change.setValue('assignment_group', actionCreate.assignment_group);
        change.setValue('end_date', actionCreate.end_date);
        change.setValue('priority', actionCreate.priority);
        change.setValue('justification', actionCreate.justification);
        return change.insert();
    },

    type: 'ChangeMgmt'
});
