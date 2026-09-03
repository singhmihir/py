function transform(input) {
    var recordSysID = input.recordSysID;
    var resolution_notes = input.resolution_notes;
    var gr = new GlideRecord(input.table);
    gr.get(recordSysID);
    //SNOWUSEMTP-1420 config starts
    // Trident remediation tasks may only be resolved with evidence attached.
    if (input.table == "sn_vulc_result_group") {
        var util = new sn_vulc.TridentClosureUtil();
        if (util.isTridentTask(gr) && !util.hasEvidence(gr)) {
            return {
                resolved: false,
                error: gs.getMessage("There is no attachment to this VIT; please attach using the paper clip icon before resolving.")
            };
        }
    }
    //SNOWUSEMTP-1420 - config ends


    gr.setValue("state", 101);
    gr.setValue("resolution_reason", resolution_notes);
    if (input.table == "sn_vulc_result_group")
        gr.setValue("substate", input.substate);
    return {
        resolved: true,
        sys_id: gr.update()
    };
}