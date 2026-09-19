/**
* @param {params} params
* @param {api} params.api
* @param {any} params.event
* @param {any} params.imports
* @param {ApiHelpers} params.helpers
*/
function handler({api, event, helpers, imports}) {
    // The resolve action refuses to run when a Trident task has no
    // attachment; close the dialog and surface its message on the page.
    var output = event && event.payload && event.payload.data ? event.payload.data.output : null;
    if (!output && api.data && api.data.resolve_task_action)
        output = api.data.resolve_task_action.output;
    if (output && output.error) {
        api.emit('ADD_NOTIFICATIONS', {
            items: [{
                "id": "alert-resolve-needs-attachment",
                "status": "critical",
                "icon": "circle-exclamation-outline",
                "content": output.error,
                "action": {
                    "type": "dismiss"
                }
            }]
        });
        helpers.modal.close();
        return;
    }
    helpers.translate('Successfully resolved task').then((value) => {
    api.emit('ADD_NOTIFICATIONS', {
        items: [{
            "id": "alert-succeded-to-resolve",
            "status": "info",
            "icon": "info-circle-outline",
            "content": value,
            "action": {
                "type": "dismiss"
            }
        }]
    });
    });
    api.emit("PARENT_FORM_RELOAD_CC");
    helpers.modal.close();
}
