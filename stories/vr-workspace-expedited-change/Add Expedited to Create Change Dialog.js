// Adds Expedited to the Change type list of the workspace Create Change dialog
// (page "Modal - Create Change Request"). Run it once, in Scripts - Background, with the
// application picker on Vulnerability Response and its update set selected.
var page = new GlideRecord('sys_ux_macroponent');
page.get('59061b92b7072010aed5b064ce11a92c');
var composition = JSON.parse(page.getValue('composition'));

function findElement(list, elementId) {
    for (var i = 0; i < list.length; i++) {
        if (list[i].elementId == elementId)
            return list[i];
        var inner = list[i].overrides && list[i].overrides.composition;
        var found = inner ? findElement(inner, elementId) : null;
        if (found)
            return found;
    }
    return null;
}

function text(message) {
    return {type: 'TRANSLATION_LITERAL', value: {code: null, comment: '', message: message}};
}

var items = findElement(composition, 'change_type').propertyValues.items.container;
var present = items.some(function(item) {
    return item.container.id.value == 'expedited';
});
if (!present) {
    items.push({
        container: {
            id: {type: 'JSON_LITERAL', value: 'expedited'},
            label: text('Expedited'),
            sublabel: text('Create an expedited Change Request.')
        },
        type: 'MAP_CONTAINER'
    });
    page.setValue('composition', JSON.stringify(composition, null, 4));
    page.update();
}
gs.print('Change type items: ' + items.map(function(item) {
    return item.container.id.value;
}).join(', '));
