// Adds Expedited to the Change type list of the workspace Create Change dialog of the application
// selected in the application picker. Run it in Scripts - Background once per application, with that
// application and its update set selected:
//   Vulnerability Response - IT and application remediation tasks (VUL, AVUL)
//   Vulnerability Response and Configuration Compliance for Containers - container tasks (CVUL)
//   Configuration Compliance - Configuration Compliance remediation tasks (CRG)
var PAGES = ['59061b92b7072010aed5b064ce11a92c', 'fd9d6e2953021110501fddeeff7b1296',
    '996c1f486db42110f877388cdecc4b6f'];
var page = new GlideRecord('sys_ux_macroponent');
page.addQuery('sys_id', 'IN', PAGES.join(','));
page.addQuery('sys_scope', gs.getCurrentApplicationId());
page.query();

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

if (!page.next()) {
    gs.print('The selected application has no Create Change dialog: select Vulnerability Response, ' +
        'Vulnerability Response and Configuration Compliance for Containers or Configuration Compliance.');
} else {
    var composition = JSON.parse(page.getValue('composition'));
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
    gs.print(page.getValue('name') + ' - Change type items: ' + items.map(function(item) {
        return item.container.id.value;
    }).join(', '));
}
