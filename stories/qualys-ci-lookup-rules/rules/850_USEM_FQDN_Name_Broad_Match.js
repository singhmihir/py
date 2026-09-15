/* USEM FQDN Name Broad Match
   -------------------------------------------------------------------------------------------------
   The one deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI
   table, classes outside the hardware tree included (a virtual machine instance, another logical
   CI). It still insists on a single owner outside the ignored classes.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "71973167",
     "IP": "164.91.209.13",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 8.10",
     "DNS": "lva40bneehcs02.ecomm.devicenp.rpg"
   }
   Input  : sourceValue is the DNS field, "lva40bneehcs02.ecomm.devicenp.rpg".
   Returns: the sys_id of the one CI in any class whose name is exactly the scanned FQDN; null when
            the name is shared.
   Sample : the Virtual Machine Instance named "lva40bneehcs02.ecomm.devicenp.rpg", which lives
            outside the hardware tree and so escaped every earlier rule.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : every hardware-scoped rule has declined for this host; USEM FQDN Name Hardware Match
            searched for the same name but only under Hardware.
   Reaches: the rare CI named with the full FQDN that lives outside the hardware tree.
   After  : the out-of-box Qualys rules (Qualys Host ID, Cloud Resource Id, FQDN, NetBIOS, DNS; the
            IP ones are inactive by default).
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "lva40bneehcs02.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Full FQDN as the CI name, across the whole CI table, one CI only -------------------------
    // This is the only USEM rule that searches outside the hardware tree, which is why it runs
    // last: every more precise rule has had its chance, and the ignore list still keeps the
    // placeholder classes out.
    // Sample: the search on cmdb_ci for name "lva40bneehcs02.ecomm.devicenp.rpg" finds the Virtual
    //         Machine Instance named exactly that and no second row, so its sys_id is returned.
    var gr = new GlideRecord('cmdb_ci');      // the root CI table, every class
    gr.addQuery('name', fqdn);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.query();
    if (!gr.next())
        return null;
    var match = gr.getUniqueValue();
    if (gr.hasNext())                             // a second CI carries the same value, never guess
        return null;
    return match;
})(rule, sourceValue, sourcePayload);
