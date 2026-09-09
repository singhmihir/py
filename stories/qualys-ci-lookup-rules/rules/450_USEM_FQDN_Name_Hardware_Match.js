/* USEM FQDN Name Hardware Match
   -------------------------------------------------------------------------------------------------
   Some loads name the CI with the whole FQDN string instead of the short hostname (the appliance
   domains ending in .rpg are the usual case), so a short name search never finds them. This rule
   compares the complete scanned name with the name field, across the hardware tree.

   Input  : sourceValue is the DNS field.
   Returns: the sys_id of the one hardware CI whose name is exactly the scanned FQDN; null when none
            or two carry it.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : every rule so far compared the short hostname or the fqdn field.
   Reaches: CIs named with the full FQDN, which none of the earlier rules can see.
   After  : the IP address rules, and finally USEM FQDN Name Broad Match, the only rule allowed to
            search the whole CI table.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // e.g. "lva40bneehcs01.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Full FQDN as the CI name, across the hardware tree, one CI only --------------------------
    // The name is compared with the whole string including the domain; the CI is accepted only when
    // it is the single row.
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
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
