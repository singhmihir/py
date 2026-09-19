/* USEM FQDN Name Hardware Match
   -------------------------------------------------------------------------------------------------
   Some loads name the CI with the whole FQDN string instead of the short hostname (the appliance
   domains ending in .rpg are the usual case), so a short name search never finds them. This rule
   compares the complete scanned name with the name field, across the hardware tree.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "71973166",
     "IP": "164.91.209.12",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 8.10",
     "DNS": "lva40bneehcs01.ecomm.devicenp.rpg",
     "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"
   }
   Input  : sourceValue is the DNS field, "lva40bneehcs01.ecomm.devicenp.rpg".
   Returns: the sys_id of the one hardware CI whose name is exactly the scanned FQDN; null when none
            or two carry it.
   Sample : the hardware CI named exactly "lva40bneehcs01.ecomm.devicenp.rpg", when it is the only
            one.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : every rule so far compared the short hostname "lva40bneehcs01" or the fqdn field.
   Reaches: CIs named with the full FQDN, which none of the earlier rules can see.
   After  : the IP address rules, and finally USEM FQDN Name Broad Match, the only rule allowed to
            search the whole CI table.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "lva40bneehcs01.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Full FQDN as the CI name, across the hardware tree, one CI only --------------------------
    // The name is compared with the whole string including the domain; the CI is accepted only when
    // it is the single row.
    // Sample: the search on cmdb_ci_hardware for name "lva40bneehcs01.ecomm.devicenp.rpg" finds the
    //         Server named exactly that and no second row, so its sys_id is returned.
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
