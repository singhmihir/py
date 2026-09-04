/* =================================================================================================
   RULE 850 - USEM FQDN Name Broad Match
   =================================================================================================
   The single, deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI
   table, classes outside the hardware tree included (a virtual machine instance, another logical
   CI). Still requires a unique owner outside the ignored classes.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "71973166",
     "IP": "164.91.209.12",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 8.10",
     "DNS": "lva40bneehcs01.ecomm.devicenp.rpg",
     "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"
   }

   sourceValue   = the DNS field -> "lva40bneehcs01.ecomm.devicenp.rpg"
   sourcePayload = the whole record
   Expected for the sample: the one CI in any class whose name is
   "lva40bneehcs01.ecomm.devicenp.rpg", for example a Virtual Machine Instance; declined when the
   name is shared.

   WHY THIS RULE SITS AT ORDER 850
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : every hardware-scoped rule (175 to 740) has declined for this host.
   - Reaches it: the rare CI named with the full FQDN that lives outside the hardware tree.
   - After it  : the out-of-box Qualys rules: 860 QUALYS HOST ID, 880 Cloud Resource Id, 900 FQDN,
                 920 NetBIOS, 940 DNS, and 950/960 IP which are inactive by default.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "lva40bneehcs01.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Search the whole CI table for a CI named with the full FQDN =================
    // What   : opens a search on cmdb_ci, the root of every CI class, keeps only CIs whose name
    //          equals the complete lower-cased DNS name, and leaves out the ignored classes.
    // Why    : this is the only USEM rule that searches outside the hardware tree, which is why it
    //          runs last: every more precise rule has had its chance, and the ignore list still
    //          keeps placeholder classes out.
    // Sample : the search on cmdb_ci for name = "lva40bneehcs01.ecomm.devicenp.rpg" finds the
    //          Virtual Machine Instance "lva40bneehcs01.ecomm.devicenp.rpg".
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ci');      // the root CI table, every class
    gr.addQuery('name', fqdn);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 2: Decide: exactly one CI, or decline ==========================================
    // What   : runs the search, reads the first CI and accepts it only when no second CI is in the
    //          result.
    // Why    : every finding of this host is linked to the CI returned; a wrong CI sends findings
    //          to the wrong owner. Two CIs sharing the value is an ambiguity, so the rule declines
    //          and a later rule with different evidence may still resolve the host.
    // Sample : one CI (the Virtual Machine Instance "lva40bneehcs01.ecomm.devicenp.rpg") -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null; the out-of-box Qualys
    //          rules (860 and above) get their turn. Two CIs -> two CIs with that full name ->
    //          return null.
    // =============================================================================================
    gr.query();
    if (!gr.next())                               // empty result -> decline
        return null;
    var match = gr.getUniqueValue();
    // -> match = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", the sys_id of the Virtual Machine Instance
    //    "lva40bneehcs01.ecomm.devicenp.rpg"
    if (gr.hasNext())                             // a second CI carries the same value -> never guess
        return null;
    return match;
    // -> the framework links the vulnerable item to this CI and stops evaluating later rules
})(rule, sourceValue, sourcePayload);
