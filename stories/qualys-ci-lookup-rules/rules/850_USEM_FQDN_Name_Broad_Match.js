/* =================================================================================================
   RULE 850 - USEM FQDN Name Broad Match
   =================================================================================================
   PURPOSE
   The single, deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI
   table, including classes outside the hardware tree (for example a virtual machine instance or
   another logical CI). It still requires a unique owner outside the ignored classes.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "71973166",
     "IP": "164.91.209.12",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 8.10",
     "DNS": "lva40bneehcs01.ecomm.devicenp.rpg",
     "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"
   }

   sourceValue   = the DNS field of that record -> "lva40bneehcs01.ecomm.devicenp.rpg"
   sourcePayload = the whole record above
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the one CI in any class whose name is
   "lva40bneehcs01.ecomm.devicenp.rpg", for example a Virtual Machine Instance; declined when the
   name is shared.

   WHY THIS RULE SITS AT ORDER 850
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : every hardware-scoped rule (175 to 740) has declined for this host.
   - Reaches it: the rare CI named with the full FQDN that lives outside the hardware tree.
   - After it  : the out-of-box Qualys rules: 860 QUALYS HOST ID, 880 Cloud Resource Id, 900 FQDN,
                 920 NetBIOS, 940 DNS, and 950/960 IP which are inactive by default. Those are the
                 vendor's best-effort matching.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and require a domain part
    3. Read the list of CI classes that must never be matched
    4. Search the whole CI table for a CI named with the full FQDN
    5. Decide: exactly one CI, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "lva40bneehcs01.ecomm.devicenp.rpg" -> not empty -> the rule
    //                carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the DNS name and require a domain part
    // What happens : '' + sourceValue turns the value into plain text, trim() removes blanks at
    //                both ends and toLowerCase() lowers it. Then the rule requires at least one dot
    //                in the name.
    // Why          : DNS names are case-insensitive and CMDB values are stored in mixed case, so
    //                both sides are compared in lower case. A name without a dot is a bare
    //                hostname, which the hostname rules (400 and 410) look after.
    // Sample       : fqdn = "lva40bneehcs01.ecomm.devicenp.rpg"; indexOf(".") finds a dot -> carry
    //                on. A bare label "lva40bneehcs01" has no dot -> indexOf(".") = -1 -> decline.
    // ---------------------------------------------------------------------------------------------
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    // -> fqdn = "lva40bneehcs01.ecomm.devicenp.rpg".
    if (fqdn.indexOf('.') == -1)
        return null;
    // -> indexOf(".") = 14 for the sample (the position of the first dot) -> not -1 -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Read the list of CI classes that must never be matched
    // What happens : reads the list of CI classes that must never be matched. Administrators keep
    //                it in the system property sn_sec_cmn.ignoreCIClass as comma separated class
    //                names. The framework may also hand the same list to the script as a variable
    //                called _ignoreClass; when that variable exists and is filled the script uses
    //                it, otherwise it reads the property directly.
    // Why          : placeholder and technical classes must never receive vulnerability findings:
    //                the unmatched CI placeholders that Security Operations creates, the Qualys
    //                staging CI class, Unclassed Hardware, incomplete IP records and DNS Name
    //                records. Keeping the list in one property means it can be changed without
    //                editing sixteen scripts.
    // Sample       : with the platform default the property holds
    //                "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name";
    //                an empty property gives ignore = "" and then no class filter is added to the
    //                searches below.
    // ---------------------------------------------------------------------------------------------
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name",
    //    one text, comma separated, ready for a NOT IN condition.
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - Search the whole CI table for a CI named with the full FQDN
    // What happens : opens a search on cmdb_ci, the root of every CI class, keeps only CIs whose
    //                name equals the complete lower-cased DNS name, and leaves out every class on
    //                the ignore list.
    // Why          : this is the only USEM rule that searches outside the hardware tree, which is
    //                why it runs last: every more precise rule has had its chance, and the ignore
    //                list still keeps placeholder classes out.
    // Sample       : the search on cmdb_ci for name = "lva40bneehcs01.ecomm.devicenp.rpg" finds the
    //                Virtual Machine Instance "lva40bneehcs01.ecomm.devicenp.rpg" (sys_id
    //                3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord('cmdb_ci');
    // -> gr = a search on the root CI table, which covers every class.
    gr.addQuery('name', fqdn);
    // -> condition added: name = "lva40bneehcs01.ecomm.devicenp.rpg" (the full string,
    //    case-insensitive).
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - Decide: exactly one CI, or decline
    // What happens : runs the search, reads the first CI and accepts it only when there is no
    //                second CI in the result.
    // Why          : every finding of this host will be linked to the CI the rule returns. A wrong
    //                CI sends the findings to the wrong owner, so when two CIs share the value the
    //                rule refuses to guess and answers null; a later rule with different evidence
    //                may still resolve the host, and if none does the host stays unmatched for the
    //                CMDB team to review.
    // Sample       : one CI -> the Virtual Machine Instance "lva40bneehcs01.ecomm.devicenp.rpg" ->
    //                return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null; the
    //                out-of-box Qualys rules (860 and above) get their turn and, if they also
    //                decline, the host stays unmatched for review. Two CIs -> two CIs with that
    //                full name -> return null.
    // ---------------------------------------------------------------------------------------------
    gr.query();
    // -> the search has run; gr now sits just before the first row of the result (0, 1 or more
    //    CIs).
    if (!gr.next())
        return null;
    // -> next() moves to the first CI and returns true. When the result is empty it returns false
    //    and the rule declines with null.
    var match = gr.getUniqueValue();
    // -> match = the 32-character sys_id of that CI, for example
    //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"; this is the value the framework expects back.
    if (gr.hasNext())
        return null;
    // -> hasNext() is true when a second CI is waiting in the result: two owners of one value is an
    //    ambiguity, so the rule declines.
    return match;
    // -> exactly one CI: its sys_id goes back to the framework, which links the vulnerable item to
    //    it and stops evaluating later rules.
})(rule, sourceValue, sourcePayload);
