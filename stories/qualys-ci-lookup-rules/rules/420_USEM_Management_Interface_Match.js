/* =================================================================================================
   RULE 420 - USEM Management Interface Match
   =================================================================================================
   Match the management controller of a server (HP iLO, Oracle ILOM, Dell iDRAC, IBM IMM, Cisco
   CIMC, generic BMC or IPMI) to the server itself. Controllers are scanned under their own DNS
   label, which is the server name plus a suffix ("-ilo", "-ilom", "-idrac"), so the name rules
   never find them. The findings belong to the server owner.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "1201534877",
     "IP": "159.185.200.11",
     "TRACKING_METHOD": "IP",
     "OS": "HP iLO",
     "DNS": "tx6dd630001-ilo.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "tx6dd630001-ilo.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the OS from it
   Expected for the sample: the hardware CI named "tx6dd630001" (the label without "-ilo"), for
   example a Linux Server; null when no CI or two CIs carry that name, or when the CI is a load
   balancer.

   WHY THIS RULE SITS AT ORDER 420
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 400/410 tried the full label "tx6dd630001-ilo" as a hostname and found nothing,
                 because no CI is named after the controller.
   - Reaches it: hosts whose label ends with a listed controller suffix, or whose OS text names a
                 controller (property lists usem.ci_lookup.mgmt_suffixes and
                 usem.ci_lookup.mgmt_os_markers).
   - After it  : 430 (network interface names) and 450 (CI named with the full FQDN).
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "tx6dd630001-ilo.bankofamerica.com"
    var label = full.split('.')[0];               // "tx6dd630001-ilo"
    var dash = label.lastIndexOf('-');             // 11, position of the last hyphen
    if (dash < 1)                                 // no hyphen -> nothing to strip -> decline
        return null;
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // "hp ilo"
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // list() reads a comma separated system property into a lower-cased list, falling back to the
    // default shipped with the rule. Administrators tune the rule by editing the property, not the
    // script.
    function list(name, fallback) {
        var parts = ('' + gs.getProperty(name, fallback)).split(',');
        var out = [];
        for (var i = 0; i < parts.length; i++) {
            var item = parts[i].trim().toLowerCase();
            if (item)
                out.push(item);
        }
        return out;
    }
    // ====== STAGE 1: Recognise a management controller and derive the server name ================
    // What   : the segment after the last hyphen is compared with the suffix list; when it is
    //          listed, the server name is the label without it. Otherwise the OS text is compared
    //          with the controller markers; when one is found, the last segment is stripped
    //          whatever it is, because controllers are named after their server with a
    //          site-specific tail such as "-r".
    // Why    : the two pieces of evidence cover both naming habits seen in the scans: an explicit
    //          suffix with any OS, and a controller OS with an arbitrary tail. Without either the
    //          host is not a controller and the rule must not touch it.
    // Sample : "tx6dd630001-ilo" -> tail "ilo" is listed -> base = "tx6dd630001". "crpchictx103-r"
    //          with OS "HP iLO" -> tail "r" is not listed, but the OS names a controller -> base =
    //          "crpchictx103". "usposwks0042-x" with OS "Windows 10" -> neither -> decline.
    // =============================================================================================
    var suffixes = list('usem.ci_lookup.mgmt_suffixes', 'ilo,ilom,idrac,drac,ipmi,bmc,oob,mgmt,imm,cimc,rmm,con');
    var markers = list('usem.ci_lookup.mgmt_os_markers', 'ilo,ilom,idrac,drac,remote access controller,imm,cimc,bmc,ipmi,lights out');
    var tail = label.substring(dash + 1);         // "ilo"
    var base = '';
    if (suffixes.indexOf(tail) != -1)
        base = label.substring(0, dash);          // listed suffix -> "tx6dd630001"
    else
        for (var i = 0; i < markers.length; i++)
            if (os.indexOf(markers[i]) != -1) {
                base = label.substring(0, dash);  // controller OS -> strip the last segment
                break;
            }
    // -> base = "tx6dd630001" for the sample; "" when the host shows no controller evidence
    if (!base)
        return null;
    // ====== STAGE 2: Search the hardware tree for the server name ================================
    // What   : opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the derived
    //          server name, and leaves out the ignored classes.
    // Why    : the controller can sit in front of a server, a storage node or a network device, so
    //          the whole hardware tree is searched; safety comes from the uniqueness check that
    //          follows.
    // Sample : the search on cmdb_ci_hardware for name = "tx6dd630001" finds the Linux Server
    //          "tx6dd630001".
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('name', base);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 3: Decide: exactly one CI that is not a load balancer, or decline ==============
    // What   : runs the search, accepts the CI only when it is the single one, and refuses a load
    //          balancer.
    // Why    : two CIs with the server name cannot be told apart from the controller label alone,
    //          and a load balancer answering on a management address is still not the scanned host.
    // Sample : one CI -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> null and rule 430 gets
    //          its turn. Two CIs named "crpchictx103" -> null.
    // =============================================================================================
    gr.query();
    if (!gr.next())                               // no CI carries the server name -> decline
        return null;
    var match = gr.getUniqueValue();
    if (gr.hasNext())                             // two CIs carry it -> never guess
        return null;
    var lb = new GlideRecord('cmdb_ci_lb');
    if (lb.isValid() && lb.get(match))            // a load balancer is never the host
        return null;
    return match;
    // -> the framework links the vulnerable item to the server and stops evaluating later rules
})(rule, sourceValue, sourcePayload);
