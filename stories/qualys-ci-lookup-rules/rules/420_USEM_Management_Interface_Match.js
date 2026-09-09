/* USEM Management Interface Match
   -------------------------------------------------------------------------------------------------
   Server management controllers (HP iLO, Oracle ILOM, Dell iDRAC, IBM IMM, Cisco CIMC, generic BMC
   or IPMI) are scanned under their own DNS label, which is the server name plus a suffix such as
   "-ilo", "-ilom" or "-idrac", so the name rules never find them. The findings belong to the
   server, and this rule strips the suffix and matches the server.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "1201534877",
     "IP": "159.185.200.11",
     "TRACKING_METHOD": "IP",
     "OS": "HP iLO",
     "DNS": "tx6dd630001-ilo.bankofamerica.com"
   }
   Input  : sourceValue is the DNS field, "tx6dd630001-ilo.bankofamerica.com"; the rule also reads
            the OS from sourcePayload.
   Returns: the sys_id of the one hardware CI named like the label without its controller suffix;
            null when the host shows no controller evidence, when no CI or two CIs carry that name,
            or when the CI is a load balancer.
   Sample : the Linux Server CI "tx6dd630001", the label without "-ilo".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the hostname rules tried the whole label "tx6dd630001-ilo" and found nothing, because no
            CI is named after the controller.
   Reaches: hosts whose label ends with one of the controller suffixes, or whose OS text names a
            controller; both lists are declared in the script, at the top of the matching stage.
   After  : USEM Network Interface Name Match and USEM FQDN Name Hardware Match.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "tx6dd630001-ilo.bankofamerica.com"
    var label = full.split('.')[0];               // "tx6dd630001-ilo"
    var dash = label.lastIndexOf('-');             // 11
    if (dash < 1)                                 // no hyphen, nothing to strip
        return null;
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // "hp ilo"
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Recognise a controller and derive the server name ----------------------------------------
    // The segment after the last hyphen is checked against the suffix list; when it is listed the
    // server name is the label without it. Otherwise the OS text is checked for a controller word,
    // and then the last segment is stripped whatever it is, because some controllers carry a
    // site-specific tail instead. Both habits are in the feed. Without either piece of evidence the
    // host is not a controller and the rule must not touch it.
    // Sample: the tail "ilo" is in suffixes, so base is "tx6dd630001". "crpchictx103-r" with OS "HP
    //         iLO" has an unlisted tail but a controller OS, so base would be "crpchictx103".
    //         "usposwks0042-x" with a Windows OS has neither, so the rule would decline.
    // The label suffixes that mark a controller, and the words that name one in the OS text. Extend
    // these two lists when a site uses another naming habit.
    var suffixes = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con'];
    var markers = ['ilo', 'ilom', 'idrac', 'drac', 'remote access controller', 'imm', 'cimc', 'bmc', 'ipmi', 'lights out'];
    var tail = label.substring(dash + 1);         // "ilo"
    var base = '';
    if (suffixes.indexOf(tail) != -1)
        base = label.substring(0, dash);          // listed suffix: "tx6dd630001"
    else
        for (var i = 0; i < markers.length; i++)
            if (os.indexOf(markers[i]) != -1) {
                base = label.substring(0, dash);  // controller OS: strip the last segment
                break;
            }
    if (!base)
        return null;
    // -- The server by name, across the hardware tree, one CI only --------------------------------
    // The controller can sit in front of a server, a storage node or a network device, so the whole
    // hardware tree is searched. Two CIs with the server name cannot be told apart from the
    // controller label alone and the rule declines; a load balancer is refused because a balancer
    // answering on a management address is still not the scanned host.
    // Sample: the search on cmdb_ci_hardware for name "tx6dd630001" finds the Linux Server
    //         "tx6dd630001" and no second row; it is not a Load Balancer, so its sys_id is
    //         returned. Two servers named "crpchictx103" would make the rule decline.
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('name', base);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.query();
    if (!gr.next())
        return null;
    var match = gr.getUniqueValue();
    if (gr.hasNext())
        return null;
    var lb = new GlideRecord('cmdb_ci_lb');
    if (lb.isValid() && lb.get(match))
        return null;
    return match;
})(rule, sourceValue, sourcePayload);
