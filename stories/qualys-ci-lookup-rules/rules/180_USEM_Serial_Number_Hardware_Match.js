/* =====================================================================
   RULE 180 - USEM Serial Number Hardware Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "MXQ13005TC"
   }

   sourceValue   = the SERIAL_NUMBER field  -> "MXQ13005TC"
   sourcePayload = the whole record above

   WHY THIS RULE SITS AT ORDER 180
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 175 already tried the serial inside the class the OS implies.
   - Reaches it: hosts with a serial whose OS is unknown (an unauthenticated
                 scan lists many OS guesses) or whose CI is classed differently
                 from what the OS suggests, so 175 found nothing.
   - After it  : 200 and above switch to names and addresses; a serial that is
                 not unique in the whole hardware tree is never used.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no SERIAL_NUMBER -> nothing to look up
        return null;
    var serial = ('' + sourceValue).trim();       // "MXQ13005TC"

    // Placeholder serials shared by many machines are rejected before searching
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    // "mxq13005tc" is 10 characters long and not a placeholder -> carry on
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // Stage 2 of serial matching: no class preference is used, the serial must
    // simply belong to exactly one CI anywhere under Hardware (servers,
    // computers, network gear, storage, printers ...).
    var gr = new GlideRecord('cmdb_ci_hardware'); // the whole hardware tree
    gr.addQuery('serial_number', serial);         // serial_number = "MXQ13005TC"
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);   // never pick a CI of an ignored class

    gr.query();                                   // run the search
    if (!gr.next())                               // no CI at all -> this rule declines, the next rule gets its turn
        return null;
    var match = gr.getUniqueValue();              // sys_id of the CI found, e.g. "b5f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
    if (gr.hasNext())                             // a second CI carries the same value -> ambiguous, never guess
        return null;
    return match;                                 // exactly one CI -> this is the match
})(rule, sourceValue, sourcePayload);
