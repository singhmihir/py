/* =================================================================================================
   RULE 180 - USEM Serial Number Hardware Match
   =================================================================================================
   Match a scanned host by serial number anywhere in the hardware tree (servers, computers, network
   gear, storage, printers). Second and last serial stage: it runs when rule 175 could not use the
   class the OS implies, and still insists on the serial belonging to exactly one CI.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "MXQ13005TC"
   }

   sourceValue   = the SERIAL_NUMBER field -> "MXQ13005TC"
   sourcePayload = the whole record
   Expected for the sample: the one hardware CI whose serial_number is "MXQ13005TC", for example the
   Server CI "txr9gxcenah031" (kept in the generic Server class because the scan could not identify
   its OS).

   WHY THIS RULE SITS AT ORDER 180
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 175 already tried the serial inside the class the OS implies.
   - Reaches it: hosts with a serial whose OS is unknown (the sample OS is an unauthenticated scan
                 listing seven guesses) or whose CI sits in another class than the OS suggests.
   - After it  : 200 and above switch to names and addresses. A serial that is not unique in the
                 whole hardware tree is never used.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var serial = ('' + sourceValue).trim();       // "MXQ13005TC"
    // Placeholder serials that vendors ship on thousands of machines would match dozens of CIs at
    // once, so they are refused, as is any serial shorter than four characters.
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Search the whole hardware tree for the serial ===============================
    // What   : opens a search on cmdb_ci_hardware, the parent of every device class, keeps only CIs
    //          whose serial_number equals the serial, and leaves out the ignored classes. No class
    //          preference is used.
    // Why    : the OS gave no usable class, so the serial itself carries the decision; that is safe
    //          because the next stage still requires it to belong to exactly one CI in the whole
    //          tree.
    // Sample : the search on cmdb_ci_hardware for serial_number = "MXQ13005TC" finds the Server
    //          "txr9gxcenah031".
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('serial_number', serial);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 2: Decide: exactly one CI, or decline ==========================================
    // What   : runs the search, reads the first CI and accepts it only when no second CI is in the
    //          result.
    // Why    : every finding of this host is linked to the CI returned; a wrong CI sends findings
    //          to the wrong owner. Two CIs sharing the value is an ambiguity, so the rule declines
    //          and a later rule with different evidence may still resolve the host.
    // Sample : one CI (the Server "txr9gxcenah031") -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    //          No CI -> return null and rule 200 gets its turn. Two CIs -> "txr9gxcenah031" and a
    //          Storage Server loaded with the same serial -> return null.
    // =============================================================================================
    gr.query();
    if (!gr.next())                               // empty result -> decline
        return null;
    var match = gr.getUniqueValue();
    // -> match = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", the sys_id of the Server "txr9gxcenah031"
    if (gr.hasNext())                             // a second CI carries the same value -> never guess
        return null;
    return match;
    // -> the framework links the vulnerable item to this CI and stops evaluating later rules
})(rule, sourceValue, sourcePayload);
