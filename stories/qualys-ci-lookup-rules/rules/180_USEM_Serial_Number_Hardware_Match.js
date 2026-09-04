/* =================================================================================================
   RULE 180 - USEM Serial Number Hardware Match
   =================================================================================================
   PURPOSE
   Match a scanned host to its CI by serial number anywhere in the hardware tree (servers,
   computers, network gear, storage, printers). It is the second and last serial stage: it runs when
   rule 175 could not use the class the OS implies, and it still insists on the serial belonging to
   exactly one CI.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "MXQ13005TC"
   }

   sourceValue   = the SERIAL_NUMBER field of that record -> "MXQ13005TC"
   sourcePayload = the whole record above
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the one hardware CI whose serial_number is "MXQ13005TC", for
   example the Server CI "txr9gxcenah031" (stored in the generic Server class because the scan could
   not identify its OS); its sys_id is returned.

   WHY THIS RULE SITS AT ORDER 180
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 175 already tried the serial inside the class the OS implies.
   - Reaches it: hosts with a serial whose OS is unknown (the sample OS is an unauthenticated scan
                 listing seven guesses, so no class can be chosen) or whose CI sits in a different
                 class than the OS suggests, so that 175 found nothing.
   - After it  : 200 and above switch to names and addresses. A serial that is not unique in the
                 whole hardware tree is never used.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a serial number
    2. Clean the serial number
    3. Reject placeholder serial numbers
    4. Read the list of CI classes that must never be matched
    5. Search the whole hardware tree for the serial
    6. Decide: exactly one CI, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a serial number
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "MXQ13005TC" -> not empty -> the rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the serial number
    // What happens : '' + sourceValue turns the platform value into a plain text string and trim()
    //                removes blanks at both ends. Blanks inside the value stay, because they are
    //                part of the serial.
    // Why          : some feeds pad values with blanks; a search for " MXQ13005TC " would not find
    //                "MXQ13005TC".
    // Sample       : serial = "MXQ13005TC".
    // ---------------------------------------------------------------------------------------------
    var serial = ('' + sourceValue).trim();
    // -> serial = "MXQ13005TC" (10 characters).
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Reject placeholder serial numbers
    // What happens : the rule keeps a list of placeholder serials that vendors ship on thousands of
    //                machines ("To Be Filled By O.E.M.", "System Serial Number", "0123456789",
    //                "None" and so on) and refuses to search for any of them, or for a serial
    //                shorter than four characters.
    // Why          : a placeholder would match dozens of CIs at once and the tie could never be
    //                broken; declining at once lets the name and address rules do the work instead.
    // Sample       : "mxq13005tc" is 10 characters long and is not in the list -> carry on. "N/A"
    //                would be found as ",n/a," in the list -> decline. "12" is shorter than four
    //                characters -> decline.
    // ---------------------------------------------------------------------------------------------
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    // -> junk = one long text with a comma before and after every placeholder, so that "," + serial
    //    + "," can only be found when the whole serial equals a placeholder (",na," is never found
    //    inside ",not available,").
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;
    // -> serial.toLowerCase() = "mxq13005tc"; junk.indexOf(",mxq13005tc,") = -1 (not found) and the
    //    length is 10 -> the condition is false -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - Read the list of CI classes that must never be matched
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
    // STAGE 5 - Search the whole hardware tree for the serial
    // What happens : opens a search on cmdb_ci_hardware, the parent class of every physical and
    //                virtual device class (Server, Linux Server, Windows Server, Computer, Network
    //                Gear, Storage Server, Printer and so on), keeps only CIs whose serial_number
    //                equals the cleaned serial, and leaves out every class on the ignore list. No
    //                class preference is used at this stage.
    // Why          : the OS gave no usable class, so the serial itself has to carry the decision;
    //                that is safe because the next stage still requires the serial to belong to
    //                exactly one CI in the whole tree.
    // Sample       : the search on cmdb_ci_hardware for serial_number = "MXQ13005TC" finds the
    //                Server "txr9gxcenah031" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord('cmdb_ci_hardware');
    // -> gr = a search on Hardware and every class beneath it; nothing has run yet.
    gr.addQuery('serial_number', serial);
    // -> condition added: serial_number = "MXQ13005TC" (exact match, case-insensitive).
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Decide: exactly one CI, or decline
    // What happens : runs the search, reads the first CI and accepts it only when there is no
    //                second CI in the result.
    // Why          : every finding of this host will be linked to the CI the rule returns. A wrong
    //                CI sends the findings to the wrong owner, so when two CIs share the value the
    //                rule refuses to guess and answers null; a later rule with different evidence
    //                may still resolve the host, and if none does the host stays unmatched for the
    //                CMDB team to review.
    // Sample       : one CI -> the Server "txr9gxcenah031" -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null and rule 200 gets its
    //                turn. Two CIs -> "txr9gxcenah031" and a Storage Server that was loaded with
    //                the same serial -> return null.
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
