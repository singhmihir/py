/* USEM Serial Number Hardware Match
   -------------------------------------------------------------------------------------------------
   Second and last serial rule: the same serial search, but across the whole hardware tree (servers,
   computers, network gear, storage, printers). It exists for hosts whose OS gives no usable class
   and for CIs that sit in a different class than the OS suggests.

   Input  : sourceValue is the SERIAL_NUMBER field.
   Returns: the sys_id of the one hardware CI whose serial_number equals the scanned serial; null
            when none or more than one carries it.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM Serial Number Class Match already tried the serial inside the class the OS implies.
   Reaches: hosts with a serial whose OS is unknown (an unauthenticated scan listing several
            guesses, such as "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5
            Networks Big-IP / Cisco IOS Software") or whose CI is classed differently.
   After  : the phone rule and the name rules. A serial that is not unique in the whole hardware
            tree is never used.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var serial = ('' + sourceValue).trim();       // e.g. "MXQ13005TC"
    // Placeholder serials that vendors ship on thousands of machines ("To be filled by O.E.M.",
    // "0123456789") would match dozens of CIs, so they are refused, as is anything shorter than
    // four characters.
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Serial search across the hardware tree, one CI only --------------------------------------
    // cmdb_ci_hardware is the parent of every device class, so nothing is filtered by class here;
    // the safety is that the serial still has to belong to exactly one CI in the whole tree.
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('serial_number', serial);
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
