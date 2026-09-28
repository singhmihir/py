var BOFA_SI_VerificationIdHistory = Class.create();
BOFA_SI_VerificationIdHistory.prototype = {

    /**
     * Configuration: the application vulnerable item table, its Verification ID history field, the
     * date and time formats stamped on each entry (time zone of the session saving the record) and the
     * pattern of a stamped entry.
     * @returns {void}
     */
    initialize: function() {
        this.TABLE = 'sn_vul_app_vulnerable_item';
        this.FIELD = 'u_verification_id';
        this.SOURCE_AVIT_ID = 'source_avit_id';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.STAMPED_ENTRY = / \(\d{2}-\d{2}-\d{4}( \d{2}:\d{2}:\d{2})?\)$/;
    },

    /**
     * Records a verification ID received from VAMP on every application vulnerable item carrying the
     * Source AVIT ID; the before rule on the table adds it under the earlier ones with the date and time.
     * @param {String} sourceAvitId - the Source AVIT ID named by the verification record, e.g. VMP-7781
     * @param {String} verificationId - the verification ID, e.g. VER-622
     * @returns {Number} the number of application vulnerable items updated
     */
    recordVerification: function(sourceAvitId, verificationId) {
        var updated = 0;
        try {
            sourceAvitId = String(sourceAvitId || '').trim();
            verificationId = String(verificationId || '').trim();
            if (!sourceAvitId)
                throw new Error('no Source AVIT ID was given');
            if (!verificationId)
                throw new Error('no verification ID was given');
            var avit = new GlideRecord(this.TABLE);
            avit.addQuery(this.SOURCE_AVIT_ID, sourceAvitId);
            avit.query();
            while (avit.next()) {
                avit.setValue(this.FIELD, verificationId);
                avit.update();
                updated++;
            }
            if (!updated)
                throw new Error('no application vulnerable item has this Source AVIT ID');
        } catch (e) {
            gs.error(this.type + ': verification ID ' + verificationId + ' not recorded for ' + this.TABLE + ' source_avit_id ' +
                sourceAvitId + ' - ' + (e.message || e));
        }
        return updated;
    },

    /**
     * Keeps the Verification ID history when a single new ID is written to the field: the earlier
     * entries stay in order and the new ID is added on the next line as "<ID> (MM-dd-yyyy HH:mm:ss)". An ID
     * already in the history is not added again; a value holding several lines or a stamped entry is
     * an edit of the history and is left as written.
     * @param {GlideRecord} current - the application vulnerable item being saved
     * @param {GlideRecord} previous - the record before the save; null on insert
     * @returns {void}
     */
    appendToHistory: function(current, previous) {
        var incoming = String(current.getValue(this.FIELD) || '').trim();
        if (!incoming || incoming.indexOf('\n') > -1 || this.STAMPED_ENTRY.test(incoming))
            return;
        var history = previous ? String(previous.getValue(this.FIELD) || '') : '';
        var entries = history ? history.split('\n') : [];
        for (var i = 0; i < entries.length; i++) {
            if (entries[i] == incoming || entries[i].indexOf(incoming + ' (') == 0) {
                current.setValue(this.FIELD, history);
                return;
            }
        }
        var now = new GlideDateTime();
        entries.push(incoming + ' (' + now.getLocalDate().getByFormat(this.DATE_FORMAT) + ' ' +
            now.getLocalTime().getByFormat(this.TIME_FORMAT) + ')');
        current.setValue(this.FIELD, entries.join('\n'));
    },

    type: 'BOFA_SI_VerificationIdHistory'
};
