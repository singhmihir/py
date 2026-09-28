(function executeRule(current, previous /*null when async*/) {
    if (current.isActionAborted())
        return;
    new BOFA_SI_VerificationIdHistory().appendToHistory(current, previous);
})(current, previous);
