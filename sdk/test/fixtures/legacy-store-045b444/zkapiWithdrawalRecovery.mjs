const TERMINAL_LATE_ATTEMPTS = new Set([
    'closed', 'detached', 'reverted', 'challenged', 'superseded', 'quarantined'
]);

// A retry can supersede a wallet window without closing it. Keep every live
// claim, including older journal formats, until its exact nonce is finalized.
export function backgroundWithdrawalClaims(record) {
    const prepared = record.preparedWithdrawal || {};
    const claims = [
        ...(record.startSubmissionId ? [{ submissionId: record.startSubmissionId,
            operationId: record.startOperationId, from: record.startSubmissionFrom,
            nonce: record.startSubmissionNonce }] : []),
        ...(prepared.submissionId ? [{ submissionId: prepared.submissionId,
            operationId: prepared.operationId, from: prepared.submissionFrom,
            nonce: prepared.submissionNonce }] : []),
        ...(record.supersededStartSubmissionClaims || []),
        ...(record.ambiguousStartReplacements || []),
        ...(prepared.ambiguousReplacements || []).map(claim => ({
            ...claim, operationId: prepared.operationId
        })),
        ...(record.startRetryFrom || record.startRetryNonce != null ? [{
            operationId: record.startRetryOperationId, from: record.startRetryFrom,
            nonce: record.startRetryNonce
        }] : [])
    ];
    const evidence = [...claims, ...(record.transactionAttempts || []),
        ...(prepared.transactionAttempts || [])];
    return claims.map(claim => {
        if (claim.from) return claim;
        const senders = [...new Set(evidence.filter(candidate => candidate.from
            && candidate.operationId === claim.operationId
            && candidate.nonce != null && claim.nonce != null
            && Number(candidate.nonce) === Number(claim.nonce))
            .map(candidate => String(candidate.from).toLowerCase()))];
        return { ...claim, from: senders.length === 1 ? senders[0] : null };
    });
}

// A canceled, never-broadcast close needs no chain-transition finality. Older
// clients manufactured challenge/finality metadata merely by polling an Active
// note, so those fields cannot establish that a transaction was ever submitted.
export function isUnsubmittedParkedMutualWithdrawal(record, lateAttempts = []) {
    const prepared = record?.preparedWithdrawal;
    if (record?.mode !== 'mutual' || prepared?.mode !== 'mutual'
        || !record.state || Number(record.state.note_id) !== Number(record.noteId)
        || Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(record.noteId)
        || !['parked', 'restored', 'challenged_unconfirmed', 'recovery_unconfirmed'].includes(record.phase)
        || !['prepared', 'reserving'].includes(prepared.phase || 'prepared')
        || ['pending_withdrawal', 'closed'].includes(record.chainStatus)) return false;

    const scalarEvidence = [
        'transactionHash', 'submissionId', 'startSubmissionId', 'finalizeSubmissionId',
        'finalizeTransactionHash', 'startRetryFrom', 'startRetryNonce',
        'submissionFrom', 'submissionNonce', 'startSubmissionFrom', 'startSubmissionNonce',
        'startBlockNumber', 'closeBlockNumber', 'challengeDeadline', 'closedAt'
    ];
    const arrayEvidence = [
        'transactionHashes', 'transactionAttempts', 'finalizeTransactionHashes',
        'finalizeTransactionAttempts', 'supersededStartSubmissionClaims',
        'ambiguousStartReplacements', 'ambiguousReplacements', 'ambiguousSubmissions',
        'ambiguousFinalizationSubmissions', 'finalizeAttempts', 'replacementOf'
    ];
    for (const value of [record, prepared]) {
        if (scalarEvidence.some(key => value[key] != null && value[key] !== false
            && value[key] !== '' && (!['startBlockNumber', 'closeBlockNumber', 'challengeDeadline', 'closedAt'].includes(key)
                || Number(value[key]) > 0))) return false;
        if (arrayEvidence.some(key => Array.isArray(value[key]) && value[key].length)) return false;
        if (value.startRecoveryPending === true
            || [value.submissionOutcome, value.startSubmissionOutcome].some(outcome =>
                /unknown|ambiguous|awaiting_wallet|submitted|receipt_missing/.test(String(outcome || '')))) return false;
    }
    return !lateAttempts.some(attempt => !TERMINAL_LATE_ATTEMPTS.has(attempt.status)
        && Number(attempt.noteId ?? attempt.note_id) === Number(record.noteId)
        && (!attempt.deploymentId || attempt.deploymentId === record.deploymentId));
}
