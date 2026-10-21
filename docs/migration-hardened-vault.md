# Migrating to the hardened vault (superseded)

The hardened vault this guide described (`vault_revision` 2, circuit
`zkapi-v2-note-bound-v1`) was built but never deployed. The concession-exit
vault (revision 3, circuit `zkapi-v2-concession-v1`) replaces it, so users
migrate once, from the legacy vault straight to revision 3.

Follow [Migrating to the concession-exit vault](migration-concession-vault.md).
Its Phase 0 is this guide's Phase 0, the in-place hardening of the legacy
stack, which now runs from the release line `release/v2-note-bound`. Its
operations runbooks, rollback table, compromise procedure and residual risks
replace the ones here.

The full text of this guide stays on `release/v2-note-bound`
(`docs/migration-hardened-vault.md` there). Use that copy only for the legacy
stack: the behaviour changes and compatibility of its services and clients,
and its legacy-only runbooks, such as "Receipt journal missing". Its Phases 1
to 4, which deploy the revision-2 vault, do not apply.
