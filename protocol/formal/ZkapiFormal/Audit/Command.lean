import Lean.Util.CollectAxioms
import Lean.Elab.Command

/-! The axiom-audit command, from msp-formal-curve `Proofs/AuditCommand.lean` (Apache-2.0, same
author). It lives in a module that imports only core Lean, so every name and instance its code
uses is resolved before any project module loads, and no project declaration can change what it
checks.

`assert_standard_axioms n` fails unless every axiom `n` depends on is one of Lean's standard
`propext`, `Classical.choice` and `Quot.sound`. An admitted proof (`sorryAx`), a declared
`axiom`, or `native_decide` (`Lean.ofReduceBool`) therefore fails the build. -/

elab "assert_standard_axioms " n:ident : command => do
  let name ← _root_.Lean.Elab.Command.liftCoreM <|
    _root_.Lean.Elab.realizeGlobalConstNoOverloadWithInfo n
  let axioms ← _root_.Lean.collectAxioms name
  let allowed : _root_.List _root_.Lean.Name := [`propext, `Classical.choice, `Quot.sound]
  let extra := axioms.filter fun ax => !allowed.contains ax
  unless extra.isEmpty do
    _root_.Lean.throwError m!"{n} depends on nonstandard axioms: {extra}"

/-- `assert_standard_axioms_in ns` runs the same check on every declaration whose name starts
with `ns` (theorems, definitions and generated auxiliaries alike) and reports how many it
checked. -/
elab "assert_standard_axioms_in " ns:ident : command => do
  let env ← _root_.Lean.MonadEnv.getEnv
  let pre := ns.getId
  let names : _root_.List _root_.Lean.Name := env.constants.fold
    (fun (acc : _root_.List _root_.Lean.Name) n _ => if pre.isPrefixOf n then n :: acc else acc) []
  let allowed : _root_.List _root_.Lean.Name := [`propext, `Classical.choice, `Quot.sound]
  for name in names do
    let axioms ← _root_.Lean.Elab.Command.liftCoreM <| _root_.Lean.collectAxioms name
    let extra := axioms.filter fun ax => !allowed.contains ax
    unless extra.isEmpty do
      _root_.Lean.throwError m!"{name} depends on nonstandard axioms: {extra}"
  _root_.Lean.logInfo m!"{names.length} declarations under {pre} use only standard axioms"
