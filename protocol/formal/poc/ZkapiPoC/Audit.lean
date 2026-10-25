import ZkapiFormal.Audit.Command
import ZkapiPoC.Compress

/-! The PoC's axiom audit, as `ZkapiFormal.Audit.Axioms` does for the main development. -/

assert_standard_axioms Zkapi.PoC.execL_unemb
assert_standard_axioms Zkapi.PoC.pocOK_source
assert_standard_axioms Zkapi.PoC.permute_body
assert_standard_axioms Zkapi.PoC.poc_compress
assert_standard_axioms Zkapi.PoC.poc_compress_reference
assert_standard_axioms Zkapi.PoC.poc_vector_compress
assert_standard_axioms Zkapi.PoC.poc_vector_short
assert_standard_axioms Zkapi.PoC.poc_vector_selector
assert_standard_axioms_in Zkapi.PoC
