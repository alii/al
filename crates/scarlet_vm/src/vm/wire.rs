//! `scarlet/wire`: values as bytes, under a descriptor of the type the call
//! site was inferred at.
//!
//! The declaration surface only. Both ops are in the ISA, both are reachable
//! from Scarlet, and both trap: the descriptor operand does not exist yet, and
//! without it neither walk has anything to walk. The encoder, the decoder and
//! the byte format land on top of this.
//!
//! What is already fixed here is the outcome vocabulary. `DecodeError`'s five
//! constructors are bound as [`AbiSlot`](crate::abi::AbiSlot)s, so the decoder
//! builds its refusals the same way every other stdlib error is built, and a
//! renamed constructor is a compile diagnostic rather than a mis-built value.

use super::{VM, VmError, VmResult};

impl VM {
    /// `Op::WireEncode` — `[value] -> Binary`.
    pub(super) fn wire_encode(&mut self) -> VmResult<()> {
        Err(VmError::internal(
            "wire.encode has no encoder yet: the op is declared, not implemented",
        ))
    }

    /// `Op::WireDecode` — `[bytes Binary] -> Result(a, DecodeError)`.
    pub(super) fn wire_decode(&mut self) -> VmResult<()> {
        Err(VmError::internal(
            "wire.decode has no decoder yet: the op is declared, not implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    //! The ABI half of the surface: every `DecodeError` the decoder will need
    //! is constructible from the VM today. Nothing here witnesses encoding or
    //! decoding — there is none — only that the five slots are bound, carry
    //! the arity their payload order fixes, and name the right constructor.

    use super::super::halt_test_vm;
    use crate::abi::AbiSlot;
    use crate::bytecode::Value;

    fn variant_of(v: &Value) -> String {
        v.as_enum()
            .expect("an ABI slot builds an enum")
            .variant_name()
            .to_string()
    }

    fn payload(v: &Value) -> Vec<Value> {
        v.as_enum()
            .expect("an ABI slot builds an enum")
            .payload()
            .to_vec()
    }

    #[test]
    fn the_vm_builds_every_decode_error_through_the_abi() {
        let mut vm = halt_test_vm();

        let truncated = vm.abi_nullary(AbiSlot::WireTruncated).expect("bound");
        assert_eq!(variant_of(&truncated), "Truncated");
        assert!(payload(&truncated).is_empty());

        let not_wire = vm.abi_nullary(AbiSlot::WireNotWire).expect("bound");
        assert_eq!(variant_of(&not_wire), "NotWire");
        assert!(payload(&not_wire).is_empty());

        let mismatch = vm
            .abi_make(
                AbiSlot::WireSchemaMismatch,
                &[Value::small_int(11), Value::small_int(22)],
            )
            .expect("bound");
        assert_eq!(variant_of(&mismatch), "SchemaMismatch");
        assert_eq!(
            payload(&mismatch)
                .iter()
                .map(|v| v.as_int().expect("Int payload"))
                .collect::<Vec<_>>(),
            vec![11, 22],
            "payload order is normative: expected then found"
        );

        let what = Value::str_in(&mut vm.heap, "variant tag out of range");
        let malformed = vm
            .abi_make(AbiSlot::WireMalformed, &[Value::small_int(7), what])
            .expect("bound");
        assert_eq!(variant_of(&malformed), "Malformed");
        let m = payload(&malformed);
        assert_eq!(m[0].as_int().expect("Int payload"), 7);
        assert_eq!(
            m[1].as_str().expect("Str payload"),
            "variant tag out of range"
        );

        let trailing = vm
            .abi_make(AbiSlot::WireTrailingBytes, &[Value::small_int(3)])
            .expect("bound");
        assert_eq!(variant_of(&trailing), "TrailingBytes");
        assert_eq!(payload(&trailing)[0].as_int().expect("Int payload"), 3);
    }

    /// The two ops are in the ISA and have no bodies. Pinned so the day a body
    /// lands, this test is what says so.
    #[test]
    fn both_ops_trap_until_their_bodies_land() {
        let mut vm = halt_test_vm();
        assert!(vm.wire_encode().is_err());
        assert!(vm.wire_decode().is_err());
    }
}
