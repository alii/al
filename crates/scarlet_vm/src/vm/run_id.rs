//! The identity of one run of one program.

use std::io;

/// The identity of this run: 128 bits from the OS CSPRNG, minted once per
/// [`Runtime`](super::sched::Runtime) and read by every scheduler through it.
///
/// A `Pid`, a `Subject` or a socket handle is a number that means something
/// only inside the run that minted it. Written to the wire beside the number,
/// this is what lets a decoder tell its own handles from another run's, the
/// way a pid from a dead BEAM node is recognisably foreign.
///
/// Two values are equal only if the CSPRNG produced the same 128 bits twice:
/// 2^-128 per pair, so two runs in one process, two runs started in the same
/// nanosecond, and two hosts each starting the same binary as pid 1 all
/// differ. Neither the clock nor the process id is mixed in — a fleet
/// starting one container per host at the same instant shares both.
///
/// The byte form is [`WIDTH`](Self::WIDTH) bytes, big-endian. It is a
/// compatibility surface: the wire header carries it, so it moves only with
/// the wire format version.
///
/// This is not a node name (clustering adds one), not a hash of the program
/// (two runs of one binary differ), and not persisted (a restart is a new
/// run).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RunId(u128);

impl RunId {
    /// Width in bytes of [`to_bytes`](Self::to_bytes) and
    /// [`from_bytes`](Self::from_bytes). The wire decoder reads exactly this
    /// many bytes for a handle's run.
    pub(crate) const WIDTH: usize = 16;

    /// Draw a fresh identity from the OS CSPRNG, the source `Op::RandomBytes`
    /// reads. Fails only when the OS cannot supply randomness. There is
    /// deliberately no clock-and-pid fallback: it would hand the fleet case
    /// above a colliding identity, and nothing would say so.
    pub(crate) fn mint() -> io::Result<RunId> {
        let mut bytes = [0u8; Self::WIDTH];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        Ok(RunId(u128::from_be_bytes(bytes)))
    }

    pub(crate) fn to_bytes(self) -> [u8; Self::WIDTH] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; Self::WIDTH]) -> RunId {
        RunId(u128::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::RunId;

    // A value with sixteen distinct bytes, so neither test below can pass on
    // a palindrome.
    const SAMPLE: RunId = RunId(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);

    #[test]
    fn the_byte_form_round_trips() {
        assert_eq!(RunId::from_bytes(SAMPLE.to_bytes()), SAMPLE);
        let minted = RunId::mint().expect("the OS must supply randomness");
        assert_eq!(RunId::from_bytes(minted.to_bytes()), minted);
    }

    // The width and byte order are what the wire header will carry; pinning
    // them here means a change there is a deliberate format change.
    #[test]
    fn the_byte_form_is_sixteen_bytes_most_significant_first() {
        let bytes = SAMPLE.to_bytes();
        assert_eq!(bytes.len(), RunId::WIDTH);
        assert_eq!(
            bytes,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }
}
