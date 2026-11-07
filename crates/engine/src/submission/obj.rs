//! Cooperative, bounded validator for the controlled triangular OBJ fixture.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(crate) const MAX_BYTES: usize = 1_048_576;
const MAX_VERTICES: usize = 10_000;
const MAX_FACES: usize = 20_000;
const MAX_LINES: usize = 40_000;
const MAX_LINE_BYTES: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_COORDINATE: f64 = 1_000_000.0;
const VALIDATION_SLOTS: usize = 2;
pub(super) const VALIDATION_WALL_BUDGET: Duration = Duration::from_millis(5_000);

static ACTIVE_VALIDATIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjError {
    Capacity,
    Deadline,
    TooLarge,
    InvalidUtf8,
    InvalidGrammar,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjSummary {
    pub(crate) bytes: usize,
    pub(crate) vertices: usize,
    pub(crate) faces: usize,
}

pub(super) struct ValidationPermit<'a>(&'a AtomicUsize);

impl ValidationPermit<'static> {
    pub(super) fn acquire() -> Result<Self, ObjError> {
        Self::acquire_from(&ACTIVE_VALIDATIONS)
    }
}

impl<'a> ValidationPermit<'a> {
    fn acquire_from(counter: &'a AtomicUsize) -> Result<Self, ObjError> {
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < VALIDATION_SLOTS).then_some(active + 1)
            })
            .map(|_| Self(counter))
            .map_err(|_| ObjError::Capacity)
    }
}

impl Drop for ValidationPermit<'_> {
    fn drop(&mut self) {
        let previous = self.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn validate_obj<R: Read>(reader: R) -> Result<ObjSummary, ObjError> {
    validate_obj_until(reader, Instant::now() + VALIDATION_WALL_BUDGET)
}

#[cfg(any(test, feature = "test-support"))]
fn validate_obj_until<R: Read>(reader: R, deadline: Instant) -> Result<ObjSummary, ObjError> {
    let permit = ValidationPermit::acquire()?;
    validate_obj_in(reader, deadline, &permit)
}

pub(super) fn validate_obj_in<R: Read>(
    reader: R,
    deadline: Instant,
    _permit: &ValidationPermit<'_>,
) -> Result<ObjSummary, ObjError> {
    let mut reader = BufReader::new(reader).take((MAX_BYTES + 1) as u64);
    let mut line = Vec::with_capacity(256);
    let mut bytes = 0usize;
    let mut lines = 0usize;
    let mut vertices: Vec<[f64; 3]> = Vec::new();
    let mut faces: Vec<[usize; 3]> = Vec::new();
    let mut unique_faces = BTreeSet::new();

    loop {
        check_deadline(deadline)?;
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|_| ObjError::InvalidGrammar)?;
        if read == 0 {
            break;
        }
        check_deadline(deadline)?;
        bytes = bytes.checked_add(read).ok_or(ObjError::TooLarge)?;
        if bytes > MAX_BYTES {
            return Err(ObjError::TooLarge);
        }
        lines += 1;
        if lines > MAX_LINES || line.len() > MAX_LINE_BYTES {
            return Err(ObjError::LimitExceeded);
        }
        let text = std::str::from_utf8(&line).map_err(|_| ObjError::InvalidUtf8)?;
        let content = text.split_once('#').map_or(text, |(before, _)| before);
        let mut fields = content.split_ascii_whitespace();
        let Some(directive) = fields.next() else {
            continue;
        };
        let tokens = fields.collect::<Vec<_>>();
        if tokens.iter().any(|token| token.len() > MAX_TOKEN_BYTES) {
            return Err(ObjError::LimitExceeded);
        }
        match directive {
            "v" => {
                if tokens.len() != 3 || vertices.len() == MAX_VERTICES {
                    return Err(if vertices.len() == MAX_VERTICES {
                        ObjError::LimitExceeded
                    } else {
                        ObjError::InvalidGrammar
                    });
                }
                let mut point = [0.0; 3];
                for (index, token) in tokens.iter().enumerate() {
                    let value = token.parse::<f64>().map_err(|_| ObjError::InvalidGrammar)?;
                    if !value.is_finite() || value.abs() > MAX_COORDINATE {
                        return Err(ObjError::InvalidGrammar);
                    }
                    point[index] = value;
                }
                vertices.push(point);
            }
            "f" => {
                if tokens.len() != 3 || faces.len() == MAX_FACES {
                    return Err(if faces.len() == MAX_FACES {
                        ObjError::LimitExceeded
                    } else {
                        ObjError::InvalidGrammar
                    });
                }
                check_deadline(deadline)?;
                let mut face = [0usize; 3];
                for (index, token) in tokens.iter().enumerate() {
                    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(ObjError::InvalidGrammar);
                    }
                    let one_based = token
                        .parse::<usize>()
                        .map_err(|_| ObjError::InvalidGrammar)?;
                    if one_based == 0 || one_based > vertices.len() {
                        return Err(ObjError::InvalidGrammar);
                    }
                    face[index] = one_based - 1;
                }
                if face[0] == face[1] || face[0] == face[2] || face[1] == face[2] {
                    return Err(ObjError::InvalidGrammar);
                }
                let mut unordered = face;
                unordered.sort_unstable();
                if !unique_faces.insert(unordered) || is_degenerate(face, &vertices) {
                    return Err(ObjError::InvalidGrammar);
                }
                faces.push(face);
            }
            _ => return Err(ObjError::InvalidGrammar),
        }
    }
    check_deadline(deadline)?;
    if vertices.len() < 4 || faces.len() < 4 {
        return Err(ObjError::InvalidGrammar);
    }
    Ok(ObjSummary {
        bytes,
        vertices: vertices.len(),
        faces: faces.len(),
    })
}

pub(super) fn check_deadline(deadline: Instant) -> Result<(), ObjError> {
    if Instant::now() >= deadline {
        Err(ObjError::Deadline)
    } else {
        Ok(())
    }
}

fn is_degenerate(face: [usize; 3], vertices: &[[f64; 3]]) -> bool {
    let a = vertices[face[0]];
    let b = vertices[face[1]];
    let c = vertices[face[2]];
    let ab = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
    let ac = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
    let cross = [
        ab[1] * ac[2] - ab[2] * ac[1],
        ab[2] * ac[0] - ab[0] * ac[2],
        ab[0] * ac[1] - ab[1] * ac[0],
    ];
    cross.iter().all(|component| *component == 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TETRAHEDRON: &[u8] =
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n";

    #[test]
    fn validates_tetrahedron_and_rejects_invalid_face_semantics() {
        let summary = validate_obj(TETRAHEDRON).expect("valid tetrahedron");
        assert_eq!((summary.vertices, summary.faces), (4, 4));
        for invalid in [
            b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 3 2\nf 1 4 3\nf 2 3 4\n".as_slice(),
            b"v 0 0 0\nv 1 0 0\nv 2 0 0\nv 0 0 1\nf 1 2 3\nf 1 2 4\nf 1 4 3\nf 2 3 4\n".as_slice(),
            b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 5\n".as_slice(),
        ] {
            assert!(validate_obj(invalid).is_err());
        }
    }

    #[test]
    fn rejects_unsupported_directives_nonfinite_coordinates_and_index_overflow() {
        for invalid in [
            b"mtllib model.mtl\n".as_slice(),
            b"v NaN 0 0\n".as_slice(),
            b"v 1000001 0 0\n".as_slice(),
            b"f 999999999999999999999999999999999999 2 3\n".as_slice(),
        ] {
            assert!(validate_obj(invalid).is_err());
        }
    }

    #[test]
    fn enforces_byte_line_and_token_limits() {
        assert_eq!(
            validate_obj(std::io::Cursor::new(vec![b' '; MAX_BYTES + 1])),
            Err(ObjError::TooLarge)
        );
        assert_eq!(
            validate_obj(std::io::Cursor::new(vec![b' '; MAX_LINE_BYTES + 1])),
            Err(ObjError::LimitExceeded)
        );
        assert_eq!(
            validate_obj(b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 2 3 4 5 6".as_slice()),
            Err(ObjError::InvalidGrammar)
        );
    }

    #[test]
    fn validation_deadline_is_checked_after_cpu_bound_reader_work() {
        struct CpuBoundReader {
            deadline: Instant,
        }

        impl Read for CpuBoundReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let stop = self.deadline + Duration::from_millis(2);
                let mut value = 0_u64;
                while Instant::now() < stop {
                    value = value.wrapping_add(1);
                    std::hint::black_box(value);
                }
                buffer[..2].copy_from_slice(b"#\n");
                Ok(2)
            }
        }

        let deadline = Instant::now() + Duration::from_millis(1);
        assert_eq!(
            validate_obj_until(CpuBoundReader { deadline }, deadline),
            Err(ObjError::Deadline)
        );
    }

    #[test]
    fn validation_slots_reject_excess_work_without_waiting() {
        let slots = AtomicUsize::new(0);
        let first = ValidationPermit::acquire_from(&slots).expect("first validation slot");
        let second = ValidationPermit::acquire_from(&slots).expect("second validation slot");
        assert_eq!(
            ValidationPermit::acquire_from(&slots).err(),
            Some(ObjError::Capacity)
        );
        drop((first, second));
        assert!(
            validate_obj(
                b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n"
                    .as_slice()
            )
            .is_ok()
        );
    }
}
