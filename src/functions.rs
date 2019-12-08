use crate::eval::Value;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use digest;
use digest::generic_array::typenum::Unsigned;
use digest::{FixedOutput, Input, VariableOutput};
use rand::{CryptoRng, Rng};
use std::borrow::Cow;

#[cfg(feature = "bls")]
use ff::*;
#[cfg(feature = "bls")]
use group::*;
#[cfg(feature = "bls")]
use pairing::{bls12_381, Engine};
#[cfg(feature = "bls")]
use std::{
    convert::{AsMut, AsRef},
    io,
};

#[cfg(feature = "bls")]
fn append_repr_to_bytes<T: PrimeFieldRepr>(bytes: &mut Vec<u8>, repr: T) {
    repr.write_be(bytes)
        .expect("Failed to write repr bytes to vec");
}

#[cfg(feature = "bls")]
pub fn fr_to_bytes(fr: bls12_381::Fr) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_repr_to_bytes(&mut bytes, bls12_381::FrRepr::from(fr));
    bytes
}

#[cfg(feature = "bls")]
fn append_fq2_to_bytes(bytes: &mut Vec<u8>, fq: bls12_381::Fq2) {
    append_repr_to_bytes(bytes, bls12_381::FqRepr::from(fq.c1));
    append_repr_to_bytes(bytes, bls12_381::FqRepr::from(fq.c0));
}

#[cfg(feature = "bls")]
fn append_fq6_to_bytes(bytes: &mut Vec<u8>, fq: bls12_381::Fq6) {
    append_fq2_to_bytes(bytes, fq.c2);
    append_fq2_to_bytes(bytes, fq.c1);
    append_fq2_to_bytes(bytes, fq.c0);
}

#[cfg(feature = "bls")]
pub fn fq12_to_bytes(fq: bls12_381::Fq12) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_fq6_to_bytes(&mut bytes, fq.c1);
    append_fq6_to_bytes(&mut bytes, fq.c0);
    bytes
}

#[cfg(feature = "bls")]
fn read_fq_from_bytes<R: io::Read>(r: R) -> Result<bls12_381::Fq, Cow<'static, str>> {
    let mut repr = bls12_381::FqRepr::default();
    repr.read_be(r)
        .map_err(|_| "not enough bytes to read scalar")?;
    Ok(bls12_381::Fq::from_repr(repr).map_err(|e| e.to_string())?)
}

#[cfg(feature = "bls")]
fn read_fq2_from_bytes<R: io::Read>(mut r: R) -> Result<bls12_381::Fq2, Cow<'static, str>> {
    let c1 = read_fq_from_bytes(&mut r)?;
    let c0 = read_fq_from_bytes(&mut r)?;
    Ok(bls12_381::Fq2 { c0, c1 })
}

#[cfg(feature = "bls")]
fn read_fq6_from_bytes<R: io::Read>(mut r: R) -> Result<bls12_381::Fq6, Cow<'static, str>> {
    let c2 = read_fq2_from_bytes(&mut r)?;
    let c1 = read_fq2_from_bytes(&mut r)?;
    let c0 = read_fq2_from_bytes(&mut r)?;
    Ok(bls12_381::Fq6 { c0, c1, c2 })
}

#[cfg(feature = "bls")]
fn read_fq12_from_bytes<R: io::Read>(mut r: R) -> Result<bls12_381::Fq12, Cow<'static, str>> {
    let c1 = read_fq6_from_bytes(&mut r)?;
    let c0 = read_fq6_from_bytes(&mut r)?;
    Ok(bls12_381::Fq12 { c0, c1 })
}

pub fn num_to_scalar(num: i64) -> Scalar {
    let positive = num.abs();
    let mut scalar = Scalar::from(positive as u64);
    if num.is_negative() {
        scalar = -scalar;
    }
    scalar
}

#[cfg(feature = "bls")]
pub fn num_to_bls_scalar(num: i64) -> bls12_381::Fr {
    let positive = num.abs();
    let repr = bls12_381::FrRepr::from(positive as u64);
    let mut scalar = bls12_381::Fr::from_repr(repr)
        .expect("64 bit number not in prime field (shouldn't happen)");
    if num.is_negative() {
        scalar.negate();
    }
    scalar
}

fn with_bytes<R, F: FnOnce(Cow<'_, [u8]>) -> R>(
    value: Value,
    f: F,
) -> Result<R, Cow<'static, str>> {
    match value {
        Value::Scalar(s) => Ok(f(Cow::Borrowed(s.as_bytes()))),
        Value::Point(p) => Ok(f(Cow::Borrowed(p.compress().as_bytes()))),
        Value::Bytes(b) => Ok(f(Cow::Owned(b))),
        #[cfg(feature = "bls")]
        Value::Fr(s) => Ok(f(Cow::Owned(fr_to_bytes(s)))),
        #[cfg(feature = "bls")]
        Value::Fq12(s) => Ok(f(Cow::Owned(fq12_to_bytes(s)))),
        #[cfg(feature = "bls")]
        Value::G1(p) => Ok(f(Cow::Borrowed(
            &p.clone().into_affine().into_compressed().as_ref(),
        ))),
        #[cfg(feature = "bls")]
        Value::G2(p) => Ok(f(Cow::Borrowed(
            &p.clone().into_affine().into_compressed().as_ref(),
        ))),
        Value::String(b) => Ok(f(Cow::Owned(b.into_bytes()))),
        arg => Err(format!("tried to convert {} into bytes", arg.type_name()).into()),
    }
}

pub fn bytes(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("bytes takes 1 argument, but {} provided", args.len()).into());
    }
    with_bytes(args.pop().unwrap(), |x| Value::Bytes(x.into_owned()))
}

pub fn scalar(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("scalar takes 1 argument, but {} provided", args.len()).into());
    }
    match args.pop().unwrap() {
        Value::Scalar(s) => Ok(Value::Scalar(s)),
        Value::Number(num) => Ok(Value::Scalar(num_to_scalar(num))),
        Value::Bytes(b) => {
            if b.len() == 32 {
                let mut slice = [0u8; 32];
                slice.copy_from_slice(&b);
                Ok(Value::Scalar(Scalar::from_bytes_mod_order(slice)))
            } else if b.len() == 64 {
                let mut slice = [0u8; 64];
                slice.copy_from_slice(&b);
                Ok(Value::Scalar(Scalar::from_bytes_mod_order_wide(&slice)))
            } else {
                return Err(format!(
                    "tried to convert {} bytes into a scalar (needs 32 or 64 bytes)",
                    b.len(),
                )
                .into());
            }
        }
        arg => Err(format!("tried to convert {} into a scalar", arg.type_name()).into()),
    }
}

pub fn point(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("point takes 1 argument, but {} provided", args.len()).into());
    }
    match args.pop().unwrap() {
        Value::Scalar(s) => Ok(Value::Point(&s * &ED25519_BASEPOINT_TABLE)),
        Value::Point(p) => Ok(Value::Point(p)),
        Value::Bytes(b) => {
            if b.len() != 32 {
                return Err(format!(
                    "tried to convert {} bytes into a curve point (needs 32 bytes)",
                    b.len()
                )
                .into());
            }
            let mut slice = [0u8; 32];
            slice.copy_from_slice(&b);
            let point = CompressedEdwardsY(slice)
                .decompress()
                .ok_or("failed to decompress curve point bytes as compressed edwards y encoding")?;
            Ok(Value::Point(point))
        }
        arg => Err(format!("tried to convert {} into a curve point", arg.type_name()).into()),
    }
}

pub fn val_to_len(val: Value, func_name: &str) -> Result<usize, Cow<'static, str>> {
    match val {
        Value::Number(num) => {
            if num.is_positive() && num <= (u32::max_value() as i64) {
                Ok(num as usize)
            } else {
                Err(format!("bad length {} passed to {}", num, func_name).into())
            }
        }
        val => return Err(format!("{} passed as length to {}", val.type_name(), func_name).into()),
    }
}

pub fn slice(
    val: Value,
    start: Option<usize>,
    end: Option<usize>,
) -> Result<Value, Cow<'static, str>> {
    match val {
        Value::Bytes(mut b) => {
            let start = start.unwrap_or(0);
            let end = end.unwrap_or(b.len());
            if start > b.len() {
                return Err(format!(
                    "attempted to slice bytes with length {} with a start index of {}",
                    b.len(),
                    start,
                )
                .into());
            }
            if end > b.len() {
                return Err(format!(
                    "attempted to slice bytes with length {} with an end index of {}",
                    b.len(),
                    end,
                )
                .into());
            }
            if start == 0 {
                b.truncate(end);
                Ok(Value::Bytes(b))
            } else {
                Ok(Value::Bytes(b[start..end].to_vec()))
            }
        }
        arg => return Err(format!("attempted to slice {}", arg.type_name()).into()),
    }
}

pub fn index(val: Value, idx: usize) -> Result<Value, Cow<'static, str>> {
    match val {
        Value::Bytes(b) => {
            if idx >= b.len() {
                return Err(format!(
                    "attempted to index bytes with length {} with an index of {}",
                    b.len(),
                    idx,
                )
                .into());
            }
            Ok(Value::Number(b[idx] as i64))
        }
        Value::Array(a) => {
            if idx >= a.len() {
                return Err(format!(
                    "attempted to index bytes with length {} with an index of {}",
                    a.len(),
                    idx,
                )
                .into());
            }
            Ok(a[idx].clone())
        }
        arg => return Err(format!("attempted to slice {}", arg.type_name()).into()),
    }
}

pub fn rand<R: CryptoRng + Rng>(
    mut args: Vec<Value>,
    rng: &mut R,
) -> Result<Value, Cow<'static, str>> {
    if args.len() > 1 {
        return Err(format!(
            "rand takes a maximum of 1 argument, but {} were provided",
            args.len(),
        )
        .into());
    }
    let len = match args.pop() {
        Some(Value::String(s)) => match s.as_str() {
            "scalar" => return Ok(Value::Scalar(Scalar::random(rng))),
            "point" => {
                return Ok(Value::Point(
                    &Scalar::random(rng) * &ED25519_BASEPOINT_TABLE,
                ))
            }
            #[cfg(feature = "bls")]
            "bls_scalar" => return Ok(Value::Fr(bls12_381::Fr::random(rng))),
            #[cfg(feature = "bls")]
            "pairing" => return Ok(Value::Fq12(bls12_381::Fq12::random(rng))),
            #[cfg(feature = "bls")]
            "g1" => return Ok(Value::G1(bls12_381::G1::random(rng))),
            #[cfg(feature = "bls")]
            "g2" => return Ok(Value::G2(bls12_381::G2::random(rng))),
            _ => return Err("cannot generate that type randomly".into()),
        },
        Some(v) => val_to_len(v, "rand")?,
        None => 32,
    };
    let mut bytes = vec![0u8; len];
    rng.fill(bytes.as_mut_slice());
    Ok(Value::Bytes(bytes))
}

pub fn equal_inner(a: Value, b: Value) -> Result<bool, Cow<'static, str>> {
    match (a, b) {
        (Value::Bytes(a), Value::Bytes(b)) => Ok(a == b),
        (Value::Bytes(a), Value::Scalar(b)) => Ok(&a == b.as_bytes()),
        (Value::Scalar(a), Value::Bytes(b)) => Ok(a.as_bytes() == b.as_slice()),
        (Value::Bytes(a), Value::Point(b)) => Ok(&a == b.compress().as_bytes()),
        (Value::Point(a), Value::Bytes(b)) => Ok(a.compress().as_bytes() == b.as_slice()),
        (Value::Scalar(a), Value::Scalar(b)) => Ok(a == b),
        (Value::Point(a), Value::Point(b)) => Ok(a == b),
        (Value::Number(a), Value::Number(b)) => Ok(a == b),
        (Value::Number(a), Value::Scalar(b)) => Ok(num_to_scalar(a) == b),
        (Value::Scalar(a), Value::Number(b)) => Ok(a == num_to_scalar(b)),
        (Value::String(a), Value::String(b)) => Ok(a == b),
        (Value::Bool(a), Value::Bool(b)) => Ok(a == b),
        #[cfg(feature = "bls")]
        (Value::G1(a), Value::G1(b)) => Ok(a == b),
        #[cfg(feature = "bls")]
        (Value::G2(a), Value::G2(b)) => Ok(a == b),
        #[cfg(feature = "bls")]
        (Value::Fr(a), Value::Fr(b)) => Ok(a == b),
        #[cfg(feature = "bls")]
        (Value::Fq12(a), Value::Fq12(b)) => Ok(a == b),
        #[cfg(feature = "bls")]
        (Value::Number(a), Value::Fr(b)) => Ok(num_to_bls_scalar(a) == b),
        #[cfg(feature = "bls")]
        (Value::Fr(a), Value::Number(b)) => Ok(a == num_to_bls_scalar(b)),
        (a, b) => Err(format!(
            "attempted to check equality of {} and {}",
            a.type_name(),
            b.type_name(),
        )
        .into()),
    }
}

pub fn equal(a: Value, b: Value) -> Result<Value, Cow<'static, str>> {
    equal_inner(a, b).map(Value::Bool)
}

pub fn not_equal(a: Value, b: Value) -> Result<Value, Cow<'static, str>> {
    equal_inner(a, b).map(|b| Value::Bool(!b))
}

#[allow(dead_code)]
fn var_hash<H: VariableOutput + Input>(
    mut args: Vec<Value>,
    name: &str,
) -> Result<Value, Cow<'static, str>> {
    if args.len() < 1 || args.len() > 2 {
        return Err(format!(
            "{} takes 1 or 2 arguments, but {} were provided",
            name,
            args.len(),
        )
        .into());
    }
    let mut out_len = 64;
    if args.len() > 1 {
        out_len = val_to_len(args.pop().unwrap(), name)?;
    }
    let mut hasher = H::new(out_len)
        .map_err(|_| format!("{} cannot produce output length {}", name, out_len))?;
    with_bytes(args.pop().unwrap(), |bytes| hasher.input(bytes))?;
    Ok(Value::Bytes(hasher.vec_result()))
}

#[allow(dead_code)]
fn fixed_hash<H: FixedOutput + Default + Input>(
    mut args: Vec<Value>,
    name: &str,
) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!(
            "{} takes 1 argument, but {} were provided",
            name,
            args.len(),
        )
        .into());
    }
    let mut hasher = H::default();
    with_bytes(args.pop().unwrap(), |bytes| hasher.input(bytes))?;
    Ok(Value::Bytes(hasher.fixed_result().to_vec()))
}

#[cfg(feature = "blake2")]
pub fn blake2b(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use blake2::VarBlake2b;
    var_hash::<VarBlake2b>(args, "blake2b")
}

#[cfg(not(feature = "blake2"))]
pub fn blake2b(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("blake2 support not enabled in features".into())
}

#[cfg(feature = "sha2")]
pub fn sha256(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use sha2::Sha256;
    fixed_hash::<Sha256>(args, "sha256")
}

#[cfg(not(feature = "sha2"))]
pub fn sha256(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("sha2 support not enabled in features".into())
}

#[cfg(feature = "sha2")]
pub fn sha512(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use sha2::Sha512;
    fixed_hash::<Sha512>(args, "sha256")
}

#[cfg(not(feature = "sha2"))]
pub fn sha512(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("sha2 support not enabled in features".into())
}

#[cfg(feature = "sha3")]
pub fn keccak256(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use sha3::Keccak256;
    fixed_hash::<Keccak256>(args, "keccak256")
}

#[cfg(not(feature = "sha3"))]
pub fn keccak256(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("sha3 support not enabled in features".into())
}

#[cfg(feature = "sha3")]
pub fn sha3_256(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use sha3::Sha3_256;
    fixed_hash::<Sha3_256>(args, "sha3_256")
}

#[cfg(not(feature = "sha3"))]
pub fn sha3_256(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("sha3 support not enabled in features".into())
}

#[cfg(feature = "sha3")]
pub fn sha3_512(args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    use sha3::Sha3_512;
    fixed_hash::<Sha3_512>(args, "sha3_512")
}

#[cfg(not(feature = "sha3"))]
pub fn sha3_512(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("sha3 support not enabled in features".into())
}

#[cfg(feature = "nano")]
pub fn nano_account_encode(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!(
            "nano_account_encode takes 1 argument, but {} provided",
            args.len()
        )
        .into());
    }
    use nanocurrency_types::Account;
    let bytes = match args.pop().unwrap() {
        Value::Bytes(b) => b,
        Value::Point(p) => p.compress().to_bytes().to_vec(),
        arg => {
            return Err(format!("attempted to encode {} as a nano account", arg.type_name()).into())
        }
    };
    if bytes.len() != 32 {
        return Err(format!(
            "attempted to encode {} bytes as a nano account",
            bytes.len()
        )
        .into());
    }
    let mut slice = [0u8; 32];
    slice.copy_from_slice(&bytes);
    Ok(Value::String(Account(slice).to_string()))
}

#[cfg(not(feature = "nano"))]
pub fn nano_account_encode(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("nano support not enabled in features".into())
}

#[cfg(feature = "nano")]
pub fn nano_account_decode(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!(
            "nano_account_decode takes 1 argument, but {} provided",
            args.len()
        )
        .into());
    }
    use nanocurrency_types::Account;
    let s = match args.pop().unwrap() {
        Value::String(s) => s,
        arg => {
            return Err(
                format!("attempted to decode {} as a nano account", arg.type_name()).into(),
            );
        }
    };
    let account: Account = s
        .parse()
        .map_err(|e| format!("failed to decode account: {:?}", e))?;
    let point = CompressedEdwardsY(account.0)
        .decompress()
        .ok_or("nano account bytes didn't represent valid curve point")?;
    Ok(Value::Point(point))
}

#[cfg(not(feature = "nano"))]
pub fn nano_account_decode(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("nano support not enabled in features".into())
}

#[cfg(feature = "nano")]
pub fn nano_block_hash(
    block: ::nanocurrency_types::BlockInner,
) -> Result<Value, Cow<'static, str>> {
    Ok(Value::Bytes(block.get_hash().0.to_vec()))
}

#[cfg(not(feature = "nano"))]
pub fn nano_block_hash<T>(_: T) -> Result<Value, Cow<'static, str>> {
    Err("nano support not enabled in features".into())
}

#[allow(dead_code)]
#[derive(Default)]
struct UnimplementedHasher;

impl Input for UnimplementedHasher {
    fn input<B: AsRef<[u8]>>(&mut self, _: B) {
        unimplemented!()
    }
}

impl FixedOutput for UnimplementedHasher {
    type OutputSize = digest::generic_array::typenum::consts::U0;
    fn fixed_result(self) -> digest::generic_array::GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
}

impl VariableOutput for UnimplementedHasher {
    fn new(_: usize) -> Result<Self, digest::InvalidOutputSize> {
        unimplemented!()
    }
    fn output_size(&self) -> usize {
        unimplemented!()
    }
    fn variable_result<F: FnOnce(&[u8])>(self, _: F) {
        unimplemented!()
    }
}

#[cfg(feature = "blake2")]
type Blake2b = ::blake2::VarBlake2b;
#[cfg(not(feature = "blake2"))]
type Blake2b = UnimplementedHasher;

#[cfg(feature = "sha2")]
type Sha256 = ::sha2::Sha256;
#[cfg(not(feature = "sha2"))]
type Sha256 = UnimplementedHasher;

#[cfg(feature = "sha2")]
type Sha512 = ::sha2::Sha512;
#[cfg(not(feature = "sha2"))]
type Sha512 = UnimplementedHasher;

fn fixed_hash_with_size<
    H: Default + FixedOutput + Input,
    B: AsRef<[u8]>,
    I: IntoIterator<Item = B>,
>(
    input: I,
    len: usize,
) -> Option<Vec<u8>> {
    if H::OutputSize::to_usize() != len {
        return None;
    }
    let mut hasher = H::default();
    for bytes in input {
        hasher.input(bytes);
    }
    Some(hasher.fixed_result().to_vec())
}

fn hash_to_size<B: AsRef<[u8]>, I: IntoIterator<Item = B>>(
    mut name: &str,
    input: I,
    len: usize,
) -> Result<Vec<u8>, Cow<'static, str>> {
    let bad_len_msg = move || format!("{} cannot produce output of length {}", name, len);
    if name == "sha2" {
        if len == 32 {
            name = "sha256";
        } else if len == 64 {
            name = "sha512";
        } else {
            return Err(bad_len_msg().into());
        }
    }
    match name {
        "blake2b" => {
            let mut hasher = Blake2b::new(len).map_err(|_| bad_len_msg())?;
            for bytes in input {
                hasher.input(bytes);
            }
            Ok(hasher.vec_result())
        }
        "sha256" => Ok(fixed_hash_with_size::<Sha256, _, _>(input, len).ok_or_else(bad_len_msg)?),
        "sha512" => Ok(fixed_hash_with_size::<Sha512, _, _>(input, len).ok_or_else(bad_len_msg)?),
        _ => Err(format!("unknown hasher {:?}", name).into()),
    }
}

fn ed25519_extsk_inner(
    hasher: &str,
    bytes: &[u8],
    name: &str,
) -> Result<Vec<u8>, Cow<'static, str>> {
    if bytes.len() != 32 {
        return Err(format!(
            "{} passed to {} as secret key (needs 32 bytes)",
            bytes.len(),
            name
        )
        .into());
    }
    hash_to_size(hasher, &[bytes], 64).map(|mut hash| {
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;
        hash
    })
}

pub fn ed25519_extsk(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() < 1 || args.len() > 2 {
        return Err(format!(
            "ed25519_skey takes 1 or 2 arguments, but {} were provided",
            args.len(),
        )
        .into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 2 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to ed25519_skey as hasher", val).into()),
        }
    }
    match args.pop().unwrap() {
        Value::Bytes(bytes) => {
            ed25519_extsk_inner(&hasher, &bytes, "ed25519_extsk").map(Value::Bytes)
        }
        val => Err(format!("{} passed to ed25519_skey as skey", val).into()),
    }
}

pub fn ed25519_pub(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() < 1 || args.len() > 2 {
        return Err(format!(
            "ed25519_pub takes 1 or 2 arguments, but {} were provided",
            args.len(),
        )
        .into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 2 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to ed25519_skey as hasher", val).into()),
        }
    }
    match args.pop().unwrap() {
        Value::Bytes(bytes) => ed25519_extsk_inner(&hasher, &bytes, "ed25519_pub").map(|bytes| {
            let mut slice = [0u8; 32];
            slice.copy_from_slice(&bytes[..32]);
            Value::Point(&Scalar::from_bytes_mod_order(slice) * &ED25519_BASEPOINT_TABLE)
        }),
        val => Err(format!("{} passed to ed25519_skey as skey", val).into()),
    }
}

fn ed25519_sign_inner<R: CryptoRng + Rng>(
    mut args: Vec<Value>,
    extended: bool,
    rng: &mut R,
    name: &str,
) -> Result<Value, Cow<'static, str>> {
    if args.len() < 2 || args.len() > 3 {
        return Err(format!(
            "{} takes 2 or 3 arguments, but {} were provided",
            name,
            args.len(),
        )
        .into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 3 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to {} as hasher", val, name).into()),
        }
    }
    let message = with_bytes(args.pop().unwrap(), |b| b.into_owned())?;
    let extsk = if extended {
        let arg = args.pop().unwrap();
        let mut extsk = match arg {
            Value::Bytes(bytes) => {
                if bytes.len() != 32 && bytes.len() != 64 {
                    return Err(format!(
                        "{} bytes passed to {} as extended secret key (expected 32 or 64 bytes)",
                        bytes.len(),
                        name,
                    )
                    .into());
                }
                bytes
            }
            Value::Scalar(scalar) => scalar.to_bytes().to_vec(),
            val => return Err(format!("{} passed to {} as extended secret key", val, name).into()),
        };
        if extsk.len() < 64 {
            extsk.resize_with(64, Default::default);
            rng.fill(&mut extsk[32..]);
        }
        extsk
    } else {
        match args.pop().unwrap() {
            Value::Bytes(bytes) => ed25519_extsk_inner(&hasher, &bytes, name)?,
            val => return Err(format!("{} passed to {} as secret key", val, name).into()),
        }
    };
    let mut skey_scalar_bytes = [0u8; 32];
    skey_scalar_bytes.copy_from_slice(&extsk[..32]);
    let skey_scalar = Scalar::from_bytes_mod_order(skey_scalar_bytes);
    let pkey_point = &skey_scalar * &ED25519_BASEPOINT_TABLE;
    let pkey_point_bytes = pkey_point.compress().to_bytes();
    let mut r_bytes = [0u8; 64];
    r_bytes.copy_from_slice(&hash_to_size(&hasher, &[&extsk[32..], &message], 64)?);
    let r_scalar = Scalar::from_bytes_mod_order_wide(&r_bytes);
    let r_point = &r_scalar * &ED25519_BASEPOINT_TABLE;
    let r_point_bytes = r_point.compress().to_bytes();
    let mut hram_bytes = [0u8; 64];
    hram_bytes.copy_from_slice(&hash_to_size(
        &hasher,
        &[&r_point_bytes as &[u8], &pkey_point_bytes, &message],
        64,
    )?);
    let hram_scalar = Scalar::from_bytes_mod_order_wide(&hram_bytes);
    let s_value = r_scalar + hram_scalar * skey_scalar;
    let mut sig = vec![0u8; 64];
    sig[..32].copy_from_slice(&r_point_bytes);
    sig[32..].copy_from_slice(s_value.as_bytes());
    Ok(Value::Bytes(sig))
}

pub fn ed25519_sign<R: CryptoRng + Rng>(
    args: Vec<Value>,
    rng: &mut R,
) -> Result<Value, Cow<'static, str>> {
    ed25519_sign_inner(args, false, rng, "ed25519_sign")
}

pub fn ed25519_sign_extended<R: CryptoRng + Rng>(
    args: Vec<Value>,
    rng: &mut R,
) -> Result<Value, Cow<'static, str>> {
    ed25519_sign_inner(args, true, rng, "ed25519_sign_extended")
}

pub fn ed25519_verify(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() < 3 || args.len() > 4 {
        return Err(format!(
            "ed25519_verify takes 3 or 4 arguments, but {} were provided",
            args.len(),
        )
        .into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 4 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to ed25519_verify as hasher", val).into()),
        }
    }
    let signature = match args.pop().unwrap() {
        Value::Bytes(bytes) => bytes,
        val => return Err(format!("{} passed to ed25519_verify as signature", val).into()),
    };
    if signature.len() != 64 {
        return Err(format!(
            "{} bytes passed to ed25519_verify as signature (needs 64 bytes)",
            signature.len(),
        )
        .into());
    }
    let message = with_bytes(args.pop().unwrap(), |b| b.into_owned())?;
    let (pkey_bytes, pkey_point): ([u8; 32], _) = match args.pop().unwrap() {
        Value::Bytes(bytes) => {
            if bytes.len() != 32 {
                return Err(format!(
                    "{} bytes passed to ed25519_verify as public key (needs 32 bytes)",
                    bytes.len(),
                )
                .into());
            }
            let mut slice = [0u8; 32];
            slice.copy_from_slice(&bytes);
            let point = CompressedEdwardsY(slice)
                .decompress()
                .ok_or("invalid curve point passed to ed25519_verify as public key")?;
            (slice, point)
        }
        Value::Point(point) => (point.compress().to_bytes(), point),
        val => return Err(format!("{} passed to ed25519_verify as public key", val).into()),
    };
    let mut s_value_bytes = [0u8; 32];
    s_value_bytes.copy_from_slice(&signature[32..]);
    let s_value_scalar = Scalar::from_bytes_mod_order(s_value_bytes);
    let mut r_value_bytes = [0u8; 32];
    r_value_bytes.copy_from_slice(&signature[..32]);
    let r_value_point = match CompressedEdwardsY(r_value_bytes).decompress() {
        Some(p) => p,
        None => return Ok(Value::Bool(false)),
    };
    let mut hram_bytes = [0u8; 64];
    hram_bytes.copy_from_slice(&hash_to_size(
        &hasher,
        &[&r_value_bytes as &[u8], &pkey_bytes, &message],
        64,
    )?);
    let hram_scalar = Scalar::from_bytes_mod_order_wide(&hram_bytes);
    Ok(Value::Bool(
        &s_value_scalar * &ED25519_BASEPOINT_TABLE == r_value_point + hram_scalar * pkey_point,
    ))
}

#[cfg(feature = "bls")]
pub fn bls_scalar(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("scalar takes 1 argument, but {} provided", args.len()).into());
    }
    match args.pop().unwrap() {
        Value::Fr(s) => Ok(Value::Fr(s)),
        Value::Number(num) => Ok(Value::Fr(num_to_bls_scalar(num))),
        Value::Bytes(b) => {
            let mut repr = bls12_381::FrRepr::default();
            repr.read_be(io::Cursor::new(b))
                .map_err(|e| e.to_string())?;
            let scalar = bls12_381::Fr::from_repr(repr).map_err(|_| "bytes not in prime field")?;
            Ok(Value::Fr(scalar))
        }
        arg => Err(format!("tried to convert {} into a BLS scalar", arg.type_name()).into()),
    }
}

#[cfg(not(feature = "bls"))]
pub fn bls_scalar(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("bls support not enabled in features".into())
}

#[cfg(feature = "bls")]
pub fn g1(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("g1 takes 1 argument, but {} provided", args.len()).into());
    }
    match args.pop().unwrap() {
        Value::G1(p) => Ok(Value::G1(p)),
        Value::Fr(s) => Ok(Value::G1(bls12_381::G1Affine::one().mul(s))),
        Value::Bytes(b) => {
            let mut compressed = bls12_381::G1Compressed::empty();
            let compressed_bytes = compressed.as_mut();
            if compressed_bytes.len() != b.len() {
                return Err(format!(
                    "tried to convert {} bytes into a BLS G1 point (needs {} bytes)",
                    compressed_bytes.len(), // 48
                    b.len(),
                )
                .into());
            }
            compressed_bytes.copy_from_slice(&b);
            let affine = compressed.into_affine().map_err(|e| e.to_string())?;
            Ok(Value::G1(affine.into_projective()))
        }
        arg => Err(format!("tried to convert {} into a BLS G1 point", arg.type_name()).into()),
    }
}

#[cfg(not(feature = "bls"))]
pub fn g1(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("bls support not enabled in features".into())
}

#[cfg(feature = "bls")]
pub fn g2(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!("g2 takes 1 argument, but {} provided", args.len()).into());
    }
    match args.pop().unwrap() {
        Value::G2(p) => Ok(Value::G2(p)),
        Value::Fr(s) => Ok(Value::G2(bls12_381::G2Affine::one().mul(s))),
        Value::Bytes(b) => {
            let mut compressed = bls12_381::G2Compressed::empty();
            let compressed_bytes = compressed.as_mut();
            if compressed_bytes.len() != b.len() {
                return Err(format!(
                    "tried to convert {} bytes into a BLS G2 point (needs {} bytes)",
                    compressed_bytes.len(), // 96
                    b.len(),
                )
                .into());
            }
            compressed_bytes.copy_from_slice(&b);
            let affine = compressed.into_affine().map_err(|e| e.to_string())?;
            Ok(Value::G2(affine.into_projective()))
        }
        arg => Err(format!("tried to convert {} into a BLS G2 point", arg.type_name()).into()),
    }
}

#[cfg(not(feature = "bls"))]
pub fn g2(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("bls support not enabled in features".into())
}

#[cfg(feature = "bls")]
pub fn pairing(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() == 1 {
        match args.pop().unwrap() {
            Value::Fq12(s) => Ok(Value::Fq12(s)),
            Value::Bytes(b) => Ok(Value::Fq12(read_fq12_from_bytes(io::Cursor::new(b))?)),
            arg => Err(format!("tried to convert {} into a BLS pairing", arg.type_name()).into()),
        }
    } else if args.len() == 2 {
        let a = args.pop().unwrap();
        let b = args.pop().unwrap();
        match (a, b) {
            (Value::G1(g1), Value::G2(g2)) | (Value::G2(g2), Value::G1(g1)) => {
                Ok(Value::Fq12(bls12_381::Bls12::pairing(g1, g2)))
            }
            (a, b) => Err(format!(
                concat!(
                    "cannot find pairing between {} and {}",
                    " (expected a BLS G1 point and a BLS G2 point)",
                ),
                a.type_name(),
                b.type_name(),
            )
            .into()),
        }
    } else {
        return Err(format!("g2 takes 1 or 2 arguments, but {} provided", args.len()).into());
    }
}

#[cfg(not(feature = "bls"))]
pub fn pairing(_: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    Err("bls support not enabled in features".into())
}
