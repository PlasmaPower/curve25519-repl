use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use digest;
use digest::generic_array::typenum::Unsigned;
use digest::{FixedOutput, Input, VariableOutput};
use eval::Value;
use rand::{CryptoRng, Rng};
use std::borrow::Cow;

pub fn num_to_scalar(num: i64) -> Scalar {
    let positive = if num.is_negative() { -num } else { num };
    let mut scalar = Scalar::from(positive as u64);
    if num.is_negative() {
        scalar = -scalar;
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
                    b.len()
                ).into());
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
        Value::Number(n) => Ok(Value::Point(&num_to_scalar(n) * &ED25519_BASEPOINT_TABLE)),
        Value::Scalar(s) => Ok(Value::Point(&s * &ED25519_BASEPOINT_TABLE)),
        Value::Point(p) => Ok(Value::Point(p)),
        Value::Bytes(b) => {
            if b.len() != 32 {
                return Err(format!(
                    "tried to convert {} bytes into a curve point (needs 32 bytes)",
                    b.len()
                ).into());
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
                ).into());
            }
            if end > b.len() {
                return Err(format!(
                    "attempted to slice bytes with length {} with an end index of {}",
                    b.len(),
                    end,
                ).into());
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

pub fn rand<R: CryptoRng + Rng>(
    mut args: Vec<Value>,
    rng: &mut R,
) -> Result<Value, Cow<'static, str>> {
    if args.len() > 1 {
        return Err(format!(
            "rand takes a maximum of 1 argument, but {} were provided",
            args.len(),
        ).into());
    }
    let len = args
        .pop()
        .map(|v| val_to_len(v, "rand"))
        .unwrap_or(Ok(32))?;
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
        (a, b) => Err(format!(
            "attempted to check equality of {} and {}",
            a.type_name(),
            b.type_name(),
        ).into()),
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
        ).into());
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
        ).into());
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

#[cfg(feature = "nano")]
pub fn nano_account_encode(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() != 1 {
        return Err(format!(
            "nano_account_encode takes 1 argument, but {} provided",
            args.len()
        ).into());
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
        ).into());
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
        ).into());
    }
    use nanocurrency_types::Account;
    let s = match args.pop().unwrap() {
        Value::String(s) => s,
        arg => {
            return Err(format!("attempted to decode {} as a nano account", arg.type_name()).into());
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
        ).into());
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
        ).into());
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
        ).into());
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

pub fn ed25519_sign(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() < 2 || args.len() > 3 {
        return Err(format!(
            "ed25519_sign takes 2 or 3 arguments, but {} were provided",
            args.len(),
        ).into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 3 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to ed25519_sign as hasher", val).into()),
        }
    }
    let message = match args.pop().unwrap() {
        Value::Bytes(bytes) => bytes,
        val => return Err(format!("{} passed to ed25519_sign as message", val).into()),
    };
    let extsk = match args.pop().unwrap() {
        Value::Bytes(bytes) => ed25519_extsk_inner(&hasher, &bytes, "ed25519_sign")?,
        val => return Err(format!("{} passed to ed25519_sign as secret key", val).into()),
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

pub fn ed25519_validate(mut args: Vec<Value>) -> Result<Value, Cow<'static, str>> {
    if args.len() < 3 || args.len() > 4 {
        return Err(format!(
            "ed25519_validate takes 3 or 4 arguments, but {} were provided",
            args.len(),
        ).into());
    }
    let mut hasher = Cow::Borrowed("sha2");
    if args.len() == 4 {
        match args.pop().unwrap() {
            Value::String(s) => hasher = s.into(),
            val => return Err(format!("{} passed to ed25519_validate as hasher", val).into()),
        }
    }
    let signature = match args.pop().unwrap() {
        Value::Bytes(bytes) => bytes,
        val => return Err(format!("{} passed to ed25519_validate as signature", val).into()),
    };
    if signature.len() != 64 {
        return Err(format!(
            "{} bytes passed to ed25519_validate as signature (needs 64 bytes)",
            signature.len(),
        ).into());
    }
    let message = match args.pop().unwrap() {
        Value::Bytes(bytes) => bytes,
        val => return Err(format!("{} passed to ed25519_validate as message", val).into()),
    };
    let (pkey_bytes, pkey_point) = match args.pop().unwrap() {
        Value::Bytes(bytes) => {
            if bytes.len() != 32 {
                return Err(format!(
                    "{} bytes passed to ed25519_validate as public key (needs 32 bytes)",
                    bytes.len(),
                ).into());
            }
            let mut slice = [0u8; 32];
            slice.copy_from_slice(&bytes);
            let point = CompressedEdwardsY(slice)
                .decompress()
                .ok_or("invalid curve point passed to ed25519_validate as public key")?;
            (slice, point)
        }
        Value::Point(point) => (point.compress().to_bytes(), point),
        val => return Err(format!("{} passed to ed25519_validate as public key", val).into()),
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
