use crate::functions;
use crate::parser::Expr;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hex;
use rand::rngs::OsRng;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

#[cfg(feature = "bls")]
use ff::*;
#[cfg(feature = "bls")]
use group::*;
#[cfg(feature = "bls")]
use pairing::bls12_381;

#[derive(Debug, Clone)]
pub enum Value {
    Bytes(Vec<u8>),
    Number(i64),
    String(String),
    Bool(bool),
    Scalar(Scalar),
    Point(EdwardsPoint),
    Array(Vec<Value>),
    #[cfg(feature = "bls")]
    G1(bls12_381::G1),
    #[cfg(feature = "bls")]
    G2(bls12_381::G2),
    #[cfg(feature = "bls")]
    Fr(bls12_381::Fr),
    #[cfg(feature = "bls")]
    Fq12(bls12_381::Fq12),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match *self {
            Value::Bytes(_) => "bytes",
            Value::Number(_) => "a number",
            Value::String(_) => "a string",
            Value::Bool(_) => "a boolean",
            Value::Scalar(_) => "a scalar",
            Value::Point(_) => "a curve point",
            Value::Array(_) => "an array",
            #[cfg(feature = "bls")]
            Value::G1(_) => "a BLS G1 point",
            #[cfg(feature = "bls")]
            Value::G2(_) => "a BLS G2 point",
            #[cfg(feature = "bls")]
            Value::Fr(_) => "a BLS scalar",
            #[cfg(feature = "bls")]
            Value::Fq12(_) => "a BLS pairing",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Bytes(ref bytes) => write!(f, "0x{}", hex::encode(bytes)),
            Value::Number(ref number) => write!(f, "{}", number),
            Value::String(ref s) => write!(f, "{:?}", s),
            Value::Bool(ref b) => write!(f, "{}", b),
            Value::Scalar(ref scalar) => write!(f, "scalar(0x{})", hex::encode(scalar.as_bytes())),
            Value::Point(ref point) => {
                write!(f, "point(0x{})", hex::encode(point.compress().as_bytes()))
            }
            Value::Array(ref arr) => {
                write!(f, "[")?;
                for (i, val) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            #[cfg(feature = "bls")]
            Value::G1(ref point) => write!(
                f,
                "g1(0x{})",
                hex::encode(point.into_affine().into_compressed()),
            ),
            #[cfg(feature = "bls")]
            Value::G2(ref point) => write!(
                f,
                "g2(0x{})",
                hex::encode(point.into_affine().into_compressed()),
            ),
            #[cfg(feature = "bls")]
            Value::Fr(ref scalar) => write!(
                f,
                "bls_scalar(0x{})",
                hex::encode(functions::fr_to_bytes(scalar.clone())),
            ),
            #[cfg(feature = "bls")]
            Value::Fq12(ref pairing) => write!(
                f,
                "pairing(0x{})",
                hex::encode(functions::fq12_to_bytes(pairing.clone())),
            ),
        }
    }
}

impl Add for Value {
    type Output = Result<Value, Cow<'static, str>>;

    fn add(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(a.checked_add(b).ok_or_else(|| {
                    format!("overflowed adding {} and {}", a, b)
                })?))
            }
            (Value::Scalar(a), Value::Scalar(b)) => Ok(Value::Scalar(a + b)),
            (Value::Point(a), Value::Point(b)) => Ok(Value::Point(a + b)),
            (Value::String(a), Value::String(b)) => Ok(Value::String(a + &b)),
            (Value::Bytes(mut a), Value::Bytes(b)) => {
                a.extend(b);
                Ok(Value::Bytes(a))
            }
            #[cfg(feature = "bls")]
            (Value::Fr(mut a), Value::Fr(b)) => {
                a.add_assign(&b);
                Ok(Value::Fr(a))
            }
            #[cfg(feature = "bls")]
            (Value::Fq12(mut a), Value::Fq12(b)) => {
                a.add_assign(&b);
                Ok(Value::Fq12(a))
            }
            #[cfg(feature = "bls")]
            (Value::G1(mut a), Value::G1(b)) => {
                a.add_assign(&b);
                Ok(Value::G1(a))
            }
            #[cfg(feature = "bls")]
            (Value::G2(mut a), Value::G2(b)) => {
                a.add_assign(&b);
                Ok(Value::G2(a))
            }
            (a, b) => {
                Err(format!("attempted to add {} and {}", a.type_name(), b.type_name()).into())
            }
        }
    }
}

impl Sub for Value {
    type Output = Result<Value, Cow<'static, str>>;

    fn sub(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(a.checked_sub(b).ok_or_else(|| {
                    format!("overflowed subtracting {} from {}", b, a)
                })?))
            }
            (Value::Scalar(a), Value::Scalar(b)) => Ok(Value::Scalar(a - b)),
            (Value::Point(a), Value::Point(b)) => Ok(Value::Point(a - b)),
            #[cfg(feature = "bls")]
            (Value::Fr(mut a), Value::Fr(b)) => {
                a.sub_assign(&b);
                Ok(Value::Fr(a))
            }
            #[cfg(feature = "bls")]
            (Value::Fq12(mut a), Value::Fq12(b)) => {
                a.sub_assign(&b);
                Ok(Value::Fq12(a))
            }
            #[cfg(feature = "bls")]
            (Value::G1(mut a), Value::G1(b)) => {
                a.sub_assign(&b);
                Ok(Value::G1(a))
            }
            #[cfg(feature = "bls")]
            (Value::G2(mut a), Value::G2(b)) => {
                a.sub_assign(&b);
                Ok(Value::G2(a))
            }
            (a, b) => Err(format!(
                "attempted to subtract {} from {}",
                b.type_name(),
                a.type_name()
            )
            .into()),
        }
    }
}

impl Mul for Value {
    type Output = Result<Value, Cow<'static, str>>;

    fn mul(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(a.checked_mul(b).ok_or_else(|| {
                    format!("overflowed multiplying {} by {}", a, b)
                })?))
            }
            (Value::Bytes(a), Value::Number(b)) => {
                if b < 0 {
                    return Err("attempted to multiply bytes by a negative number".into());
                }
                if b > u32::max_value() as i64 {
                    return Err("attempted to multiply bytes by a too large number".into());
                }
                let mut out = Vec::with_capacity(a.len() * (b as usize));
                for _ in 0..b {
                    out.extend(&a);
                }
                Ok(Value::Bytes(out))
            }
            (Value::Scalar(a), Value::Scalar(b)) => Ok(Value::Scalar(a * b)),
            (Value::Point(a), Value::Scalar(b)) | (Value::Scalar(b), Value::Point(a)) => {
                Ok(Value::Point(a * b))
            }
            #[cfg(feature = "bls")]
            (Value::Fr(mut a), Value::Fr(b)) => {
                a.mul_assign(&b);
                Ok(Value::Fr(a))
            }
            #[cfg(feature = "bls")]
            (Value::Fq12(mut a), Value::Fq12(b)) => {
                a.mul_assign(&b);
                Ok(Value::Fq12(a))
            }
            #[cfg(feature = "bls")]
            (Value::G1(mut a), Value::Fr(b)) | (Value::Fr(b), Value::G1(mut a)) => {
                a.mul_assign(b);
                Ok(Value::G1(a))
            }
            #[cfg(feature = "bls")]
            (Value::G2(mut a), Value::Fr(b)) | (Value::Fr(b), Value::G2(mut a)) => {
                a.mul_assign(b);
                Ok(Value::G2(a))
            }
            (a, b) => Err(format!(
                "attempted to multiply {} by {}",
                a.type_name(),
                b.type_name()
            )
            .into()),
        }
    }
}

impl Div for Value {
    type Output = Result<Value, Cow<'static, str>>;

    fn div(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(a.checked_div(b).ok_or_else(|| {
                    format!("overflowed dividing {} by {}", a, b)
                })?))
            }
            (Value::Scalar(a), Value::Scalar(b)) => {
                if b.reduce() == Scalar::zero() {
                    return Err("attempted to divide scalar by zero".into());
                }
                Ok(Value::Scalar(a * b.invert()))
            }
            #[cfg(feature = "bls")]
            (Value::Fr(mut a), Value::Fr(b)) => {
                let b_inv: bls12_381::Fr = b
                    .inverse()
                    .ok_or("attempted to divide BLS pairing by zero".to_string())?;
                a.mul_assign(&b_inv);
                Ok(Value::Fr(a))
            }
            #[cfg(feature = "bls")]
            (Value::Fq12(mut a), Value::Fq12(b)) => {
                let b_inv: bls12_381::Fq12 = b
                    .inverse()
                    .ok_or("attempted to divide BLS pairing by zero".to_string())?;
                a.mul_assign(&b_inv);
                Ok(Value::Fq12(a))
            }
            (a, b) => {
                Err(format!("attempted to divide {} by {}", a.type_name(), b.type_name()).into())
            }
        }
    }
}

impl Neg for Value {
    type Output = Result<Value, Cow<'static, str>>;

    fn neg(self) -> Self::Output {
        match self {
            Value::Number(n) => Ok(Value::Number(
                n.checked_neg()
                    .ok_or_else(|| format!("overflowed negating {}", n))?,
            )),
            Value::Scalar(s) => Ok(Value::Scalar(-s)),
            Value::Point(s) => Ok(Value::Point(-s)),
            #[cfg(feature = "bls")]
            Value::Fr(mut x) => {
                x.negate();
                Ok(Value::Fr(x))
            }
            #[cfg(feature = "bls")]
            Value::Fq12(mut x) => {
                x.negate();
                Ok(Value::Fq12(x))
            }
            #[cfg(feature = "bls")]
            Value::G1(mut x) => {
                x.negate();
                Ok(Value::G1(x))
            }
            #[cfg(feature = "bls")]
            Value::G2(mut x) => {
                x.negate();
                Ok(Value::G2(x))
            }
            _ => Err(format!("attempted to negate {}", self.type_name()).into()),
        }
    }
}

pub struct State {
    vars: HashMap<String, Value>,
    rng: OsRng,
}

impl State {
    pub fn new() -> Self {
        let mut this = State {
            vars: HashMap::new(),
            rng: OsRng,
        };
        this.populate_initial_vars();
        this
    }

    fn populate_initial_vars(&mut self) {
        let eight_torsion = EIGHT_TORSION.iter().cloned().map(Value::Point).collect();
        self.vars
            .insert("EIGHT_TORSION".into(), Value::Array(eight_torsion));
        self.vars
            .insert("ED25519_BASEPOINT".into(), Value::Point(ED25519_BASEPOINT));
        self.vars
            .insert("G".into(), Value::Point(ED25519_BASEPOINT));
        self.vars
            .insert("B".into(), Value::Point(ED25519_BASEPOINT));
        #[cfg(feature = "bls")]
        {
            self.vars.insert(
                "G1".into(),
                Value::G1(bls12_381::G1Affine::one().into_projective()),
            );
            self.vars.insert(
                "G2".into(),
                Value::G2(bls12_381::G2Affine::one().into_projective()),
            );
        }
    }

    pub fn eval(&mut self, expr: Expr) -> Result<Value, Cow<'static, str>> {
        match expr {
            Expr::Bytes(bytes) => Ok(Value::Bytes(bytes)),
            Expr::Number(num) => Ok(Value::Number(num)),
            Expr::String(s) => Ok(Value::String(s)),
            Expr::FuncCall(name, params) => {
                let params = params
                    .into_iter()
                    .map(|x| self.eval(*x))
                    .collect::<Result<Vec<_>, _>>()?;
                match name.as_str() {
                    "bytes" => functions::bytes(params),
                    "scalar" => functions::scalar(params),
                    "point" => functions::point(params),
                    "rand" => functions::rand(params, &mut self.rng),
                    "blake2b" => functions::blake2b(params),
                    "sha256" => functions::sha256(params),
                    "sha512" => functions::sha512(params),
                    "keccak256" => functions::keccak256(params),
                    "sha3_256" => functions::sha3_256(params),
                    "sha3_512" => functions::sha3_512(params),
                    "nano_account_encode" => functions::nano_account_encode(params),
                    "nano_account_decode" => functions::nano_account_decode(params),
                    "ed25519_extsk" => functions::ed25519_extsk(params),
                    "ed25519_pub" => functions::ed25519_pub(params),
                    "ed25519_sign" | "sign" => functions::ed25519_sign(params, &mut self.rng),
                    "ed25519_sign_extended"
                    | "ed25519_sign_scalar"
                    | "sign_extended"
                    | "sign_scalar" => functions::ed25519_sign_extended(params, &mut self.rng),
                    "ed25519_verify" | "ed25519_validate" | "verify_sig" => {
                        functions::ed25519_verify(params)
                    }
                    "bls_scalar" => functions::bls_scalar(params),
                    "g1" => functions::g1(params),
                    "g2" => functions::g2(params),
                    "pairing" => functions::pairing(params),
                    _ => Err(format!("unknown function name {}", name).into()),
                }
            }
            Expr::Slice(expr, start, end) => functions::slice(self.eval(*expr)?, start, end),
            Expr::Index(expr, idx) => functions::index(self.eval(*expr)?, idx),
            Expr::NanoBlockHash(block) => functions::nano_block_hash(block),
            Expr::Eq(a, b) => functions::equal(self.eval(*a)?, self.eval(*b)?),
            Expr::Ne(a, b) => functions::not_equal(self.eval(*a)?, self.eval(*b)?),
            Expr::Var(name) => Ok(self
                .vars
                .get(&name)
                .ok_or_else(|| format!("no such variable {}", name))?
                .clone()),
            Expr::SetVar(name, val) => {
                let val = self.eval(*val)?;
                self.vars.insert(name, val.clone());
                Ok(val)
            }
            Expr::Add(a, b) => self.eval(*a)? + self.eval(*b)?,
            Expr::Sub(a, b) => self.eval(*a)? - self.eval(*b)?,
            Expr::Mul(a, b) => self.eval(*a)? * self.eval(*b)?,
            Expr::Div(a, b) => self.eval(*a)? / self.eval(*b)?,
            Expr::Neg(val) => {
                let val = self.eval(*val)?;
                -val
            }
        }
    }
}
