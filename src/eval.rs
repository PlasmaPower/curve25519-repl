use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use functions;
use hex;
use parser::Expr;
use rand::OsRng;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

#[derive(Debug, Clone)]
pub enum Value {
    Bytes(Vec<u8>),
    Number(i64),
    String(String),
    Bool(bool),
    Scalar(Scalar),
    Point(EdwardsPoint),
    Array(Vec<Value>),
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
            (Value::Scalar(a), Value::Point(b)) => Ok(Value::Point(a * b)),
            (Value::Point(a), Value::Scalar(b)) => Ok(Value::Point(a * b)),
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
                if b.reduce().as_bytes() == &[0u8; 32] {
                    return Err("attempted to divide scalar by zero".into());
                }
                Ok(Value::Scalar(a * b.invert()))
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
            rng: OsRng::new().expect("Failed to create OsRng"),
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
                    "ed25519_sign" => functions::ed25519_sign(params, &mut self.rng),
                    "ed25519_sign_extended" | "ed25519_sign_scalar" => {
                        functions::ed25519_sign_extended(params, &mut self.rng)
                    }
                    "ed25519_verify" | "ed25519_validate" => functions::ed25519_verify(params),
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
