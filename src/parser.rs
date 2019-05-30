use combine::*;
use hex;
use serde::de::Deserialize;
use serde_json;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

#[cfg(feature = "nano")]
type NanoBlock = ::nanocurrency_types::BlockInner;

#[cfg(not(feature = "nano"))]
type NanoBlock = ::serde::de::IgnoredAny;

#[derive(Debug, Clone)]
pub enum Expr {
    // Literals
    Bytes(Vec<u8>),
    Number(i64),
    String(String),
    // Misc.
    FuncCall(String, Vec<Box<Expr>>),
    Slice(Box<Expr>, Option<usize>, Option<usize>),
    Index(Box<Expr>, usize),
    // Variables
    Var(String),
    SetVar(String, Box<Expr>),
    // Arithmetic
    Add(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    // Comparisons
    Eq(Box<Expr>, Box<Expr>),
    Ne(Box<Expr>, Box<Expr>),
    // "Macros"
    NanoBlockHash(NanoBlock),
}

fn skip_whitespace<I>() -> impl Parser<Input = I, Output = ()>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
{
    parser::char::spaces().silent()
}

fn hex<I>() -> impl Parser<Input = I, Output = Vec<u8>>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
{
    many::<String, _>(parser::char::hex_digit()).and_then(|s| hex::decode(s))
}

fn from_str<I, O>() -> impl Parser<Input = I, Output = O>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
    O: ::std::str::FromStr,
    O::Err: ::std::error::Error + Send + Sync + 'static,
{
    many1::<String, _>(parser::char::digit()).and_then(|s| s.parse())
}

fn lex_char<I>(c: char) -> impl Parser<Input = I, Output = char>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
{
    parser::char::char(c).skip(skip_whitespace())
}

// The first character may be any letter. The rest may be alphanumeric.
fn ident<I>() -> impl Parser<Input = I, Output = String>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
{
    look_ahead(parser::char::letter())
        .then(|_| many1(parser::char::alpha_num().or(parser::char::char('_'))))
}

struct StreamReadOne<'a, S: Stream<Item = char, Error = easy::ParseError<S>> + 'a>(
    &'a mut S,
    VecDeque<u8>,
    Option<stream::StreamErrorFor<S>>,
);

impl<'a, S: Stream<Item = char, Error = easy::ParseError<S>> + 'a> io::Read for StreamReadOne<'a, S>
where
    S::Position: Default,
    stream::StreamErrorFor<S>: ToString,
{
    fn read(&mut self, out: &mut [u8]) -> Result<usize, io::Error> {
        if out.len() == 0 {
            return Ok(0);
        }
        if let Some(b) = self.1.pop_front() {
            out[0] = b;
            return Ok(1);
        }
        match self.0.uncons() {
            Ok(x) => {
                let mut buf = [0u8; 4];
                let s = x.encode_utf8(&mut buf);
                let bytes = s.as_bytes();
                if bytes.len() > 1 {
                    self.1.extend(&bytes[1..]);
                }
                out[0] = bytes[0];
                Ok(1)
            }
            Err(e) => {
                let is_eof =
                    ParseError::<S::Item, S::Range, S::Position>::is_unexpected_end_of_input(&e);
                let s = e.to_string();
                if self.2.is_none() {
                    self.2 = Some(e);
                }
                Err(io::Error::new(
                    if is_eof {
                        io::ErrorKind::UnexpectedEof
                    } else {
                        io::ErrorKind::Other
                    },
                    s,
                ))
            }
        }
    }
}

fn nano_block<I>() -> impl Parser<Input = I, Output = NanoBlock>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
    I::Position: Default,
    stream::StreamErrorFor<I>: ToString,
{
    parser(|stream: &mut I| {
        let mut reader = StreamReadOne(stream, VecDeque::new(), None);
        let result = {
            let mut deser = serde_json::Deserializer::from_reader(&mut reader);
            NanoBlock::deserialize(&mut deser)
        };
        result
            .map(|x| (x, error::Consumed::Consumed(())))
            .map_err(|e| {
                if e.is_io() {
                    if let Some(stream_err) = reader.2 {
                        return error::Consumed::Consumed(
                            easy::Errors::new(reader.0.position(), stream_err).into(),
                        );
                    }
                }
                error::Consumed::Consumed(
                    easy::Errors::new(
                        reader.0.position(),
                        easy::Error::Message(
                            ("error parsing block json: ".to_string() + &e.to_string()).into(),
                        ),
                    )
                    .into(),
                )
            })
    })
}

parser! {
    fn continue_expression[I](pemdas_level: u16, lhs: Expr)(I) -> Expr
        where [
            I: Stream<Item = char, Error = easy::ParseError<I>>,
            I::Error: ParseError<I::Item, I::Range, I::Position, StreamError = easy::Error<I::Item, I::Range>>,
            I::Position: Default,
            stream::StreamErrorFor<I>: ToString,
        ]
    {
        let pemdas_level = *pemdas_level;
        let require_pemdas = move |level: u16| parser(move |input| {
            if pemdas_level < level {
                let error = easy::Error::Message("exhausted PEMDAS".into());
                let errors = easy::Errors::new(Positioned::position(&*input), error);
                Err(error::Consumed::Empty(error::Tracked::from(errors)))
            } else {
                Ok(((), error::Consumed::Empty(())))
            }
        });
        let lhs = Arc::new(lhs);
        let lhs1 = lhs.clone();
        let lhs2 = lhs.clone();
        let lhs3 = lhs.clone();
        let lhs4 = lhs.clone();
        let ch = choice!(
            require_pemdas(110).then(move |_|
                (choice!(parser::char::string("=="), parser::char::string("!=")), expression_(100))
            ).map(move |x| {
                if x.0 == "==" {
                    Expr::Eq(Box::new((*lhs1).clone()), Box::new(x.1))
                } else if x.0 == "!=" {
                    Expr::Ne(Box::new((*lhs1).clone()), Box::new(x.1))
                } else {
                    unreachable!()
                }
            }),
            require_pemdas(100).then(move |_|
                (choice!(lex_char('+'), lex_char('-')), expression_(90))
            ).map(move |x| {
                if x.0 == '+' {
                    Expr::Add(Box::new((*lhs2).clone()), Box::new(x.1))
                } else if x.0 == '-' {
                    Expr::Sub(Box::new((*lhs2).clone()), Box::new(x.1))
                } else {
                    unreachable!()
                }
            }),
            require_pemdas(90).then(move |_|
                (choice!(lex_char('*'), lex_char('/')), expression_(80))
            ).map(move |x| {
                if x.0 == '*' {
                    Expr::Mul(Box::new((*lhs3).clone()), Box::new(x.1))
                } else if x.0 == '/' {
                    Expr::Div(Box::new((*lhs3).clone()), Box::new(x.1))
                } else {
                    unreachable!()
                }
            }),
            require_pemdas(80).then(move |_|
                many1::<Vec<_>, _>(
                    (lex_char('['), optional(from_str::<_, usize>()), optional((lex_char(':'),
                        optional(from_str::<_, usize>()))), lex_char(']'))
                )
            ).map(move |x| {
                let mut expr = (*lhs4).clone();
                for parts in x {
                    if let Some(slice_parts) = parts.2 {
                        expr = Expr::Slice(Box::new(expr), parts.1, slice_parts.1);
                    } else {
                        if let Some(idx) = parts.1 {
                            expr = Expr::Index(Box::new(expr), idx);
                        } else {
                            expr = Expr::Slice(Box::new(expr), None, None);
                        }
                    }
                }
                expr
            })
        );
        (skip_whitespace(), ch, skip_whitespace())
            .map(|x| x.1)
            .then(move |x| continue_expression(pemdas_level, x.clone()).or(parser::item::value(x)))
    }
}

parser! {
    fn expression_[I](pemdas_level: u16)(I) -> Expr
        where [
            I: Stream<Item = char, Error = easy::ParseError<I>>,
            I::Error: ParseError<I::Item, I::Range, I::Position, StreamError = easy::Error<I::Item, I::Range>>,
            I::Position: Default,
            stream::StreamErrorFor<I>: ToString,
        ]
    {
        let ch = choice!(
            (attempt(parser::char::string("0x")), hex()).map(|x| Expr::Bytes(x.1)),
            attempt(from_str()).map(Expr::Number),
            (attempt(parser::char::string("nano_block_hash!(")), nano_block(), lex_char(')'))
                .map(|x| Expr::NanoBlockHash(x.1)),
            attempt((ident(), lex_char('('), sep_by(expression().map(Box::new), lex_char(',')), lex_char(')'))
                .map(|x| Expr::FuncCall(x.0, x.2))),
            attempt((ident(), skip_whitespace(), lex_char('='), expression()).map(|x| Expr::SetVar(x.0, Box::new(x.3)))),
            attempt(ident().map(Expr::Var)),
            attempt(between(lex_char('('), lex_char(')'), expression())),
            attempt(between(lex_char('"'), lex_char('"'), many1(none_of(vec!['"']))).map(Expr::String)),
            attempt((lex_char('-'), expression()).map(|x| Expr::Neg(Box::new(x.1))))
        );
        let pemdas_level = *pemdas_level;
        (skip_whitespace(), ch, skip_whitespace()).then(move |x|
            continue_expression(pemdas_level, x.1.clone()).or(parser::item::value(x.1))
        )
    }
}

pub fn expression<I>() -> impl Parser<Input = I, Output = Expr>
where
    I: Stream<Item = char, Error = easy::ParseError<I>>,
    I::Position: Default,
    I::Error:
        ParseError<I::Item, I::Range, I::Position, StreamError = easy::Error<I::Item, I::Range>>,
    stream::StreamErrorFor<I>: ToString,
{
    expression_(200)
}
