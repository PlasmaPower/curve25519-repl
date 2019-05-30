#![recursion_limit = "1024"]

#[cfg(feature = "blake2")]
extern crate blake2;
extern crate combine;
extern crate curve25519_dalek;
extern crate digest;
extern crate hex;
#[cfg(feature = "nano")]
extern crate nanocurrency_types;
extern crate rand;
extern crate rustyline;
extern crate serde;
extern crate serde_json;
#[cfg(feature = "sha2")]
extern crate sha2;
#[cfg(feature = "sha3")]
extern crate sha3;

mod eval;
mod functions;
mod parser;

use combine::stream::state::State;
use combine::Parser;
use rustyline::error::ReadlineError;

fn main() {
    let mut rl = rustyline::Editor::<()>::new();
    let mut state = eval::State::new();
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_ref());
                let res =
                    (parser::expression(), combine::eof()).easy_parse(State::new(line.as_str()));
                match res {
                    Ok(((expr, _), _)) => match state.eval(expr) {
                        Ok(x) => println!("{}\n", x),
                        Err(e) => println!("Evaluation error: {}\n", e),
                    },
                    Err(err) => println!("Parsing error: {}", err),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
}
