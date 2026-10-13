
mod dbconnection;
use dbconnection::*;
mod arp;
use arp::scan;

fn main() {

    match arp::scan() {
        Ok(results) => {
            //
        }
        Err(e) => {
            eprintln!("Erro durante o scan: {:?}", e);
        }
    }
}