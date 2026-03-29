#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Val};

#[contract]
pub struct Echo;

#[contractimpl]
impl Echo {
    fn helper(v: Val) -> Val {
        v
    }

    pub fn echo(_env: Env, v: Val) -> Val {
        Self::helper(v)
    }
}
