//! HACP Wasmer sandbox demo: one normal run and three isolation checks.
//!
//! Exits 0 only if every check comes out as expected.

use hacp_wasmer_sandbox::{demo, WasmerCliExecutor, DEFAULT_PYTHON_PACKAGE};
use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    // The secret check needs fake HACP secrets in *this* process's
    // environment. Plant them by re-executing ourselves, so the executor is
    // never told what to hide — it simply must not forward anything.
    if !demo::secret_env_planted() {
        let exe = match env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                eprintln!("cannot locate demo executable: {e}");
                return ExitCode::FAILURE;
            }
        };
        let mut cmd = Command::new(exe);
        cmd.args(env::args_os().skip(1));
        demo::plant_secret_env(&mut cmd);
        return match cmd.status() {
            Ok(status) if status.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("cannot re-run demo with planted secrets: {e}");
                ExitCode::FAILURE
            }
        };
    }

    println!("== HACP Wasmer sandbox PoC ==");
    let executor = match WasmerCliExecutor::from_host(vec![DEFAULT_PYTHON_PACKAGE.to_owned()]) {
        Ok(executor) => executor,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match executor.runtime_version() {
        Ok(version) => println!("runtime : {version} (CLI)"),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    }
    println!("package : {DEFAULT_PYTHON_PACKAGE}");
    println!("grants  : /work (staged files only); env {} only; no network", demo::GRANTED_ENV.0);

    let checks = demo::run_all(&executor, executor.wasmer_dir());
    for check in &checks {
        println!();
        println!("{}: {}", check.label, check.verdict);
        for detail in &check.details {
            println!("    {detail}");
        }
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    println!();
    println!("RESULT: {passed}/{} checks as expected", checks.len());
    if passed == checks.len() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
