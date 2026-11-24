fn main() -> std::process::ExitCode {
    match xmsg_executor::operator::run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            std::process::ExitCode::FAILURE
        }
    }
}
