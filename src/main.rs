mod attachment;
mod cli;
mod config;
mod crypto;
mod daemon;
mod ipc;
mod scanner;

fn main() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    if std::env::var("WX_DAEMON_MODE").is_ok() {
        daemon::run();
    } else {
        cli::run();
    }
}
