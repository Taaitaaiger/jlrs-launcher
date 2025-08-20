use std::{
    env::{self, join_paths, split_paths},
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    process::{Command, ExitCode, exit},
};

use anyhow::{Context, Result, anyhow};
use clap::{Arg, ArgAction, builder::ValueParser};
use console::{Term, style};
use env_logger::{self, Env};
use human_panic::{Metadata, setup_panic};
use is_terminal::IsTerminal;
use itertools::Itertools;
use juliaup::{
    config_file::{JuliaupConfig, JuliaupConfigChannel, JuliaupReadonlyConfigFile, load_config_db},
    global_paths::get_paths,
    jsonstructs_versionsdb::JuliaupVersionDB,
    operations::{is_pr_channel, is_valid_channel},
    versions_file::load_versions_db,
};
use normpath::PathExt;

#[cfg(all(unix, not(target_os = "macos")))]
static LIBRARY_PATH_VAR_NAME: &'static str = "LD_LIBRARY_PATH";
#[cfg(target_os = "macos")]
static LIBRARY_PATH_VAR_NAME: &'static str = "DYLD_LIBRARY_PATH";
#[cfg(windows)]
static PATH_VAR_NAME: &'static str = "Path";

#[derive(thiserror::Error, Debug)]
#[error("{msg}")]
pub struct UserError {
    msg: String,
}

enum JuliaupChannelSource {
    CmdLine,
    EnvVar,
    Override,
    Default,
}

fn get_julia_dir(channel_from_cmd_line: Option<String>) -> Result<PathBuf> {
    let paths = get_paths().with_context(|| "Trying to load all global paths.")?;

    let config_file = load_config_db(&paths, None)
        .with_context(|| "The jlrs launcher failed to load a configuration file.")?;

    let versiondb_data = load_versions_db(&paths)
        .with_context(|| "The jlrs launcher failed to load a versions db.")?;

    let (julia_channel_to_use, juliaup_channel_source) =
        if let Some(channel) = channel_from_cmd_line {
            (channel, JuliaupChannelSource::CmdLine)
        } else if let Ok(channel) = env::var("JULIAUP_CHANNEL") {
            (channel, JuliaupChannelSource::EnvVar)
        } else if let Ok(Some(channel)) = get_override_channel(&config_file) {
            (channel, JuliaupChannelSource::Override)
        } else if let Some(channel) = config_file.data.default.clone() {
            (channel, JuliaupChannelSource::Default)
        } else {
            return Err(anyhow!(
                "The jlrs launcher failed to figure out which juliaup channel to use."
            ));
        };

    let julia_dir = get_julia_dir_from_channel(
        &versiondb_data,
        &config_file.data,
        &julia_channel_to_use,
        &paths.juliaupconfig,
        juliaup_channel_source,
    )
    .with_context(|| {
        format!(
            "The jlrs launcher failed to determine the command for the `{}` channel.",
            julia_channel_to_use
        )
    })?;

    Ok(julia_dir)
}

fn get_julia_dir_from_channel(
    versions_db: &JuliaupVersionDB,
    config_data: &JuliaupConfig,
    channel: &str,
    juliaupconfig_path: &Path,
    juliaup_channel_source: JuliaupChannelSource,
) -> Result<PathBuf> {
    let channel_valid = is_valid_channel(versions_db, &channel.to_string())?;
    let channel_info = config_data
            .installed_channels
            .get(channel)
            .ok_or_else(|| match juliaup_channel_source {
                JuliaupChannelSource::CmdLine => {
                    if channel_valid {
                        UserError { msg: format!("`{}` is not installed. Please run `juliaup add {}` to install channel or version.", channel, channel) }
                    } else if is_pr_channel(&channel.to_string()) {
                        UserError { msg: format!("`{}` is not installed. Please run `juliaup add {}` to install pull request channel if available.", channel, channel) }
                    } else {
                        UserError { msg: format!("Invalid Juliaup channel `{}`. Please run `juliaup list` to get a list of valid channels and versions.",  channel) }
                    }
                }.into(),
                JuliaupChannelSource::EnvVar=> {
                    if channel_valid {
                        UserError { msg: format!("`{}` from environment variable JULIAUP_CHANNEL is not installed. Please run `juliaup add {}` to install channel or version.", channel, channel) }
                    } else if is_pr_channel(&channel.to_string()) {
                        UserError { msg: format!("`{}` from environment variable JULIAUP_CHANNEL is not installed. Please run `juliaup add {}` to install pull request channel if available.", channel, channel) }
                    } else {
                        UserError { msg: format!("Invalid Juliaup channel `{}` from environment variable JULIAUP_CHANNEL. Please run `juliaup list` to get a list of valid channels and versions.",  channel) }
                    }
                }.into(),
                JuliaupChannelSource::Override=> {
                    if channel_valid {
                        UserError { msg: format!("`{}` from directory override is not installed. Please run `juliaup add {}` to install channel or version.", channel, channel) }
                    } else if is_pr_channel(&channel.to_string()){
                        UserError { msg: format!("`{}` from directory override is not installed. Please run `juliaup add {}` to install pull request channel if available.", channel, channel) }
                    } else {
                        UserError { msg: format!("Invalid Juliaup channel `{}` from directory override. Please run `juliaup list` to get a list of valid channels and versions.",  channel) }
                    }
                }.into(),
                JuliaupChannelSource::Default => UserError {msg: format!("The Juliaup configuration is in an inconsistent state, the currently configured default channel `{}` is not installed.", channel) }
            })?;

    match channel_info {
        JuliaupConfigChannel::LinkedChannel { command, .. } => {
            return Ok(PathBuf::from(command)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .into());
        }
        JuliaupConfigChannel::SystemChannel { version } => {
            let path = &config_data
                .installed_versions.get(version)
                .ok_or_else(|| anyhow!("The juliaup configuration is in an inconsistent state, the channel {} is pointing to Julia version {}, which is not installed.", channel, version))?.path;

            let absolute_path = juliaupconfig_path
                .parent()
                .unwrap() // unwrap OK because there should always be a parent
                .join(path)
                .normalize()
                .with_context(|| {
                    format!(
                        "Failed to normalize path for Julia binary, starting from `{}`.",
                        juliaupconfig_path.display()
                    )
                })?;
            return Ok(absolute_path.into_path_buf());
        }
        JuliaupConfigChannel::DirectDownloadChannel {
            path,
            url: _,
            local_etag,
            server_etag,
            version: _,
        } => {
            if local_etag != server_etag {
                if channel.starts_with("nightly") {
                    // Nightly is updateable several times per day so this message will show
                    // more often than not unless folks update a couple of times a day.
                    // Also, folks using nightly are typically more experienced and need
                    // less detailed prompting
                    eprintln!(
                        "A new `nightly` version is available. Install with `juliaup update`."
                    );
                } else {
                    eprintln!(
                        "A new version of Julia for the `{}` channel is available. Run:",
                        channel
                    );
                    eprintln!();
                    eprintln!("  juliaup update");
                    eprintln!();
                    eprintln!("to install the latest Julia for the `{}` channel.", channel);
                }
            }

            let absolute_path = juliaupconfig_path
                .parent()
                .unwrap()
                .join(path)
                .normalize()
                .with_context(|| {
                    format!(
                        "Failed to normalize path for Julia binary, starting from `{}`.",
                        juliaupconfig_path.display()
                    )
                })?;
            return Ok(absolute_path.into_path_buf());
        }
    }
}

fn get_override_channel(config_file: &JuliaupReadonlyConfigFile) -> Result<Option<String>> {
    let curr_dir = env::current_dir()?.canonicalize()?;

    let juliaup_override = config_file
        .data
        .overrides
        .iter()
        .filter(|i| curr_dir.starts_with(&i.path))
        .sorted_by_key(|i| i.path.len())
        .last();

    match juliaup_override {
        Some(val) => Ok(Some(val.channel.clone())),
        None => Ok(None),
    }
}

fn cmd_string(application: &OsStr, app_args: &[&OsString]) -> String {
    format!(
        "{} {}",
        application.to_string_lossy(),
        app_args
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn print_env(channel: Option<&String>) -> Result<i32> {
    let channel_from_cmd_line = channel
        .map(|c| {
            c.strip_prefix("+")
                .map(|s| s.to_string())
                .with_context(|| "Invalid channel, must start with `+`")
        })
        .transpose()?;

    let julia_dir = get_julia_dir(channel_from_cmd_line)?;

    // On *nix platforms we replace the current process with the Julia one.
    #[cfg(not(windows))]
    {
        let library_path = {
            let library_path = julia_dir.join("lib");
            match env::var_os(LIBRARY_PATH_VAR_NAME) {
                Some(var) => {
                    let split = split_paths(&var);
                    let ext = [library_path].into_iter().chain(split);
                    join_paths(ext).with_context(|| "Could join paths")?
                }
                None => library_path.into_os_string(),
            }
        };

        println!("JLRS_JULIA_DIR={}", julia_dir.to_string_lossy());
        println!(
            "{}={}",
            LIBRARY_PATH_VAR_NAME,
            library_path.to_string_lossy()
        );
    }

    #[cfg(windows)]
    {
        let path = {
            let path = julia_dir.join("bin");
            match env::var_os(PATH_VAR_NAME) {
                Some(var) => {
                    let split = split_paths(&var);
                    let ext = [path].into_iter().chain(split);
                    join_paths(ext).with_context(|| "Could join paths")?
                }
                None => path.into_os_string(),
            }
        };

        println!("JLRS_JULIA_DIR={}", julia_dir.to_string_lossy());
        println!("{}={}", PATH_VAR_NAME, path.to_string_lossy());
    }

    Ok(0)
}

fn run(cmd: Vec<&OsString>) -> Result<i32> {
    let mut args = cmd.into_iter();

    // Parse command line
    let first_arg = args
        .next()
        .with_context(|| "The jlrs launcher expected an application to launch")?;

    let channel_from_cmd_line = first_arg
        .to_string_lossy()
        .strip_prefix("+")
        .map(|s| s.to_string());

    let application = if channel_from_cmd_line.is_none() {
        first_arg
    } else {
        args.next()
            .with_context(|| "The jlrs launcher expected an application to launch")?
    };

    let app_args: Vec<&OsString> = args.collect();

    if io::stdout().is_terminal() {
        // Set console title
        let term = Term::stdout();
        let title = cmd_string(&application, &app_args);
        term.set_title(title);
    }

    let julia_dir = get_julia_dir(channel_from_cmd_line)?;

    run_app_internal(application, app_args, julia_dir)
}

// On *nix platforms we replace the current process with the Julia one.
#[cfg(not(windows))]
fn run_app_internal(
    application: &OsString,
    app_args: Vec<&OsString>,
    julia_dir: PathBuf,
) -> Result<i32> {
    use std::os::unix::process::CommandExt;

    let library_path = {
        let library_path = julia_dir.join("lib");
        match env::var_os(LIBRARY_PATH_VAR_NAME) {
            Some(var) => {
                let split = split_paths(&var);
                let ext = [library_path].into_iter().chain(split);
                join_paths(ext).with_context(|| "Could join paths")?
            }
            None => library_path.into_os_string(),
        }
    };

    let e = Command::new(&application)
        .envs([
            ("JLRS_JULIA_DIR", julia_dir.as_os_str()),
            (LIBRARY_PATH_VAR_NAME, &library_path),
        ])
        .args(app_args.iter())
        .exec();

    panic!(
        "Could not launch \"{}\" with JLRS_JULIA_DIR=\"{}\" and {}=\"{}\" (error: {})",
        cmd_string(&application, &app_args),
        julia_dir.as_os_str().to_string_lossy(),
        LIBRARY_PATH_VAR_NAME,
        library_path.to_string_lossy(),
        e
    )
}

#[cfg(windows)]
fn run_app_internal(
    application: &OsString,
    app_args: Vec<&OsString>,
    julia_dir: PathBuf,
) -> Result<i32> {
    use std::{
        ffi::c_void,
        mem::{size_of_val, transmute},
        os::windows::io::{AsRawHandle, RawHandle},
    };

    use ctrlc::set_handler;
    use windows::{
        Win32::{
            Foundation::HANDLE,
            Security::SECURITY_ATTRIBUTES,
            System::{
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject,
                },
                Threading::GetCurrentProcess,
            },
        },
        core::PCWSTR,
    };

    let path = {
        let path = julia_dir.join("bin");
        match env::var_os(PATH_VAR_NAME) {
            Some(var) => {
                let split = split_paths(&var);
                let ext = [path].into_iter().chain(split);
                join_paths(ext).with_context(|| "Could join paths")?
            }
            None => path.into_os_string(),
        }
    };

    // We set a Ctrl-C handler here that just doesn't do anything, as we want the Julia child
    // process to handle things.
    set_handler(|| ()).with_context(|| "Failed to set the Ctrl-C handler.")?;

    let mut job_attr = SECURITY_ATTRIBUTES::default();
    job_attr.bInheritHandle = false.into();

    let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK
        | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    let job_handle = unsafe {
        let job_handle = CreateJobObjectW(Some(&job_attr), PCWSTR::null())?;

        SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            &job_info as *const _ as *const c_void,
            size_of_val(&job_info) as u32,
        )?;

        AssignProcessToJobObject(job_handle, GetCurrentProcess())?;

        job_handle
    };

    let mut child_process = Command::new(&application)
        .envs([
            ("JLRS_JULIA_DIR", julia_dir.as_os_str()),
            (PATH_VAR_NAME, &path),
        ])
        .args(app_args.iter())
        .spawn()
        .with_context(|| "The jlrs launcher failed to run the command.")?; // TODO Maybe include the command we actually tried to start?

    // We ignore any error here, as that is what libuv also does, see the documentation
    // at https://github.com/libuv/libuv/blob/5ff1fc724f7f53d921599dbe18e6f96b298233f1/src/win/process.c#L1077
    let _ = unsafe {
        AssignProcessToJobObject(
            job_handle,
            transmute::<RawHandle, HANDLE>(child_process.as_raw_handle()),
        )
    };

    child_process
        .wait()
        .with_context(|| "Failed to wait for command to finish.")?
        .code()
        .with_context(|| "There is no exit code, that should not be possible on Windows.")
}

fn main() -> Result<ExitCode> {
    let client_status;

    {
        setup_panic!(
            Metadata::new("jlrs-launcher", env!("CARGO_PKG_VERSION"))
                .support("https://github.com/Taaitaaiger/jlrs")
        );

        let env = Env::new()
            .filter("JULIAUP_LOG")
            .write_style("JULIAUP_LOG_STYLE");
        env_logger::init_from_env(env);

        let cmd_matches = clap::Command::new("jlrs-launcher")
            .author("Thomas van Doornmalen")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Run a command in a Julia environment")
            .subcommand(
                clap::Command::new("run")
                    .arg(
                        Arg::new("cmd")
                            .help("The command to run")
                            .action(ArgAction::Append)
                            .required(true)
                            .value_name("CMD")
                            .value_parser(ValueParser::os_string()),
                    )
                    .about("Run a command in a Julia environment")
                    .after_help(
                        "\
When `jlrs-launcher run` is used to run a command, `juliaup` is used to
figure out what version of Julia should be activated in the environment.

Before the command is executed, the `JLRS_JULIA_DIR` environment variable is set to
the location where the active Julia version has been installed and the
directory where libjulia can be found is prepended to
`LD_LIBRARY_PATH` (Linux), `DYLD_LIBRARY_PATH` (macOS), or `Path` (Windows).

Like juliaup's launcher, it's possible to override the default version by
setting the first argument to `+channel`, e.g. `jlrs-launch run +1.11 my_cmd`.

The main use-case is running applications that embed Julia when `juliaup` is
used.",
                    ),
            )
            .subcommand(
                clap::Command::new("print-env")
                    .about("Print the current environment")
                    .arg(Arg::new("channel").help("Channel, e.g. +1.11")),
            )
            .get_matches();

        if let Some(run_matches) = cmd_matches.subcommand_matches("run") {
            if let Some(cmd) = run_matches.get_many::<OsString>("cmd") {
                let cmd = cmd.collect();
                client_status = run(cmd);
            } else {
                return Ok(ExitCode::FAILURE);
            }
        } else if let Some(print_env_matches) = cmd_matches.subcommand_matches("print-env") {
            let channel = print_env_matches.get_one::<String>("channel");
            client_status = print_env(channel);
        } else {
            return Ok(ExitCode::FAILURE);
        }

        if let Err(err) = client_status {
            if let Some(e) = err.downcast_ref::<UserError>() {
                eprintln!("{} {}", style("ERROR:").red().bold(), e.msg);
                return Ok(ExitCode::FAILURE);
            } else {
                return Err(err);
            }
        }
    }

    // TODO https://github.com/rust-lang/rust/issues/111688 is finalized, we should use that instead of calling exit
    exit(client_status?);
}
