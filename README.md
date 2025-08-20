# jlrs-launcher

A `juliaup`-aware launcher for projects that use jlrs.

## Rationale

When you use `juliaup` to manage your Julia installations it can be quite challenging to use jlrs; you need to figure out where everything has been installed, which is a detail that `juliaup` is trying to hide from you. This can be problematic whenever you try to run or compile such a project. Since `juliaup` is written in Rust and is published as a crate, it's possible to reuse its logic to declare and locate a specific Julia version, and launch an application with the appropriate environment variables set to their proper value, similar to how `juliaup` launches Julia itself.

## Installation

This application can be installed with `cargo`:

```bash
cargo install jlrs-launcher
```

## Using `jlrs-launcher`

`jlrs-launcher` supports three commands: `help`, `print-env`, and `run`. The first prints some helpful information, the second prints the additionally set environment variables, and the last runs a commands in a process with the updated environment.

When `jlrs-launcher run` is used, the installation of Julia that must be used can be set with `+version` just as `juliaup`'s `julia` launcher and `cargo`:

```bash
jlrs-launcher run +1.11 cmd
```

Any argument provided after `--` is propagated to the launched application:

```bash
jlrs-launcher run +1.11 cargo test -- --features full,ccall
```

calls

```bash
cargo test --features full,ccall
```

in the appropriate environment.
