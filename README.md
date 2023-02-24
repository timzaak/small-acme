# small-acme: small, pure-Rust ACME client

[![Documentation](https://docs.rs/small-acme/badge.svg)](https://docs.rs/small-acme/)
[![Crates.io](https://img.shields.io/crates/v/small-acme.svg)](https://crates.io/crates/small-acme)
[![Build status](https://github.com/Icelk/small-acme/workflows/CI/badge.svg)](https://github.com/Icelk/small-acme/actions?query=workflow%3ACI)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

> This is a fork from [instant-acme](https://github.com/InstantDomain/instant-acme)
> without async or hyper, to provide a slim, `rustls` based solution.

small-acme is a small, pure-Rust ACME (RFC 8555) client.

small-acme is used in production at [my](https://icelk.dev) [websites](https://kvarn.org) to help
me provision and renew TLS certificates without any intervention. small-acme relies
on ureq and rustls to implement the [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
specification.

## Features

* Store/recover your account credentials by serializing/deserializing
* Simple blocking support (which can be used in [tokio](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html))
* Support for processing multiple orders concurrently
* Uses ureq with rustls for HTTP requests
* Uses *ring* for ECDSA signing
* Minimum supported Rust version: 1.64

## Limitations

* Only tested with DNS and HTTP challenges against Let's Encrypt so far (staging and production)
* Only supports ECDSA keys for now

## Getting started

See the [examples](examples) directory for an example of how to use small-acme.
