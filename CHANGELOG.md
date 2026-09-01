# Changelog

All notable changes to this project are documented in this file.

## 0.3.0

Released on 2026-09-01

### Breaking changes

- add smb dialect selection with per-client contexts

> pavao and pavao-sys move to 0.3.0. Non-vendored
> builds now require libsmbclient ABI 0.5.0 or newer (Samba 4.10+);
> install a recent libsmbclient or use the vendored feature. Each
> SmbClient owns its native context: code that relied on the first
> client's credentials and options applying to later clients must now
> configure every client explicitly, and code that avoided keeping two
> clients alive simultaneously no longer needs that workaround. SmbError
> gained the InvalidProtocolRange and ProtocolConfiguration variants,
> so exhaustive matches on SmbError must add arms for them. The workspace
> keyword list replaced network-protocol with smb1.

### Added

- Breaking: add smb dialect selection with per-client contexts

> Allow every client to bound SMB protocol negotiation to exact dialects
> (NT1, SMB2_02, SMB2_10, SMB3_00, SMB3_02, SMB3_11) through the new
> SmbDialect enum and the SmbOptions::min_protocol/max_protocol builders.
> Bounds are validated before FFI, applied through smbc_setOptionProtocols
> before context initialization, and left unset by default so existing
> consumers keep their smb.conf negotiation; SMB1 (NT1) is never offered
> unless both bounds explicitly request it.
>
> Each SmbClient now owns a private SMBCCTX instead of sharing one
> process-global context, so multiple clients with independent
> credentials and dialect bounds may be alive at the same time. Crate
> metadata, keywords, and the README now advertise SMB 1/2/3 support,
> and integration tests cover the dialect negotiation matrix against
> configurable Samba servers.

- **pavao-sys:** add libsmbclient ABI features
- **pavao-sys:** add directory entry constants
- **pavao-sys:** add share and encryption constants
- **pavao-sys:** add extended attribute constants
- **pavao-sys:** add VFS feature constants
- **pavao-sys:** add notification constants
- **pavao-sys:** bind smbc_getDebug
- **pavao-sys:** bind smbc_setConfiguration
- **pavao-sys:** bind smbc_setLogCallback
- **pavao-sys:** bind smbc_getPort
- **pavao-sys:** bind smbc_setPort
- **pavao-sys:** bind smbc_getOptionFullTimeNames
- **pavao-sys:** bind smbc_setOptionFullTimeNames
- **pavao-sys:** bind smbc_getOptionUserData
- **pavao-sys:** bind smbc_setOptionUserData
- **pavao-sys:** bind smbc_getOptionUseNTHash
- **pavao-sys:** bind smbc_setOptionUseNTHash
- **pavao-sys:** bind smbc_set_credentials_with_fallback
- **pavao-sys:** bind smbc_getOptionDebugToStderr
- **pavao-sys:** bind smbc_getOptionOpenShareMode
- **pavao-sys:** bind smbc_getOptionSmbEncryptionLevel
- **pavao-sys:** bind smbc_getOptionCaseSensitive
- **pavao-sys:** bind smbc_getOptionBrowseMaxLmbCount
- **pavao-sys:** bind smbc_getOptionUrlEncodeReaddirEntries
- **pavao-sys:** bind smbc_getOptionOneSharePerServer
- **pavao-sys:** bind smbc_getOptionUseKerberos
- **pavao-sys:** bind smbc_getOptionFallbackAfterKerberos
- **pavao-sys:** bind smbc_getOptionNoAutoAnonymousLogin
- **pavao-sys:** bind smbc_getOptionUseCCache
- **pavao-sys:** bind smbc_getFunctionCreat
- **pavao-sys:** bind smbc_getFunctionSplice
- **pavao-sys:** bind smbc_getFunctionFstat
- **pavao-sys:** bind smbc_getFunctionFstatVFS
- **pavao-sys:** bind smbc_getFunctionFtruncate
- **pavao-sys:** bind smbc_getFunctionGetdents
- **pavao-sys:** bind smbc_getFunctionTelldir
- **pavao-sys:** bind smbc_getFunctionLseekdir
- **pavao-sys:** bind smbc_getFunctionFstatdir
- **pavao-sys:** bind smbc_getFunctionNotify
- **pavao-sys:** bind ABI 0.6 smbc_getFunctionReaddirPlus2
- **pavao-sys:** bind smbc_getFunctionUtimes
- **pavao-sys:** bind smbc_getFunctionSetxattr
- **pavao-sys:** bind smbc_getFunctionGetxattr
- **pavao-sys:** bind smbc_getFunctionRemovexattr
- **pavao-sys:** bind smbc_getFunctionListxattr
- **pavao-sys:** bind smbc_getFunctionOpenPrintJob
- **pavao-sys:** bind smbc_getFunctionListPrintJobs
- **pavao-sys:** bind smbc_getFunctionUnlinkPrintJob
- **pavao-sys:** bind ABI 0.8 smbc_getOptionPosixExtensions
- **pavao-sys:** bind ABI 0.8 smbc_setOptionPosixExtensions
- **pavao-sys:** test libsmbclient ABI features in CI

### Fixed

- improve Rust quality and test coverage

> Fix mutex error equality and align touched Rust code with project conventions. Expand pavao tests, add the workspace publishing helper, and correct pavao-sys documentation.

- **pavao-src:** bump samba to `4.22.11` (#41)
- serialize libsmbclient operations (#43)
- **pavao-sys:** make SMBCCTX opaque
- **pavao-sys:** model smbc_dirent flexible storage
- **pavao-sys:** use uint64_t for file info size
- **pavao-sys:** make encryption level signed
- **pavao-sys:** correct context string constness
- **pavao:** avoid leaking context option strings
- **just:** preserve forwarded test arguments

### Build

- modernize project tooling
- **pavao-src:** add `https` feature to `git2`

## 0.2.15

Released on 2025-11-10

### Fixed

- Build env for pkg-config on mac when building as external crate
- build of pavao-src requires the gnutls include to be passed from outside
- remove check

## 0.2.13

Released on 2025-09-20

### Build

- vendored macos (#36)

## 0.2.12

Released on 2025-03-20

### Fixed

- Vendored libsmbclient static (#32)

## 0.2.11

Released on 2025-03-19

### Added

- added new library pavao-sys

### Fixed

- 0.2.11; split lib into pavao and pavao-sys

### README

- fix author website URL (#30)

> - README: fix author website URL
> - Update README.md
>
> ---

## 0.2.10

Released on 2025-02-21

### Fixed

- 0.2.10

## 0.2.9

Released on 2025-01-06

### Added

- do matrix builds for macos runs (#25)

### Fixed

- 0.2.8
- msrv
- android support

## 0.2.8

Released on 2024-12-19

### Fixed

- tests

## 0.2.7

Released on 2024-07-29

### Added

- add statvfs support for RISC-V64 (#19)

### Fixed

- ci
- ci
- 0.2.7

## 0.2.6

Released on 2024-04-11

### Fixed

- readme
- support for armv32

## 0.2.5

Released on 2024-02-13

### Added

- add support for Linux RISC-V64 (#12)

### Fixed

- 0.2.5

## 0.2.4

Released on 2024-01-28

### Added

- pavao is now thread safe

## 0.2.3

Released on 2023-05-16

### Fixed

- aarch64 linux build
- aarch64 linux build

## 0.2.1

Released on 2023-05-15

### Fixed

- aarch64 linux build
- aarch64 linux build

## 0.2.0

Released on 2023-05-10

### Added

- Added list_dirplus function and treeplus example (#4)
- no-log features

### Fixed

- changelog

## 0.1.0

Released on 2022-05-21
