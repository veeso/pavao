# Changelog

- [Changelog](#changelog)
  - [0.2.13](#0213)
  - [0.2.12](#0212)
  - [0.2.11](#0211)
  - [0.2.10](#0210)
  - [0.2.9](#029)
  - [0.2.8](#028)
  - [0.2.7](#027)
  - [0.2.6](#026)
  - [0.2.5](#025)
  - [0.2.4](#024)
  - [0.2.3](#023)
  - [0.2.2](#022)
  - [0.2.1](#021)
  - [0.2.0](#020)
  - [0.1.2](#012)
  - [0.1.1](#011)
  - [0.1.0](#010)

---

## 0.2.13

Released on 20/09/2025

- Vendored samba now builds on MacOS.

## 0.2.12

Released on 19/03/2025

- Added `pavao-src` crate with samba source code to build smbclient
- Added `vendored` feature to use vendored samba source code

## 0.2.11

Released on 19/03/2025

- split pavao into `pavao` and `pavao-sys` (which just contains the libsmbclient bindings)

## 0.2.10

Released on 21/02/2025

- fix: race condition in `SmbClient::new` [PR29](https://github.com/veeso/pavao/pull/29)

## 0.2.9

- Support for Android

## 0.2.8

- chore(build): improve macOS linking for libsmbclient

## 0.2.7

Released on 29/07/2024

- Added support for OpenBSD

## 0.2.6

Released on 11/04/2024

- Added support for ARM 32 bit

## 0.2.5

Released on 13/02/2024

- Fixed [issue #7](https://github.com/veeso/pavao/issues/7): Added support for Linux RISC-V64
- Fixed [issue #9](https://github.com/veeso/pavao/issues/10): Added statvfs API

## 0.2.4

Released on 28/01/2024

- Pavao is now thread safe

## 0.2.3

Released on 16/05/2023

- Fixed aarch64 linux build

## 0.2.2

Released on 16/05/2023

- Fixed aarch64 linux build

## 0.2.1

Released on 15/05/2023

- Fixed aarch64 linux build

## 0.2.0

Released on 10/05/2023

- [Issue 3](https://github.com/veeso/pavao/issues/3): implemented `list_dirplus` to get the list of files in the current path with all the metadata. credit: @hexofyore
- Added `no-log` feature to disable logging

## 0.1.2

Released on 26/05/2022

- Added file type to `SmbMode`

## 0.1.1

Released on 23/05/2022

- Fixed `SmbDirent` `name` field which was always corrupted when decoding from libsmbclient.

## 0.1.0

Released on 21/05/2022

- First release
