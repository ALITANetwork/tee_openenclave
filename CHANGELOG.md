Changelog
=========

Major work such as new features, bug fixes, feature deprecations, and other
breaking changes should be noted here. It should be more concise than `git log`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased]
------------

### Added

- Open Enclave SDK works in Windows
   - Build using Visual Studio 2017's CMake Support
   - Build in x64 Native Prompt using Ninja
- Function table/id based ecall/ocall dispatching
   - oeedger8r generates ecall tables and ocall tables
   - Dispatching based on function-id (index into table)
   - oeedger8r generates `oe_create_foo_enclave` function for `foo.edl`
   - oe-gdb allows attaching to a host that is already running
- oe-gdb allows attaching to a host that is already running
- Added Quote Enclave Identity validation into `oe_verify_report` implementation
- Added OE SDK internal logging mechanism
- Support for thread local variables
   - Both GNU `__thread` and C++11 `thread_local`
   - Both hardware and simulation mode
   - Enclaves are compiled using local-exec thread-local model (-ftls-model=local-exec)
- Added `oe_get_public_key` and `oe_get_public_key_by_policy` host functions,
  which allow the host to get a public key derived from an enclave's identity.
- Added v2 versions of the following APIs that instead of passing in buffers now
  return a buffer that needs to be freed via an associated free method. `OE_API_VERSION`
  needs to be set to 2 to pick up the versions. The mentioned APIs have a *_V1 and *_V2
  version that the below versions map to detending on the `OE_API_VERSION`.
   - `oe_get_report`, free `report_buffer` via `oe_free_report`
   - `oe_get_target_info`, free `target_info_buffer` via `oe_free_target_info`
   - `oe_get_seal_key`, free `key_buffer` and `key_info` via `oe_free_seal_key`
   - `oe_get_seal_key_by_policy`, free `key_buffer` and `key_info` via `oe_free_seal_key`
- Added new enumeration for enclave type parameter of `oe_create_enclave`. Now use
  `OE_ENCLAVE_TYPE_AUTO` to have the enclave appropriate to your built environment
  be chosen automatically. For instance, building Intel binaries will select SGX
  automatically, where on ARM it will pick TrustZone.

### Changed

- `oe_create_enclave` takes two additional parameters: `ocall_table` and
  `ocall_table_size`.
- Update mbedTLS library to version 2.7.9.
- Update MUSL libc to version 1.1.20.
- Update LLVM libcxx to version 7.0.0.
   - Some libcxx headers (e.g. `<string>`) now use C++11 template features and
     may require compiling with the `-std=c++11` option when building with GCC.
- Update minimum required CMake version for building from source to 3.13.1.
- Update minimum required C++ standard for building from source to C++14.
- Moved `oe_seal_policy_t`, `oe_asymmetric_key_type_t`, `oe_asymmetric_key_format_t`,
  and `oe_asymmetric_key_params_t` to `bits/types.h` from `enclave.h`.
- Changed minimum required QE ISVSVN version from 1 to 2 for the QE Identity
  revocation check that is performed during quote verification. Remote reports
  that were generated with a QE ISVSVN version of 1 will fail during report
  verification now. To resolve this issue, please install the latest version
  of the Intel SGX DCAP packages on the system that generates the remote report,
  which as of the time of this change is version 1.0.1 and can be found here:
  https://download.01.org/intel-sgx/dcap-1.0.1/dcap_installer/ubuntuServer1604/
- Revamped `oesign` CLI tool arguments parsing. Instead of relying on the arguments
  order and name, named parameters are used as such:
   - The `sign` subcommand accepts the following mandatory flags:
     - `--enclave-image [-e]`, the enclave image file path
     - `--config-file [-c]`, the path of the config file with enclave properties
     - `--key-file [-k]`, the path of the private key file used to digitally sign the enclave image
   - The `dump` subcommand accepts only the `--enclave-image [-e]` mandatory flag, for the enclave file path.

### Deprecated

- String based `ocalls`/`ecalls`, `OE_ECALL`, and `OE_OCALL` macros.
- `OE_ENCLAVE_TYPE_UNDEFINED` was removed and replaced with `OE_ENCLAVE_TYPE_AUTO`.

### Fixed

- Check support for AVX in platform/OS before setting SECS.ATTRIBUTES.XFRM in enclave.

[v0.4.1] - 2018-12-21
---------------------

v0.4.1 contains a small fix to work with Intel's new ISV version bump.

### Changed

- This allows the OE SDK to continue to support reports signed by QE SVN=1,
  and at the same time also allow a newer QE SVN (greater than 1) during the
  oe_verify_report process.

[v0.4.0] - 2018-10-08
---------------------

v0.4.0 is the first public preview release, with numerous breaking changes from v0.1.0
as listed below.

### Added

- Support building Open Enclave SDK apps with Clang-7.
- Support Intel EDL for host & enclave stub generation with oeedger8r tool.
- Support full SGX DCAP remote report (quote) revocation.
- Expand documentation for running on different configurations.
- Add pkg-config files for building Open Enclave apps in C/C++ for GCC or Clang.
- Add data sealing sample.
- Add `oe_call_host_by_address()` to allow enclaves to make OCALLs by callback pointer.
- Add `oe_get_enclave()` to obtain enclave handle to return to host.
- Add `oe_get_target_info()` to support SGX local attestation.
- Add CMake export configuration to SDK (experimental).

### Changed

- Standardize naming convention on new [Development Guide](docs/DevelopmentGuide.md).
- Standardize Open Enclave APIs to use `size_t` type for buffer sizes.
- Standardize Open Enclave APIs to always clear output parameters on error return.
- Change report type detection logic.
   - Reports generated by Open Enclave are no longer transparently usable by Intel SGX SDK.
- Change `oe_identity.authorID` field to `oe_identity.signerID`.
- Clean up thread local storage on return from ECALL.
- Refactor liboecore and liboeenclave dependency.
   - All enclave apps must now link liboeenclave.
- Refactor liboecore and liboelibc dependency.
   - All enclave apps should call libc for C functions instead.
- Break up remote attestation sample into 4 separate samples.
- Simplify `oe_get_report()` so it doesn't accept unused `reportdata` on host side.
- Reduce the set of `oe_result` values returned.
- Update mbedTLS library to version 2.7.5.
- Update LLVM libcxx to version 6.0.1.
- Update MUSL libc to version 1.1.19.
- Update libunwind to version 1.3.

### Deprecated

- Deprecate oe_call_host and oe_call_enclave methods in favor of EDL generated interfaces.

### Removed

- Block re-entrant ECALLs. A host servicing an OCALL cannot make an ECALL back into the enclave.
- Remove oe_thread functions. All enclave apps should use libc/libcxx thread functions instead.
- Remove API reference from SDK package. Refer to https://openenclave.io/apidocs/v0.4 instead.
- Remove outdated documents including DesignOverview.pdf.
- Remove oegen, oedump and oeelf tools.
- Remove CMake-based samples.
- Replace test signing PEM files with runtime generated test keys.

### Fixed

- Add appropriate validations for ELF64 in Open Enclave loader.
- Expand libc/libcxx test coverage.

### Security

- Build all libraries with Clang-7 Spectre-1 mitigation (-x86-speculative-load-hardening).
- Update code to use safe CRT and secure memset/zero memory methods.
- Fix integer overflows and add arithmetic boundary checks in Open Enclave runtime.
- Fix cert chain validation during Open Enclave quote verification.

[v0.1.0] - 2018-06-15 (YANKED)
------------------------------

Initial private preview release, no longer supported.

[Unreleased]: https://github.com/microsoft/openenclave/compare/v0.4.0...HEAD
[v0.4.0]: https://github.com/microsoft/openenclave/compare/v0.1.0...v0.4.0
[v0.1.0]: https://github.com/microsoft/openenclave/compare/beb546f...v0.1.0
