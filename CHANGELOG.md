# Opkg Changelog

This changelog for the opkg project attempts to conform to the [KeepAChangelog](https://keepachangelog.com/en/1.0.0/) standard.

For a historic list of changes from when the project was called "Ipkg", see the [`:docs/CHANGELOG.ipkg`](./docs/CHANGELOG.ipkg) file.


## opkg-0.6.2

### Changed
- [Majorly restructured](https://groups.google.com/g/opkg-devel/c/NUP1Xeii2To) the project's developer documentation to be more correct and current.

### Fixed
- [Fixed](https://git.yoctoproject.org/opkg/commit/?id=cee294e72d257417b5e55ef7a76a0fd15313e46b) a bug in the `opkg-keys` utility script which caused the script to ignore settings in the `/etc/opkg/gpg/gpg.conf` file.
- [Fixed](https://git.yoctoproject.org/opkg/commit/?id=19e2a38c27cd98df9e5d5d959bba80136b77fa01) a compilation error in `md5.c` when using clang16+ and `-std >= gnu11`.


## opkg-0.6.1

### Changed
- Opkg will no longer complain when trying to clean up the temporary directory, if the directory does not exist.

### Fixed
- Fixed a SEGFAULT when parsing package indexes with invalid `Size` or `Installed-Size` fields. These indexes will now produce a comprehensible error.
- Fixed an inconsistecy in .list generation where files would sometimes be entered with/without a trailing slash. The trailng slash should now always be removed.
- Fixed [a bug](https://bugzilla.yoctoproject.org/show_bug.cgi?id=10461) in package removal, where empty common directories would be left on disk, even after all owning packages were removed.


## opkg-0.6.0

### Changed
- When using package signature verification, the signature file is now only downloaded when (a) it is not present in the local cache or (b) the package file must be downloaded again. This makes signature verification more reliable in cases where the connection to the package feed is unreliable, or stored on a removable device that is not always connected.
- Package `pre-depends` are now recorded in the opkg `status` file.
- Package `pre-depends` are now considered when removing packages. Opkg will now (correctly) fail, when the user asks to remove a package which is a pre-depends of another installed package.
- libsolv will now return a solver error if the user asks to install a package which does not exist in the feeds.
- The `opkg search` command now prints a newline character at the end of its output when the search path cannot be found - which looks a little nicer when using opkg interactively.


## opkg-0.5.0

### Added
- Added support for zstandard data compression (disabled by default).

### Changed
- Opkg will no longer attempt to remove the cache directory, if it already doesn't exist. This avoids a spurious error in that case.
- Increased minimum libsolv version from `0.6.25` to `0.7.14`, which adds support for blacklisting packages during the solve.
- Use libsolv's package blacklisting feature when `--add-exclude` is requested by the user, so that libsolv can provide a more meaningful error message in the case of solve failures.
- `opkg` will now return a non-zero error code and an error message when `opkg search` returns no results - which is more consistent with dpkg behavior.
- `opkg_archive` will now propagate error messages and error codes from libarchive, when archiving operations fail.
- `opkg` operations now use volatile cache directories which are namespaced by their process ID, enabling multiple read-only operations to exist concurrently.

### Removed
- Removed pathfinder x509 certificate checking, because the feature doesn't seem to be used by the community and the library is obsolescent.
- Removed openssl signature verification, because the feature doesn't seem to be used by the community and GPG feed signing should be preferred.

### Fixed
- Fixed a couple of GCC 8 compiler warnings regarding dangerous string operations in libopkg.
- Fixed a GCC 8 compiler warning about unused variables in `opkg_download_curl.c`.
- Fixed a GCC 8 compiler warning about parameter visibility in `opkg_solver_libsolv.c`.


## opkg-0.4.5

- Allow CLEAN_DATE to be derived from SOURCE_DATE_EPOCH (build reproducibility)
- Announce the deprecation of x509 signature checking through OpenSSL in the next release.


## opkg-0.4.4

- Drop feed path when manually downloading packages (issue 11301)
- Send error information to stderr/stdout immediately, by disabling buffering (issue 13985)
- Do not require root privileges for read-only operations (issue 9348)
- Fix segfault when parsing packages with long descriptions, but no summary (issue 13575)
- Only check feed signature once
- Make opkg download return -1 (instead of 0) if a package is missing
- Clear curl properties to avoid a failed call pollute next calls
- Testsuite: standardize styline and spacing at 4 (PEP 8)
- Make opkg_assert comply with reproducible builds rules
- Make opkg and opkg.conf man pages and cli help consistent and correct

#### libsolv Solver

- Do not download packages if --noaction is used with download_first=1


## opkg-0.4.3

- Do not populate install status if package is not installed (issue 13760)
- Add glob support for --add-ignore-recommends and --add-exclude (issue 13759)
- Fix possible bad memory access in file_read_line_alloc
- Allow upgrades between packages with different names
- Remove extra slash on dest struct variables
- Prevent double free on opkg_conf_load

#### libsolv Solver

- Show all solver problems and not only an educated guess
- Ignore missing recommends of installed packages (issue 13758)


## opkg-0.4.2

- Follow symlinks during install (issue 13574).
- Add support for empty payloads. Before, an empty payload would segfault opkg.
- Add new opkg verify option, to check system status.
- Add SPDX license identifiers to source files.
- Speed up opkg clean by avoiding loading feed/status information.
- Fix static build (issue 8355).
- Add missing pkg->tags initialization (issue 13380).


## opkg-0.4.1

- Improve support for Debian-based repos (issue 13185).
- Add target for testsuite installation.
- Add --add-ignore-recommends option to ignore specific recommendations.
- Check download file size when checking file hash, to insulate verification from hash collisions.
- Abort operations on download error.
- Move gpg homedir to /etc/opkg/gpg to decouple opkg from gpg internals. This is a breaking change if gpg is enabled and opkg is upgraded. You can use the conf option "option gpg dir /etc/opkg" to revert back to the old directory layout.
- Avoid window with overly permissive umask when creating directory hierarchy

#### libsolv Solver

- Make --no-install-recommends case libsolv flags consistent with the canonical case.


## opkg-0.4.0

- Remove support for long options with only one leading dash.
- Use strict matching, instead of globs, when removing maintaner scripts (issue 12905).
- Speed up opkg installed files algorithm (issue 12648). This was a regression from 0.3.4.
- Add support for lz4 compression.
- Add --fields command line argument, to customize 'info' and 'status' output.
- Add --short-description, to limit the output of 'info' and 'status'.
- Error out if feeds only have sha256 sums, but --enable-sha256=false.
- Clean up command line help and man page.

#### libsolv Solver

- Use arch when finding a package match. Before it was only using name and version, which lead to incorrect results if a feed had two packages with the name and version, but different arch.
- Make sure Essential package dependencies are not removed.
- Abort installation on first failure.


## opkg-0.3.6

- Optimize access to packagename.list file
- Add compress_list_files option to optimize disk space (issue 11912)
- Avoid duplicated entries on status file, due to stale package index (issue 8351)
- Miscelaneous fixes to make opkg compatible on more paltforms.

#### Internal Solver

- Enable upgrades of installed packages that Provide a virtual package already installed (issue 11926, regression from 0.3.4)

#### libsolv Solver

- Add list-upgradable support (issue 8165)
- Run maintainer scripts in correct order when upgrading virtual packages (issue 11362)
- Make missing packages solvable non-version constrained


## opkg-0.3.5

- Handle conffiles that don't exist gracefully (show notice instead of error)
- Correctly handle symlink files collisions (issue 11033)
- Add verbose_status_file option to store all the package metadata in the status file
- Add support for user-defined control file fields
- Enhance PATH handling for intercepts
- Explicitly run scripts and intercepts with /bin/sh instead of sh
- Run maintainer scripts by default in the ATS
- Add support for installing packages with version constrains other than '='

#### Internal Solver

- Do not process orphans in download-only case (issue 10243)
- Remove duplicate processing of provides and replacees
- Only install one provider for each virtual package (issue 10781)
- Skip dependency error message if --force-depends (issue 9060)

#### libsolv Solver

- Allow removal of recommended packages, in case of conflict (issue 10777)
- During upgrades, also upgrade Recommends (issue 9939)
- Print solver errors to stderr (issue 10407)
- Add dist-upgrade support


## opkg-0.3.4

- Improve GPG signature check by making sure the signature is not only correct, but has an approved level of trust on the trusted database.
- Add support for xz and bzip2 compressed payloads.
- Handle 'opkg remove' and 'opkg install' (libsolv) correctly for packages in SS_HALF_INSTALLED state due to a previously failed installation (issues 10358 & 9901).
- Remove redundant requirement to have check_signature enabled when check_pkg_signature is enabled (issue 10361)
- Add Installed-Size field to status file (issue 9906)
- Do not overwrite existing directory permissions on install (issue 9987)
- Add per-feed signature verification toggle (issue 10150)
- Add validation to opkg flag call (issue 8356)
- Add "find" command which searches package names and descriptions (e.g. opkg -i find "*autoconfig*")
- Add --force-checksum cmdline flag to be able to ignore mismatching md5sums (issue 8357)
- Expose lists_dir option as command line argument
- Extend 'opkg list' command to optionally display package size
- Add gzip support for tar.gzipped ipk packages.
- Make the /var and /etc directories configurable at compile time.
- Replace active_list structure with basic list type.

#### Internal Solver

- Fix incorrect removal of packages during download only operations (issue 10182)

#### libsolv Solver

- Enable globs for install, remove and upgrade operaionts (issue 9792)
- Set libsolv version comparision to be Debian-compatible, instead of RPM-compatible.
- Allow package names to be matched against provides
- Display libsolv version in --version output, if enabled


## opkg-0.3.3

- Fix build breakage when using configure option --enable-sha256. Regression from 0.3.1

#### Internal Solver

- Do not upgrade installed dependencies if version constrains are meet (issue 9802).
- Do not remove packages if removal operation is not valid due to installed dependents (issue 9862). Regression from 0.3.1.


## opkg-0.3.2

- Remove configure script --enable-solver. To enable libsolv, add config option --with-libsolv.
- Add version constrain support for Replaces (issue 8931)
- Add targeted install support, enabling installation of a specific version of a package when multiple available (issue 76).
- Remove functions no longer used.
- Fix compare-version functionality (issue 166).
- Add disable_intercepts option (issue 8837)
- Add support for UTF-8 Package files (issue 9557)

#### libsolv Solver

- Add pkg-config support
- Add --download-first option
- Fix crash when using more than 4 arch config options.

#### Internal Solver

- Split internal solver from install/upgrade/remove transactions. Solving now happens first, instead of at the same time as installation/removal. New architecture fix issues 156 and 162.
- Abort installation if pkg A B is installed, and pkg A (Provides B, Conflicts B) is set to be installed (issue 9533)
- Skip dependency if a Provider is already installed (issue 9059)
- Fix status file corruption (issue 8601)
- Mark top level package as not AutoInstalled, when circular dependencies are present (issue 167)
- Fix upgrade error when package A replaces provider B, and B is provided by A.


## opkg-0.3.1

- Libsolv backend support. Add --enable-solver=libsolv config option to have opkg use the external solver libsolv. This feature is fully functional, but in experimental stage.
- Cache filenames are now based on the path md5sum instead of the full path, to fix errors on long filepaths.
- Fix several memory leaks
- Add --host-cache-dir and --cache-dir command line flag to change the cache directory location
- Fix error when processing empty Package.gz files.


## opkg-0.3.0

- Fix exit status when upgrading multiple packages with inter-dependencies (issue 154).


## opkg-0.3.0-rc2

- Ensure `libopkg/xfuncs.h`, `tests/` and `scripts/` are included in the release archive!


## opkg-0.3.0-rc1

- Reformat all C code so that it is easier to read (issue 119).
- Fix a few minor logic bugs.
- Tidy up `autogen.sh` and ensure it runs correctly with old versions of `aclocal` and non-bash shells.
- Rearrange test scripts into logical categories.
- Fix segfault when reinstalling a package with `force_reinstall` set (issue 153).


## opkg-0.3.0-rc0

- opkg now depends on libarchive.
- Rename `opkg-cl` to `opkg`.
- Add config option `autoremove` equivalent to `--autoremove` command line flag.
- Add config option `overwrite_no_owner` allowing un-owned files to be overwritten during package install (issue 99).
- Add config options `connect_timeout_ms`, `transfer_timeout_ms` and `follow_location` for use with CURL.
- Add command line option `--volatile-cache`.
- Add config option `no_install_recommends` and command line option `--no-install-recommends` to prevent the installation of packages listed as Recommends.
- Add command line option `--add-exclude` to add packages to an exclusion list.
- Add config option `ignore_maintainer` to silently ignore changes to files listed as Conffiles during a package upgrade (issue 128, part 2).
- Add config option `lock_file`. This option replaces the configure script argument `--with-opkglockfile`, allowing the lock file path to be specified at run-time.
- Add config options `info_dir` and `status_file`. Together with the config option `lists_dir` which existed previously, these options replace the configure script argument `--with-opkglibdir`, allowing the paths to the the data files and directories to be specified at run-time and with better granularity.
- Add config option `signature_type` allowing the signature verification backend to be selected at runtime. Both openssl and gpg support may not coexist within a single build of opkg.
- Add config option `check_pkg_signature` which allows individual package files to be signed and verified.
- Add config option `cache_local_files` to copy local files into the cache when downloading. If this option is not set, any URL with a `file://` is symlinked into the cache rather than downloaded (issue 139).
- Drop support for the old `lists_dir` config option syntax. The new syntax introduced in v0.2.3 must now be used.
- Add support for passing package filename arguments to `opkg info` (issue 125).
- Add support for implicit and explicit FTP-over-SSL when using the curl download backend.
- Add support for a https proxy using the curl download backend.
- Add support for http basic authentication when using the CURL download backend.
- Add support for ASCII-armored gpg signatures.
- Change the default cache directory to `/var/cache` (issue 131).
- Improve package and package feed verification.
- Improve download caching.
- Improve heuristics to determine whether an argument is a package name, remote URI or local path.
- Improve detection and handling of package conflicts.
- Improve handling of package flags (such as hold) and status.
- Improve proxy authentication when using the curl download backend.
- Allow interrupted downloads to be resumed when curl is enabled (issue 115).
- Only upgrade installed packages during `opkg upgrade` (issue 127).
- Correctly handle pacakges which list a virtual package in Provides, Replaces and Conflicts (issue 89).
- Ensure that the lock file can be created by creating the parent directory if it does not already exist (issue 110).
- Issue a NOTICE message not an ERROR message if files listed as Conffiles have been changed by the user prior to a package upgrade but the `force_maintainer` option has not been set (issue 128, part 1).
- Call prerm and postrm scripts on package upgrade (issue 104).

#### opkg-key

- Only install `opkg-key` when gpg support is enabled.
- Add `opkg-key reset` command to remove all trusted keys.
- Add `opkg-key populate` command to populated the list of trusted keys using the contents of `/usr/share/opkg/keyrings`.
- Improve usage output of `opkg-key`.

#### update-alternatives

- `update-alternatives` has been moved out of opkg and into opkg-utils.

#### Developer visible

- Add functions `opkg_conf_get_option` and `opkg_conf_set_option`, direct access to `options` array is no longer allowed.
- Add documentation in `developer-doc` directory.
- Add `scripts/checkpatch.pl`, adapted from the Linux kernel. This script may be used to check that patches match the expected coding style and are free from some common mistakes.
- Remove confusing `from_upgrade` argument from `opkg_remove_pkg`.
- Drop the configure script arguments `--with-opkglockfile`, `--with-opkglibdir` and `--with-opkgtcdir`.
- Drop unnecessary source files under 'tests'.
- Deprecate the libopkg API defined in 'libopkg/opkg.c'. The configure script argument `--enable-libopkg-api` must be given to build this API.
- Improve testsuite with more tests, `make check` now runs the testsuite and exits non-zero if any test fails.
- Improve `autogen.sh` script for developers & maintainers, no longer runs configure directly. `./autogen.sh --clean` now removes all generated files without requiring configure to have been ran.
- Rename `conf` -> `opkg_config` to prevent global symbol clashes (issue 92).
- Allow pkg-config to be used to find the gpg-error library.
- Use libarchive to extract packages instead of hand-rolled tar, ar and gzip handling (adds dependency on libarchive).
- Remove libbb!
- Lots of code refactoring and minor improvements.


## opkg-0.2.4

- Improve handling of failed installs. Package status is now set to 'install reinst-required half-installed' and advice on how to rectify the situation is now given.
- Improve handling of upgrades, and fix detection of orphan packages. Orphan RECOMMENDS will now be removed during an upgrade, as well as orphan DEPENDS, if autoremove is enabled. However, packages which move from DEPENDS to RECOMMENDS will now be kept. (issue 144)
- Improve handling of package flags.
- Fix 'opkg whatconflicts'.
- Fix handling of '--force-removal-of-dependent-packages'. (issue 140)
- Fix selection between multiple providers of the same abstract package. (issue 152)
- Fix uname and gname caching during package extraction.
- Fix verification of release metadata files.
- Fix possible segfault in 'pkg_hash_fetch_conflicts()'.
- Use 'sh' instead of 'bash' as the interpreter for 'opkg-check-config'.


## opkg-0.2.3

- New, optional syntax for setting lists_dir in config files. This new syntax will be required in v0.3.0 and later, the old syntax is now deprecated. The new syntax is:
  ```
  option lists_dir <path>
  ```
- New 'opkg-check-config' helper script to check and update config files. Currently this just changes the old lists_dir syntax to the new syntax.
- Add the 'combine' option and '--combine' command line argument. These options combine the installation or upgrade of multiple packages so that dependency evaluation is carried out for the whole transaction rather than separately for each package. This resolves the case of issue 124 where multiple packages depend on a common package with version constraints in such a way that all dependent packages need to be upgraded together.
- Don't select packages for installation which break the dependencies of already installed packages (issue 124).
- Fix epoch:version split so that a colon is only interpreted as the epoch separator in a version string if it is the first non-numeric character.
- Fix package flags after failed upgrade. This ensures that subsequent installs or upgrades do not consider the old package as scheduled for removal.
- Prevent packages listed in RECOMMENDS of an installed package from being removed automatically when autoremove is set.
- Fix 'extern "C"' wrapping in header files.
- Improve check for gpgme in configure script. Now either pkg-config or gpgme-config can be used to find gpgme.
- Fix internal usage of 'config.h', this ensures building opkg and its dependencies with large file support will work correctly.
- Fix internal memory leaks and suboptimal code.


## opkg-0.2.2

- Fix '--force-reinstall' flag so that it acts as an upgrade rather than removing possibly critical packages before reinstall (issue 71)
- Symlinks are now correctly removed during package uninstall (issue 91)
- Fixed help and manual pages to reflect that shell globs not true regexps are accepted by opkg (issue 107)
- The error message "no valid architecture" is no longer given when the architecture of a package is valid but incompatible with the current system.


## opkg-0.2.1

- Updated AUTHORS, README, CONTRIBUTING, etc
- Dropped "config.h" from the list of installed headers and removed checks for HAVE_* symbols from all installed headers
- Made libopkg usable from C++ via `extern "C"` wrapping


## opkg-0.2.0

- No changes


## opkg-0.2.0-rc2

- Remove libopkg/config.h from the distribution archive, it's generated by configure and doesn't belong in there


## opkg-0.2.0-rc1

- Added basic regression test suite
- Added man pages for opkg-cl and opkg-key
- Added the `overlay_root` config option
- Added the `--prefer-arch-to-version` option
- Added the `--force-postinstall` option
- Added the `list-changed-conffiles` command
- Added the `opkg_compare_versions` function to libopkg
- Allow external gunzip binary to be used to perform decompression if the OPKG_USE_VFORK environment variable is set
- Do not read /etc/opkg/*.conf if -f option is specified
- Detect and handle circular dependencies
- Replaced GPLv3+ licensed sha256 implementation with GPLv2+ implementation
- Use `ln -snf` rather than `ln -sf` in update-alternatives
- Many other bugfixes, improvements and cleanups...
