# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as well as [SemVer Compatibility](https://doc.rust-lang.org/cargo/reference/semver.html) guidline.

<!-- 
Guiding Principles:

- Changelogs are for humans, not machines.
- There should be an entry for every single version.
- The same types of changes should be grouped.
- Versions and sections should be linkable.
- The latest version comes first.
- The release date of each version is displayed.

Types of changes:

- Added: for new features.
- Changed: for changes in existing functionality.
- Deprecated: for soon-to-be removed features.
- Removed: for now removed features.
- Fixed: for any bug fixes.
- Security: in case of vulnerabilities.
 -->

## [Unreleased]

### Added

- Added [CHANGELOG](https://github.com/amitrahman1026/wsdf/pull/2)
- Rust workspace resolver version '2' is added.
- Added option to specify type of wireshark plugin created, with a fallback to Epan type plugin

### Changed

- Pinning wireshark to [stable release 4.4.1](https://gitlab.com/wireshark/wireshark/-/tags/wireshark-4.4.1) for backported fixes on wireshark (e.g. Fixed CMake's python module finding [bugs](https://gitlab.com/wireshark/wireshark/-/commit/601bf39e6b2eaff9e77588ff1b1a8a987dad404d))
- The `tvb_get_guintX` and `tvb_get_gintX` functions in the tvbuff API has been renamed to `tvb_get_uintX` and `tvb_get_intX` (the GLib-style "g" has been removed). The old-style names have been deprecated.
- `#[derive(Protocol)]` will now correctly register dissector protocols with unique `proto_register_xxx` in line with breaking wireshark plugin API changes since release 4.2.x
- `plugin_describe()` will now be implemented to properly build a plugin since 4.2.x


## [0.1.0] - 2015-08-04

### Added

- Initial release of the project.

[unreleased]: https://github.com/amitrahman1026/wsdf
[0.1.0]: https://github.com/ghpr-asia/wsdf 
<!-- #TODO: Add release tag for current version of wsdf on ghpr -->
