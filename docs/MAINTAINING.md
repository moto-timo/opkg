# Maintaining Opkg

This document contains policy documentation and helpful references for how this fork of the Opkg project is maintained and released.


## Version Policy

This fork follows the semantic versioning specification outlined [here](https://semver.org/spec/v2.0.0.html) as SemVer 2.0.

In short...
```
Given a version number MAJOR.MINOR.PATCH, increment the:

    1. MAJOR version when you make incompatible API changes
    2. MINOR version when you add functionality in a backwards compatible manner
    3. PATCH version when you make backwards compatible bug fixes

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.
```

**Public API.** For Opkg, the public API is the `opkg` CLI application; the opkg configuration files; the public API of the libopkg library; and the on-disk structure of OPK/IPK package files, status, and control files.