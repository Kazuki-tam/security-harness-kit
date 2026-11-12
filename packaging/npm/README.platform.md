# @PACKAGE@

Prebuilt `shk` binary for `@TARGET@`.

This package is an implementation detail of
[`security-harness-kit`](https://www.npmjs.com/package/security-harness-kit),
which selects it automatically through `optionalDependencies`. Do not install
it directly:

```bash
npm install -g security-harness-kit
```

The binary is byte-identical to the one in the `@ARCHIVE@` asset of the matching
[GitHub release](https://github.com/Kazuki-tam/security-harness-kit/releases/tag/v@VERSION@).
The `shkBinary` field in `package.json` records the SHA-256 of that archive and
of the binary.
