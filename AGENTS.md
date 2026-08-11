# Repository build instructions

- Build Linux AMD64 production and release binaries with `GOAMD64=v3` by default.
- Name Linux AMD64 release artifacts `linux-amd64-v3` so the required CPU level is explicit.
- Do not build or deploy `GOAMD64=v4` unless the user explicitly requests it.
- Keep generic `GOAMD64=v1` builds only when backward compatibility is explicitly required.
