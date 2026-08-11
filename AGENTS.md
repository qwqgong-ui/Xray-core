# Repository build instructions

- Build Linux AMD64 production and release binaries with `GOAMD64=v4` by default.
- Name Linux AMD64 release artifacts `linux-amd64-v4` so the required CPU level is explicit.
- Do not downgrade production builds below `GOAMD64=v4` unless the user explicitly requests compatibility.
- Keep generic `GOAMD64=v1` builds only when backward compatibility is explicitly required.
