# Repository build instructions

- Before building or deploying Linux AMD64, detect the target CPU's supported x86-64 microarchitecture level.
- Use `GOAMD64=v4` when the target supports AVX-512F, AVX-512BW, AVX-512CD, AVX-512DQ, and AVX-512VL; otherwise use `GOAMD64=v3`.
- Name Linux AMD64 release artifacts `linux-amd64-v4` so the required CPU level is explicit.
- The Japan production server supports v4 and should use `GOAMD64=v4` unless its CPU changes.
- Keep generic `GOAMD64=v1` builds only when backward compatibility is explicitly required.
