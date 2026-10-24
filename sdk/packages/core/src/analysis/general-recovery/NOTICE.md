# Wakaru recovery engine notice

This first-party adapter can invoke the unmodified upstream Wakaru 1.14.0
executable (Apache-2.0). It does not install or depend on REA.

- Upstream: https://github.com/pionxzh/wakaru
- Source revision: 8219bf5016a063d7fb215101a8c45d5959ec733f
- Official release: https://github.com/pionxzh/wakaru/releases/tag/v1.14.0
- Original license retained verbatim in WAKARU-LICENSE (SHA256
  c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4).
- Exact archive and executed-file hashes are recorded in contracts.ts. Build
  preparation validates both, refuses existing output roots and performs no
  package-manager install. The application must never run build preparation.

The fixed engine invocation now uses the existing shared Windows Job Object
supervisor (suspended assignment, 2 GiB job commit, four processes, independent
45-second owner wait). Linux uses a fixed OS prlimit entrypoint (2 GiB virtual
address space, CPU 45/46 seconds, 64 MiB per-file write limit) inside the existing
supervised process group. These are resource controls, not target-execution
permission or a filesystem/network sandbox. Linux wall cancellation still relies
on the living host; Windows' finite job-owner wait survives caller loss. The
2 MiB output inventory monitor remains an observed limit, not a disk quota.

The adapter is internal: public model routing, installed-resource packaging,
parent/descendant cancellation integration and saved/export receipt integration
are not complete. Its owned fixture is not a general recovery parity claim.
Single-input structural recovery uses minimal rewrites, retains source maps as
inert data, and separates transformed-module hashes from original-range hashes.
No target execution, original naming or runtime-equivalence claim is made.
