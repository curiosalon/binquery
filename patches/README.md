# Pinned Unicorn macOS repair

`unicorn-2.1.4-darwin-cache.patch` prevents the Linux ARM cache-register fallback
from running on macOS. When a sandbox denies `hw.cachelinesize`, that fallback
executes privileged `MRS CTR_EL0` and dies with SIGILL during `mem_map`, before
guest execution. On macOS, retain Unicorn's existing conservative alignment
fallback. Actual instruction-cache invalidation already uses Apple's
`sys_icache_invalidate`, not the guessed alignment. Guest instruction semantics
are unchanged. No sandbox permission is expanded.

Source: [Unicorn 2.1.4 cache detection](https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/util/cacheinfo.c)
and [Apple cache invalidation path](https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/tcg/aarch64/tcg-target.h).

Apply to the PyPI 2.1.4 source distribution with `patch -p1`. Build with CMake,
`-DCMAKE_BUILD_TYPE=Release -DUNICORN_BUILD_TESTS=OFF -DUNICORN_ARCH=x86`.
Copy the resulting dylib into the source distribution's `prebuilt/` directory
and build its normal wheel with `SETUPTOOLS_SCM_PRETEND_VERSION=2.1.4+darwin1`.
The qualified wheel is for Binquery's IA-16 and AMD64 paths only. Keep the stock
package available for rollback. Install only into Binquery's own environment.
The local version is included in checkpoint identity, so stock checkpoints stay
readable but are not silently resumed with a changed native engine.
