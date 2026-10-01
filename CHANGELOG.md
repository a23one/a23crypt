# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-02

### Changed

- The noise layer is vectorized with numpy for inputs of 320 bytes and up,
  making large-payload encrypt / decrypt ~6x faster (~44 → ~255 MiB/s on an
  Apple M4 Max). Smaller inputs keep the original implementation, so small
  records see no change. Run `benchmarks/bench_noise.py` to reproduce.
- Output is byte-identical to 0.1.0. The wire format is unchanged, and
  ciphertexts interoperate in both directions between 0.1.0 and 0.2.0.

### Added

- Runtime dependency on `numpy>=2.3.2`. Importing `a23crypt` now also
  imports numpy (~50 ms, once per process).

## [0.1.0] - 2026-05-01

Initial release.

[0.2.0]: https://pypi.org/project/a23crypt/0.2.0/
[0.1.0]: https://pypi.org/project/a23crypt/0.1.0/
