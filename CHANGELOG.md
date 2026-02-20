# Changelog

## [1.3.8](https://github.com/usetero/policy-go/compare/v1.3.7...v1.3.8) (2026-02-20)


### Bug Fixes

* respect disabled policies ([#36](https://github.com/usetero/policy-go/issues/36)) ([27dcd60](https://github.com/usetero/policy-go/commit/27dcd6088bb2b14756a6e602012575565dc72a11))
* support scope and resource fields ([#38](https://github.com/usetero/policy-go/issues/38)) ([e005452](https://github.com/usetero/policy-go/commit/e0054521e5336239d8f040e94a60a1ddae3d2ae8))

## [1.3.7](https://github.com/usetero/policy-go/compare/v1.3.6...v1.3.7) (2026-02-20)


### Bug Fixes

* use probability sampling ([#34](https://github.com/usetero/policy-go/issues/34)) ([0be5062](https://github.com/usetero/policy-go/commit/0be50623ee77ddeabccf7bf892372b8df87a8396))

## [1.3.6](https://github.com/usetero/policy-go/compare/v1.3.5...v1.3.6) (2026-02-19)


### Bug Fixes

* record misses and hits correctly ([#32](https://github.com/usetero/policy-go/issues/32)) ([0dbf3ba](https://github.com/usetero/policy-go/commit/0dbf3baee00b5874f9f5ba5368c928ecc15864f6))

## [1.3.5](https://github.com/usetero/policy-go/compare/v1.3.4...v1.3.5) (2026-02-18)


### Bug Fixes

* all policies post keep should be run if decision is matched ([#30](https://github.com/usetero/policy-go/issues/30)) ([a04c5de](https://github.com/usetero/policy-go/commit/a04c5deca3cec163a7e703eaae7d5f0b8ab8ddf9))
* negate not negated ([#29](https://github.com/usetero/policy-go/issues/29)) ([8c9deaa](https://github.com/usetero/policy-go/commit/8c9deaacf996e1fc6fa2de3410d493f3f92b82fd))
* rename transform fields ([#27](https://github.com/usetero/policy-go/issues/27)) ([13f2b86](https://github.com/usetero/policy-go/commit/13f2b861b3af05cd613275ecb601cf9190d34675))
* support enabled ([#31](https://github.com/usetero/policy-go/issues/31)) ([e2103b7](https://github.com/usetero/policy-go/commit/e2103b7088c4cbc3d68c723dfd37b6aebe10522c))

## [1.3.4](https://github.com/usetero/policy-go/compare/v1.3.3...v1.3.4) (2026-02-18)


### Bug Fixes

* don't emit null matchers for enum fields ([#25](https://github.com/usetero/policy-go/issues/25)) ([834da16](https://github.com/usetero/policy-go/commit/834da163662d11fa43017ff7d386fc70aaa6f963))

## [1.3.3](https://github.com/usetero/policy-go/compare/v1.3.2...v1.3.3) (2026-02-17)


### Bug Fixes

* http json incorrect encoding ([#23](https://github.com/usetero/policy-go/issues/23)) ([c33116f](https://github.com/usetero/policy-go/commit/c33116f379d66da2d546467cf75c0afb8c706134))

## [1.3.2](https://github.com/usetero/policy-go/compare/v1.3.1...v1.3.2) (2026-02-13)


### Bug Fixes

* metric and trace policy loading ([#21](https://github.com/usetero/policy-go/issues/21)) ([41db73c](https://github.com/usetero/policy-go/commit/41db73c135ea1db75dcbbb2f970c5e7cd02cec3a))

## [1.3.1](https://github.com/usetero/policy-go/compare/v1.3.0...v1.3.1) (2026-02-06)


### Bug Fixes

* support json format ([#18](https://github.com/usetero/policy-go/issues/18)) ([22bc40d](https://github.com/usetero/policy-go/commit/22bc40dc0dddf27d55632b6f04583b6d34c86484))

## [1.3.0](https://github.com/usetero/policy-go/compare/v1.2.0...v1.3.0) (2026-02-06)


### Features

* implement log transformations ([#16](https://github.com/usetero/policy-go/issues/16)) ([505d193](https://github.com/usetero/policy-go/commit/505d19341cc9e77d3a683fd5b1640c4446899600))


### Bug Fixes

* support matching enums ([#15](https://github.com/usetero/policy-go/issues/15)) ([38959ef](https://github.com/usetero/policy-go/commit/38959ef84d9f497f548f5db0584c5c7a8bd6faa4))

## [1.2.0](https://github.com/usetero/policy-go/compare/v1.1.0...v1.2.0) (2026-02-02)


### Features

* add span and metric support to policy go ([#13](https://github.com/usetero/policy-go/issues/13)) ([4f71f1f](https://github.com/usetero/policy-go/commit/4f71f1f139abee4de06d95d8b0afb3a9a80ab4f1))

## [1.1.0](https://github.com/usetero/policy-go/compare/v1.0.2...v1.1.0) (2026-01-30)


### Features

* upgrade to policy spec 1.2.0 ([#10](https://github.com/usetero/policy-go/issues/10)) ([16a865d](https://github.com/usetero/policy-go/commit/16a865dbfcadfdb68e2732a999c4f39af933d550))


### Bug Fixes

* ci validate ([#12](https://github.com/usetero/policy-go/issues/12)) ([be0ac94](https://github.com/usetero/policy-go/commit/be0ac944c09bfdb0694369a21595082ce7824696))

## [1.0.2](https://github.com/usetero/policy-go/compare/v1.0.1...v1.0.2) (2026-01-27)


### Bug Fixes

* add map structure tags ([#7](https://github.com/usetero/policy-go/issues/7)) ([625c5e3](https://github.com/usetero/policy-go/commit/625c5e328b0e28e904a7529a0cebacb355a5e982))

## [1.0.1](https://github.com/usetero/policy-go/compare/v1.0.0...v1.0.1) (2026-01-26)


### Bug Fixes

* interface needs to be generic, lower go version ([#5](https://github.com/usetero/policy-go/issues/5)) ([ebfe097](https://github.com/usetero/policy-go/commit/ebfe0977583a27f1f5fad7ce6e7ad3383d07e2c6))

## 1.0.0 (2026-01-26)


### Features

* instantiate http and grpc providers ([#4](https://github.com/usetero/policy-go/issues/4)) ([1a320be](https://github.com/usetero/policy-go/commit/1a320bed13e5fa8b38baecc4dfb42cb7bcdef441))
* instantiate module with a file policy provider ([#2](https://github.com/usetero/policy-go/issues/2)) ([ca5dc44](https://github.com/usetero/policy-go/commit/ca5dc442e0424fd812a33f1c01e867fbb035f1f7))
