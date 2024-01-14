# KZG Polynomial Commitments

An implementation of [**KZ**ig**G** polynomial commitments](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf) in Zig, using [`blst`](https://github.com/supranational/blst) as the backend via Zig's C interop.

Heavily based on [c-kzg-4844](https://github.com/ethereum/c-kzg-4844).

_Disclaimer: this repository is me learning how KZG and 4844 works underneath and is not meant for real world use._

## Prerequisites

You need Zig installed and `blst` built to use as a static library.

## Test

```sh
zig build test -Doptimize=ReleaseSafe
```

## Benchmark

```sh
zig build benchmark
```
