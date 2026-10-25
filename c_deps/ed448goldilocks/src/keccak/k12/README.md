# K12 ARM SHA3 leaf kernels

`KeccakP-1600-ARMv8Asha3.S` is unmodified from
https://github.com/XKCP/K12 at `f95b0b73e29fe75fe99fbbb24c8000d9fcf0b40e`
(2026-10-25). SHA256: 10d5af1f561b2b1c8865622beee2525f090906f4ad39bb495ccfe72f106b53f3.

The embedded CC0 notice is retained. This supplies register-resident KT128/KT256
2-leaf kernels and a 12-round absorb fast loop. The shared 24-round primitives
continue to use XKCP; these entry points have distinct symbol names.
