# PizzaBun [_snakeCTF 2025 Finals_]

**Category**: Crypto
**Author**: crisis82

## Description

I've found a little note stuck on my PC, but are written only numbers. I wonder what it is...

## Solution

In the source code it's implemented the **GMiMC** cipher in _Expanding Round Function_ (ERF) mode and to the user it's given the digest of the GMiMC-hash applied to the flag.

The vulnerability of this challenge stands in the **number of rounds**, that is **too low** to provide enough security and allows cryptanalytical attacks.
To recover the flag, the user needs to implement a polynomial version of the cipher and build the system of polynomials that represents the digest. Now he's able to compute the Gröbner basis over this system and apply a root finding algorithm on top of it to recover the values of the variables corresponding to the plaintext.


[Here](./attachments/solve.sage) is the solver code.
