# silly-fractions [_snakeCTF 2025 Finals_]

**Category**: reversing
**Author**: rw-r-r-0644

## Description

Just a bunch of fractions I guess. Have fun!

## Solution

Surprisingly enough, the simple rule of starting with an integer number and multiplying it by the first fraction in a list that yields an integer result is enough to build a Turing-complete system.
This formalism is known as Fractran, and was invented by none other than John Conway (the same person behind the much more well-known Game of Life, also somehow Turing complete xD).

It behaves kind of like a system of multiset term rewriting rules: prime numbers are the atoms, the exponent is the multiplicity, the denominator of a fraction is the set of preconditions of a rule, and the numerator is the set of postconditions.

Every time a rule is executed, the preconditions are removed from the state (dividing by the denominator), and the postconditions are added to the state (multiplying by the numerator).
It may be somewhat familiar if you ever had to deal with Tamarin or other similar formalisms.

We could represent these rules as something like this (in fact, this was extracted from an intermediate step we use to generate the challenge):
```
...
DoPerm, Input24^1 --> DoPerm1, State17^4
DoPerm, Input27^1 --> DoPerm1, State1^1
DoLoSubst15, State15^1 --> DoLoSubst31, Input15^3
DoPerm, Input35^1 --> DoPerm1, State17^64
DoHiSubst4, State4^0 --> DoLoSubst5, Input4^224
DoLoSubst25, State25^0 --> DoHiSubst45, Input25^7
CheckResult, Input47^8 --> CheckResult1, PMatch
...
```


By factoring the numerator and denominator of the rules we can recover a similarly looking set of term rewritings (ofc initially unlabeled).

How can we make sense of the gigantic list of unlabeled rewrite rules originating from the factorization of fractions in checker.frac?
A good approach is to start from the fairly limited set of atoms / prime factors (there should only be about ~211 atoms).
From the run.py file we know the meaning of at least the first 48 + 2 atoms (/ primes): these are used, respectively, for flag input bytes, the start state and the success state.

By looking at the value of these atoms as the program runs, we can see that the first 48 atoms aren't just used as input, but are actually kept around as some kind of cipher state.
There's also a suspicious looking rule with a gigantic numerator that involves all of the input atoms - looks a lot like a key addition!

If we track these two steps throughout the cipher, we can see that they are repeated 10 times, with a few intermediate steps involving powers-of-two exponents in between!
Indeed, what the fractions in checker.frac actually implement is a simple a 10-round SPN cipher with two 4-bit SBOXes (for the high/low nibble of each byte) and a permutation involving all of the 384 state bits.
The key and the encrypted flag are hardcoded into the program; once we have reconstructed what the cipher is doing, we have enough information to apply it in reverse and recover the flag!

```
def decrypt(block, key, rounds=10):
	state = bytearray(block)
	for i in range(rounds):
		state = apply_sbox4(state, SBOX1_INV, SBOX2_INV)
		state = apply_perm(state, PERM_INV)
		state = sub_round_key(state, key)
	return state
```