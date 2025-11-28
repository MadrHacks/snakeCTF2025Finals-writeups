# silly-fractions [_snakeCTF 2025 Finals_]

**Category**: reversing  
**Author**: rw-r-r-0644  

## Description

Just a bunch of fractions I guess. Have fun!
  
(attachment: silly-fractions.zip)

## Solution

Surprisingly enough, the simple rule of starting with an integer number and multiplying it by the first fraction in a list that yields an integer result is enough to build a Turing-complete system!  
This formalism is known as FRACTRAN, and was invented by none other than John Conway, the same person behind the much more well-known Game of Life (also somehow Turing complete xD) and a whole lot of other cool stuff.  

It behaves kind of like a system of multiset term rewriting rules: prime numbers are the atoms, their exponent is the multiplicity, the denominator of a fraction is the set of preconditions of a rule, and the numerator is the set of postconditions.  

Every time a rule is executed, the preconditions are removed from the state (dividing by the denominator), and the postconditions are added to the state (multiplying by the numerator). This may sound suspiciously familiar if you ever had to deal with protocols in Tamarin - the formalism used there is somewhat related.  

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


By factoring the numerator and denominator of the rules we can recover a similar looking set of term rewritings (ofc initially unlabeled).
If you want to have a go at analysing the set of term rewritings on your own, you can find some example analysis scripts to try and modify in rrules-analysis.zip (you can have a peek at silly-fractions.checker.map if you get stuck) - otherwise keep on reading ^^
  
How can we make sense of the gigantic list of unlabeled rewrite rules originating from the factorization of fractions in checker.frac?
A good approach is to start from the fairly limited set of atoms / prime factors (there should only be about ~211 atoms).
From the run.py file we know the meaning of at least the first 48 + 2 atoms (/ primes): these are used, respectively, for flag input bytes, the start state and the success state.

By looking at the value of these atoms as the program runs, we can see that the first 48 atoms aren't just used as input, but are actually kept around as some kind of cipher state.
There's also a suspicious looking rule with a gigantic numerator that involves all of the input atoms - looks a lot like a key addition!

If we track this step throughout the cipher, we can see that it is actually repeated 10 times, with a few intermediate steps involving powers-of-two exponents in between.
Indeed, what the fractions in checker.frac actually implement is a simple a 10-round SPN cipher operating on a 48 /byte state, with each round composed of:

 * a 48-byte fixed key addition modulo 256
 * two 4-bit SBOXes applied respectively to the high and low nibble of each byte of the state
 * a 384-bit permutation

If you need more information about how any of the cipher steps are taking place, you can find the labelled rewrite rules without randomization and the scripts we used to generate them in rrules-generation.zip

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

In solver.zip you can find a sample solve script which extracts the key and encrypted flag for any given checker.frac, decrypts the flag and prints it out to screen - normally you only need to extract the key and encrypted flag of your specific checker.frac, so there are some extra steps which may normally be omitted.

Hope you had fun! Thanks for playing :3