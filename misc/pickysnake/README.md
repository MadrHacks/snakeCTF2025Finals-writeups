# Picky Snake [_snakeCTF 2025 Finals_]

**Category**: web

## Description

The Picky Snake is a very special snake that only eats certain types of food.
It has a very specific diet and will only eat food that meets its criteria.
Your task is to figure out what the Picky Snake likes to eat and feed it accordingly.

### Hints

No hints provided

## Solution

Challenge requires to manually craft a pickle, then exploit copyreg._inverted_registry to load arbitrary objects
A full exploit is [available](./attachments/solve.asm)

rasm2 -a pickle -f solve.asm -B