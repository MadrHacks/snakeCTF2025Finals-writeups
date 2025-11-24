#!/usr/bin/env sage

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

class GMiMC:
    def __init__(self):
        self.setParams()
        self.genConstants()

    def setParams(self):
        self.exp = 3
        self.p = 60167
        self.state_size = 8
        self.bytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.rounds = 5

    def genConstants(self):
        shake = SHAKE256.new()
        shake.update(b"my_super_secret_seed")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.bytes), "big")))
        self.constants

    def compose(self, state):
        padded_message = b''
        for s in state:
            padded_message += long_to_bytes(int(s))
        message = unpad(padded_message, self.state_size * self.n_states)
        return message

    def exponentiate(self, state):
        for i in range(self.n_states):
            state[i][0] = state[i][0]^self.exp
        return state

    def erf(self, state, round):
        for i in range(self.n_states):
            for j in range(1, self.state_size):
                state[i][j] = state[i][j] + state[i][0] + self.constants[round]
            state
        return state

    def leftRotation(self, state):
        for i in range(self.n_states):
            state[i] = state[i][1:] + state[i][:1]
        return state

    def round(self, state, round):
        state = self.exponentiate(state)
        state = self.erf(state, round)
        state = self.leftRotation(state)
        return state

    def perm(self, state):
        for i in range(self.rounds):
            state = self.round(state, i)
        return state


class GMiMCPoly(GMiMC):
    def  __init__(self):
        super().__init__()

    def initVariables(self):
        variables = []
        for i in range(self.n_states):
            for j in range(self.state_size):
                variables.append(var(f"s{i}_{j}"))
        self.R = PolynomialRing(self.F, variables)
        self.R.inject_variables(verbose=False)
        varis = []
        for i in range(self.n_states):
            vs = []
            for j in range(self.state_size):
                vs.append(self.R(variables[i*self.state_size + j]))
            varis.append(vs)
        return varis

    def unhash(self, digest):
        variables = self.initVariables()
        output = self.perm(variables)
        equations = []
        for i in range(self.n_states):
            eq = []
            for j in range(self.state_size):
                eq.append(output[i][j] - digest[i][j])
            equations.append(eq)
        return equations

def solve(equations):
    solutions = []
    for eq in equations:
        fact = list(factor(eq))
        var = str(eq.lm().variables()[0])
        val = eval(str(fact[0][0]).replace(var, "(0)").replace("^", "**")) * -1
        solutions.append(val)
    return solutions

if __name__ == "__main__":
    gmimc = GMiMCPoly()

    with open("note.txt", "r") as f:
        digest = eval(f.readline())

    gmimc.n_states = len(digest)
    for i in range(gmimc.n_states):
        for j in range(gmimc.state_size):
            digest[i][j] = gmimc.F(digest[i][j])

    equations = gmimc.unhash(digest)

    simplified_equations = []
    for eq in equations:
        I = gmimc.R.ideal(eq)
        simplified_equations += I.groebner_basis()

    solutions = solve(simplified_equations)
    flag = gmimc.compose(solutions)
    print(flag.decode())
