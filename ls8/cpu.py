"""CPU functionality."""

import sys

LDI = 0b10000010
PRN = 0b01000111
HLT = 0b00000001
ADD = 0b10100000
SUB = 0b10100001
MUL = 0b10100010
PUSH = 0b01000101
POP = 0b01000110
CALL = 0b01010000
RET = 0b00010001
CMP = 0b10100111
JMP = 0b01010100
JEQ = 0b01010101
JNE = 0b01010110

###  INVENTORY OF FILES ###

# cpu.py - CPU class and methods
# ls8.py - Instatiation of CPU class,
# CPU.load() and CPU.run() methods

### Needs to be implemented or removed: ##
# DAY 1:
#  X properties in CPU class
#  X ram_read()
#  X ram_write()
#  X run()
#  X HLT
#  X LDI
#  X PRN

# DAY 2:
# X remove hardcoded programs
# X implement load()
# X MUL

# DAY 3:
# X Clean up run()
# X System Stack

# DAY 4:
# X implement CALL and RET

# Sprint Challenge:

# X Add CMP Instruction

# X Add JMP Instruction

# X Add JEQ and JNE Instructions

############################


class CPU:
    """Main CPU class."""

    def __init__(self):
        """Construct a new CPU."""
        self.reg = [0] * 8  # Register
        self.reg[7] = 0xF4  # Stack Pointer, reg[7] reserved
        self.ram = [0] * 256  # Random Access Memory(RAM)
        self.pc = 0  # Program Count
        self.is_cpu_running = True
        # Flags bits (ex. 00000LGE, L = (<), G = (>), E = (==))
        self.fl = [0] * 8
        # Implement Branchtable
        self.branch_table = {}
        self.branch_table[LDI] = self.op_LDI
        self.branch_table[PRN] = self.op_PRN
        self.branch_table[ADD] = self.op_ADD
        self.branch_table[SUB] = self.op_SUB
        self.branch_table[MUL] = self.op_MUL
        self.branch_table[HLT] = self.op_HLT
        self.branch_table[PUSH] = self.op_PUSH
        self.branch_table[POP] = self.op_POP
        self.branch_table[CALL] = self.op_CALL
        self.branch_table[RET] = self.op_RET
        self.branch_table[CMP] = self.op_CMP
        self.branch_table[JMP] = self.op_JMP
        self.branch_table[JEQ] = self.op_JEQ
        self.branch_table[JNE] = self.op_JNE

    def load(self, name_of_file):
        """Load a program into memory."""
        try:
            address = 0
            with open(name_of_file) as f:
                for ln in f:
                    split_cmt = ln.split("#")
                    num_str = split_cmt[0].strip()

                    if num_str == '':
                        continue

                    num_val = int(num_str)
                    num_val = eval(f"0b{num_val}")
                    self.ram_write(address, num_val)
                    address += 1

        except FileNotFoundError:
            print(f'{sys.argv[0]}: could not find {sys.argv[1]}')
            sys.exit(1)

    def alu(self, op, reg_a, reg_b):
        """ALU operations."""

        if op == "ADD":
            self.reg[reg_a] += self.reg[reg_b]
        # elif op == "SUB": etc
        elif op == "SUB":
            self.reg[reg_a] -= self.reg[reg_b]
        elif op == "MUL":
            self.reg[reg_a] *= self.reg[reg_b]
        elif op == "CMP":
            if self.reg[reg_a] == self.reg[reg_b]:
                self.fl[7] = 1  # set "E" flag to true
                self.fl[6] = 0
                self.fl[5] = 0
            elif self.reg[reg_a] < self.reg[reg_b]:
                self.fl[5] = 1  # set "L" flag to true
                self.fl[6] = 0
                self.fl[7] = 0
            elif self.reg[reg_a] > self.reg[reg_b]:
                self.fl[6] = 1  # set "G" flag to true
                self.fl[5] = 0
                self.fl[7] = 0
        else:
            raise Exception("Unsupported ALU operation")

    def trace(self):
        """
        Handy function to print out the CPU state. You might want to call this
        from run() if you need help debugging.
        """

        print(f"TRACE: %02X | %02X %02X %02X |" % (
            self.pc,
            # self.fl,
            # self.ie,
            self.ram_read(self.pc),
            self.ram_read(self.pc + 1),
            self.ram_read(self.pc + 2)
        ), end='')

        for i in range(8):
            print(" %02X" % self.reg[i], end='')

        print()

    def ram_read(self, MAR):
        return self.ram[MAR]

    def ram_write(self, MAR, MDR):
        self.ram[MAR] = MDR

    def op_LDI(self, arg_A, arg_B):
        self.reg[arg_A] = arg_B
        self.pc += 3

    def op_PRN(self, arg_A, arg_B):
        print(self.reg[arg_A])
        self.pc += 2

    def op_ADD(self, arg_A, arg_B):
        self.alu("ADD", arg_A, arg_B)
        self.pc += 3

    def op_SUB(self, arg_A, arg_B):
        self.alu("SUB", arg_A, arg_B)
        self.pc += 3

    def op_MUL(self, arg_A, arg_B):
        self.alu("MUL", arg_A, arg_B)
        self.pc += 3

    def op_PUSH(self, arg_A, arg_B):
        self.reg[7] -= 1
        val = self.reg[arg_A]
        self.ram[self.reg[7]] = val
        self.pc += 2

    def op_POP(self, arg_A, arg_B):
        val = self.ram_read(self.reg[7])
        self.reg[arg_A] = val
        self.reg[7] += 1
        self.pc += 2

    def op_CALL(self, arg_A, arg_B):
        rtn_add = self.pc + 2
        self.reg[7] -= 1
        self.ram_write(self.reg[7], rtn_add)
        self.pc = self.reg[arg_A]

    def op_RET(self, arg_A, arg_B):
        rtn_add = self.reg[7]
        self.pc = self.ram_read(rtn_add)
        self.reg[7] += 1

    def op_CMP(self, arg_A, arg_B):
        self.alu("CMP", arg_A, arg_B)
        self.pc += 3

    def op_JMP(self, arg_A, arg_B):
        self.pc = self.reg[arg_A]

    def op_JEQ(self, arg_A, arg_B):
        # check if self.fl[7] = 1
        if self.fl[7] == 1:
            self.pc = self.reg[arg_A]
        else:
            self.pc += 2

    def op_JNE(self, arg_A, arg_B):
        # check if self.fl[7] = 0
        if self.fl[7] == 0:
            self.pc = self.reg[arg_A]
        else:
            self.pc += 2

    def op_HLT(self, arg_A, arg_B):
        self.is_cpu_running = False

    def run(self):
        """Run the CPU."""
        while self.is_cpu_running:
            instruct_reg = self.ram_read(self.pc)
            arg_A = self.ram_read(self.pc + 1)
            arg_B = self.ram_read(self.pc + 2)
            try:
                self.branch_table[instruct_reg](arg_A, arg_B)
            except:
                raise Exception(f"Command {instruct_reg} doesn't exist.")
