import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from trace_data import TraceData

# registers for x64dbg traces
# if you want to see more regs, add them here (in correct order)
# check the order of regs from REGISTERCONTEXT:
# https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h#L723
X32_REGS = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "eip",
    "eflags",
    "gs",
    "fs",
    "es",
    "ds",
    "cs",
    "ss",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
]
X64_REGS = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "eflags",
    "gs",
    "fs",
    "es",
    "ds",
    "cs",
    "ss",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
]

def open_x64dbg_trace(filename):
    """Opens x64dbg trace file

    Args:
        filename: name of trace file
    Returns:
        TraceData object
    """
    with open(filename, "rb") as f:
        trace_data = TraceData()
        trace_data.filename = filename

        # check first 4 bytes
        magic = f.read(4)
        if magic != b"TRAC":
            raise ValueError("Error, wrong file format.")

        json_length_bytes = f.read(4)
        json_length = int.from_bytes(json_length_bytes, "little")

        # read JSON blob
        json_blob = f.read(json_length)
        json_str = str(json_blob, "utf-8")
        arch = json.loads(json_str)["arch"]

        reg_indexes = {}
        if arch == "x64":
            regs = X64_REGS
            ip_reg = "rip"
            capstone_mode = CS_MODE_64
            pointer_size = 8  # qword
        else:
            regs = X32_REGS
            ip_reg = "eip"
            capstone_mode = CS_MODE_32
            pointer_size = 4  # dword

        for i, reg in enumerate(regs):
            reg_indexes[reg] = i

        trace_data.arch = arch
        trace_data.ip_reg = ip_reg
        trace_data.regs = reg_indexes
        trace_data.pointer_size = pointer_size

        md = Cs(CS_ARCH_X86, capstone_mode)
        reg_values = [None] * len(reg_indexes)
        trace = []
        row_id = 0
        while f.read(1) == b"\x00":
            register_changes = int.from_bytes(f.read(1), "little")
            memory_accesses = int.from_bytes(f.read(1), "little")
            flags_and_opcode_size = int.from_bytes(f.read(1), "little")  # Bitfield
            thread_id_bit = (flags_and_opcode_size >> 7) & 1  # msb
            opcode_size = flags_and_opcode_size & 15  # 4 lsbs

            if thread_id_bit > 0:
                thread_id = int.from_bytes(f.read(4), "little")

            opcodes = f.read(opcode_size)

            register_change_position = []
            for _ in range(register_changes):
                register_change_position.append(int.from_bytes(f.read(1), "little"))

            register_change_new_data = []
            for _ in range(register_changes):
                register_change_new_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_flags = []
            for _ in range(memory_accesses):
                memory_access_flags.append(int.from_bytes(f.read(1), "little"))

            memory_access_addresses = []
            for _ in range(memory_accesses):
                memory_access_addresses.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_old_data = []
            for _ in range(memory_accesses):
                memory_access_old_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_new_data = []
            for i in range(memory_accesses):
                if memory_access_flags[i] & 1 == 0:
                    memory_access_new_data.append(
                        int.from_bytes(f.read(pointer_size), "little")
                    )

            reg_id = 0
            regchanges = ""
            for i, change in enumerate(register_change_position):
                reg_id += change
                if reg_id + i < len(reg_indexes):
                    reg_values[reg_id + i] = register_change_new_data[i]
                if reg_id + i < len(reg_indexes) and row_id > 0:
                    reg_name = regs[reg_id + i]
                    if reg_name is not ip_reg:
                        old_value = trace[-1]["regs"][reg_id + i]
                        new_value = register_change_new_data[i]
                        if old_value != new_value:
                            regchanges += (
                                    f"{reg_name}: {hex(old_value)} -> {hex(new_value)} "
                            )
                            if 0x7F > new_value > 0x1F:
                                regchanges += f"'{chr(new_value)}' "

            # disassemble
            ip = reg_values[reg_indexes[ip_reg]]
            for _address, _size, mnemonic, op_str in md.disasm_lite(opcodes, ip):
                disasm = mnemonic
                if op_str:
                    disasm += " " + op_str

            mems = []
            mem = {}
            new_data_counter = 0
            for i in range(memory_accesses):
                flag = memory_access_flags[i]
                value = memory_access_old_data[i]
                mem["access"] = "READ"
                if flag & 1 == 0:
                    value = memory_access_new_data[new_data_counter]
                    mem["access"] = "WRITE"
                    new_data_counter += 1
                else:
                    pass
                    # memory value didn't change
                    # (it is read or overwritten with identical value)
                    # this has to be fixed somehow in x64dbg

                mem["addr"] = memory_access_addresses[i]

                # fix value (x64dbg saves all values as qwords)
                if "qword" in disasm:
                    pass
                elif "dword" in disasm:
                    value &= 0xFFFFFFFF
                elif "word" in disasm:
                    value &= 0xFFFF
                elif "byte" in disasm:
                    value &= 0xFF
                mem["value"] = value
                mems.append(mem.copy())

            if regchanges:
                trace[-1]["regchanges"] = regchanges

            trace_row = {}
            trace_row["id"] = row_id
            trace_row["ip"] = ip
            trace_row["disasm"] = disasm
            trace_row["regs"] = reg_values.copy()
            trace_row["opcodes"] = opcodes.hex()
            trace_row["mem"] = mems.copy()
            # trace_row["comment"] = ""
            trace.append(trace_row)
            row_id += 1

        trace_data.trace = trace
        return trace_data
