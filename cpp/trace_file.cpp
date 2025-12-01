#include "trace_file.h"

TraceData parse_x64dbg_trace(std::string filename) {
    std::ifstream f;
    std::uintmax_t file_size = std::filesystem::file_size(filename);

    f.open(filename, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        throw std::exception("Error opening file.");
    }

    TraceData trace_data{};
    trace_data.trace_filename = filename;

    // check magic number 'TRAC' (0x43415254)
    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != 0x43415254) {
        throw std::exception("Error, wrong file format.");
    }

    size_t json_metalen = 0; // JSON metadata size
    f.read(reinterpret_cast<char*>(&json_metalen), 4);
    
    // read JSON string
    std::string json_metastr(json_metalen, 0x00);
    f.read(json_metastr.data(), json_metalen);

    Json::Value json_meta;
    Json::Reader reader;
    if (!reader.parse(json_metastr, json_meta)) {
        throw std::exception("Error parse json file.");
    }

    std::string arch = json_meta["arch"].asString();
    if (arch == "x86") { trace_data.arch = TraceDataArch::X86_32; }
    else if (arch == "x64") { trace_data.arch = TraceDataArch::X86_64; }
    else {
        f.close();
        throw std::exception("Error arch.");
    }
    trace_data.ptr_size = ((trace_data.arch == TraceDataArch::X86_64) ? sizeof(uint64_t) : sizeof(uint32_t));

    trace_data.meta.arch = arch;
    trace_data.meta.filepath = json_meta["path"].asString();
    trace_data.meta.hashAlgorithm = json_meta["hashAlgorithm"].asString();
    trace_data.meta.hash = json_meta["hash"].asString();
    trace_data.meta.compression = json_meta["compression"].asString();
    trace_data.meta.version = json_meta["ver"].asInt();

    // Provide cache space to facilitate the acceleration of parsing speed
    size_t probably_ins_num = (file_size / ((trace_data.arch == TraceDataArch::X86_64) ? 40ULL : 30ULL)); // average 30 bytes(x86-32bit)/ 40 bytes(x86-64bit) -> 1 instruction
    trace_data.record.reserve(probably_ins_num);

    csh hcs;
    if (cs_open(CS_ARCH_X86, ((trace_data.arch == TraceDataArch::X86_64) ? CS_MODE_64 : CS_MODE_32), &hcs) != CS_ERR_OK) {
        throw std::exception("Open capstone instance failed.");
    }
    if (cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        throw std::exception("Open detail mode failed.");
    }

    // Block type (0 = instruction, 0x80-0xFF = user-defined)
    uint8_t block_type = 0;
    f.read(reinterpret_cast<char*>(&block_type), 1);
    TraceRegDump reg_dump{};
    uint32_t inst_idx = 0;
    uint32_t current_thread_id = 0;
    while (!f.eof()) {
        // User-defined Block
        if (block_type >= 0x80 && block_type <= 0xFF) {
            uint32_t block_size = 0;
            f.read(reinterpret_cast<char*>(&block_size), 4);
            std::vector<uint8_t> block_data(block_size);
            f.read(reinterpret_cast<char*>(block_data.data()), block_size);
            switch (block_type) {
                // ----------------------------
                //            TODO
                // ----------------------------
            }

            f.read(reinterpret_cast<char*>(&block_type), 1);
        }

        // Instruction Block
        if (block_type == 0x00) {
            InstructionRecord inst_record{};
            uint8_t register_changes = 0; // Register change count
            f.read(reinterpret_cast<char*>(&register_changes), 1);
            uint8_t memory_accesses = 0; // Memory access count
            f.read(reinterpret_cast<char*>(&memory_accesses), 1);
            uint8_t flags_and_opcode_size = 0; // Flags
            f.read(reinterpret_cast<char*>(&flags_and_opcode_size), 1);
            uint8_t thread_id_bit = (flags_and_opcode_size >> 7) & 1; // (Flags) bit 7 = thread ID present
            uint8_t opcode_size = flags_and_opcode_size & 15;  // (Flags) bits 0-3 = opcode size

            if (thread_id_bit > 0) {
                // Optional thread ID (4 bytes)
                f.read(reinterpret_cast<char*>(&current_thread_id), 4);
            }
            inst_record.thread_id = current_thread_id;

            inst_record.bytes.resize(opcode_size); // Opcode bytes
            f.read(reinterpret_cast<char*>(inst_record.bytes.data()), opcode_size);

            /* Changed registers (index + value pairs) */
            std::vector<uint8_t> register_change_position(register_changes); // array
            std::vector<duint> register_change_new_data(register_changes); // array
            for (size_t i = 0; i < register_changes; i++) {
                uint8_t reg = 0;
                f.read(reinterpret_cast<char*>(&reg), 1);
                register_change_position[i] = reg;
            }
            for (size_t i = 0; i < register_changes; i++) {
                duint new_data = 0;
                f.read(reinterpret_cast<char*>(&new_data), sizeof(duint));
                register_change_new_data[i] = new_data;
            }

            /* Memory access info */
            std::vector<uint8_t> memory_access_flags(memory_accesses); // flags (bit 0 = valid flag)
            std::vector<duint> memory_access_addresses(memory_accesses);
            std::vector<duint> memory_access_old_data(memory_accesses);
            std::vector<duint> memory_access_new_data{};
            for (size_t i = 0; i < memory_accesses; i++) {
                uint8_t flag = 0;
                f.read(reinterpret_cast<char*>(&flag), 1);
                memory_access_flags[i] = flag;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                duint address = 0;
                f.read(reinterpret_cast<char*>(&address), sizeof(duint));
                memory_access_addresses[i] = address;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                duint old_data = 0;
                f.read(reinterpret_cast<char*>(&old_data), sizeof(duint));
                memory_access_old_data[i] = old_data;
            }
            for (size_t i = 0; i < memory_accesses; i++) {
                if ((memory_access_flags[i] & 1) == 0) { // check valid flag
                    duint new_data = 0;
                    f.read(reinterpret_cast<char*>(&new_data), sizeof(duint));
                    memory_access_new_data.push_back(new_data);
                }
            }

            /* Fill the register of the current instruction to record data */
            uint8_t reg_id = 0;
            for (size_t i = 0; i < register_change_position.size(); i++) {
                uint8_t change = register_change_position[i];
                reg_id += change;
                size_t reg_offset = (reg_id + i) * sizeof(duint);
                if (reg_offset < sizeof(TraceRegDump)) {
                    duint* area_ptr = (duint*)(((uint8_t*)&reg_dump) + reg_offset);
                    duint old_value = *area_ptr;
                    duint new_value = register_change_new_data[i];
                    *area_ptr = new_value;

                    if (trace_data.record.size() >= 1) {
                        if (old_value != new_value) {
                            trace_data.record.back().reg_changes[reg_offset] = std::make_pair(old_value, new_value);
                        }
                    }
                }
                else {
                    throw std::exception("Offset of regdump is invaild.");
                }
            }
            inst_record.reg_dump = reg_dump;
            inst_record.ins_address = reg_dump.regcontext.cip;

            cs_insn* pcsins;
            if (cs_disasm(hcs, inst_record.bytes.data(), inst_record.bytes.size(), inst_record.ins_address, 1, &pcsins) == 0) {
                throw std::exception("Disassembly instruction failed.");
            }

            /* Fill the memory record data of the current instruction */
            size_t new_data_counter = 0;
            for (size_t i = 0; i < memory_accesses; i++) {
                MemoryAccessRecord mem_acc{};

                uint8_t flag = memory_access_flags[i];
                mem_acc.old_data = memory_access_old_data[i];

                for (size_t j = 0; j < pcsins->detail->x86.op_count; j++) {
                    if (pcsins->detail->x86.operands[j].type == X86_OP_MEM) {
                        // movs
                        if (pcsins->id == X86_INS_MOVSB || pcsins->id == X86_INS_MOVSW || pcsins->id == X86_INS_MOVSD || pcsins->id == X86_INS_MOVSQ) {
                            mem_acc.type = AccessType::WRITE;
                            mem_acc.read_and_write = true;
                        }
                        // cmps
                        else if (pcsins->id == X86_INS_CMPSB || pcsins->id == X86_INS_CMPSW || pcsins->id == X86_INS_CMPSD || pcsins->id == X86_INS_CMPSQ) {
                            mem_acc.type = AccessType::READ;
                        }

                        else if (pcsins->detail->x86.operands[j].access == cs_ac_type::CS_AC_READ) {
                            mem_acc.type = AccessType::READ;
                        }
                        else if (pcsins->detail->x86.operands[j].access == cs_ac_type::CS_AC_WRITE) {
                            mem_acc.type = AccessType::WRITE;
                        }
                        else if (pcsins->detail->x86.operands[j].access == (cs_ac_type::CS_AC_READ | cs_ac_type::CS_AC_WRITE)) {
                            mem_acc.type = AccessType::WRITE;
                            mem_acc.read_and_write = true;
                        }
                        else { continue; }

                        mem_acc.acc_size = pcsins->detail->x86.operands[j].size;
                        break;
                    }
                }
            

                if ((flag & 1) == 0) {
                    mem_acc.new_data = memory_access_new_data[new_data_counter];
                    new_data_counter += 1;
                }
                else {
                    mem_acc.overwritten_or_identical = true;
                    mem_acc.new_data = mem_acc.old_data;
                    // memory value didn't change (it is read or overwritten with identical value)
                }
                mem_acc.acc_address = memory_access_addresses[i];

                inst_record.mem_accs.push_back(mem_acc);
            }
            cs_free(pcsins, 1);

            inst_record.id = inst_idx;
            inst_record.dbg_id = inst_idx;
            trace_data.record.push_back(inst_record);
            inst_idx++;

            f.read(reinterpret_cast<char*>(&block_type), 1);
        }
    }

    trace_data.record.shrink_to_fit();
    cs_close(&hcs);
    f.close();
    return trace_data;
}
