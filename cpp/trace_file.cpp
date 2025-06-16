#include "trace_file.h"

TraceData parse_x64dbg_trace(std::string filename) {
    std::ifstream f;
    f.open(filename, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        throw std::exception("Error opening file.");
    }

    TraceData trace_data{};
    trace_data.trace_filename = filename;

    // check first 4 bytes
    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != 0x43415254) { // "TRAC"
        throw std::exception("Error, wrong file format.");
    }

    size_t json_length = 0;
    f.read(reinterpret_cast<char*>(&json_length), 4);
    
    // read JSON blob
    std::vector<uint8_t> json_blob(json_length);
    f.read(reinterpret_cast<char*>(json_blob.data()), json_length);
    std::string json_str(json_blob.cbegin(), json_blob.cend());
    Json::Reader reader;
    Json::Value json_root;
    if (!reader.parse(json_str, json_root)) {
        throw std::exception("Error parse json file.");
    }
    std::string arch = json_root["arch"].asString();
    trace_data.arch = ((arch == "x64") ? TraceDataArch::X86_64 : TraceDataArch::X86_32);
    trace_data.target_filename = json_root["path"].asString();
    trace_data.hashAlgorithm = json_root["hashAlgorithm"].asString();
    trace_data.hash = json_root["hash"].asString();
    trace_data.compression = json_root["compression"].asString();
    trace_data.version = json_root["ver"].asInt();

    uint8_t block_type = 0;
    f.read(reinterpret_cast<char*>(&block_type), 1);
    size_t row_id = 0;
    TraceRegDump reg_dump{};
    while (block_type == 0x00 && !f.eof()) {
        InstructionRecord inst_record{};

        uint8_t register_changes = 0;
        f.read(reinterpret_cast<char*>(&register_changes), 1);
        uint8_t memory_accesses = 0;
        f.read(reinterpret_cast<char*>(&memory_accesses), 1);
        uint8_t flags_and_opcode_size = 0;
        f.read(reinterpret_cast<char*>(&flags_and_opcode_size), 1);
        uint8_t thread_id_bit = (flags_and_opcode_size >> 7) & 1; // msb
        uint8_t opcode_size = flags_and_opcode_size & 15;  // lsbs

        uint32_t thread_id = 0;
        if (thread_id_bit > 0) {
            f.read(reinterpret_cast<char*>(&thread_id), 4);
        }

        std::vector<uint8_t> opcodes(opcode_size);
        f.read(reinterpret_cast<char*>(opcodes.data()), opcode_size);
        inst_record.bytes = opcodes;

        std::vector<uint8_t> register_change_position; // array
        std::vector<duint> register_change_new_data{}; // array
        for (size_t i = 0; i < register_changes; i++) {
            uint8_t reg = 0;
            f.read(reinterpret_cast<char*>(&reg), 1);
            register_change_position.push_back(reg);
        }
        for (size_t i = 0; i < register_changes; i++) {
            duint new_data = 0;
            f.read(reinterpret_cast<char*>(&new_data), sizeof(duint));
            register_change_new_data.push_back(new_data);
        }

        std::vector<uint8_t> memory_access_flags;
        std::vector<duint> memory_access_addresses{};
        std::vector<duint> memory_access_old_data{};
        std::vector<duint> memory_access_new_data{};
        for (size_t i = 0; i < memory_accesses; i++) {
            uint8_t flag = 0;
            f.read(reinterpret_cast<char*>(&flag), 1);
            memory_access_flags.push_back(flag);
        }
        for (size_t i = 0; i < memory_accesses; i++) {
            duint address = 0;
            f.read(reinterpret_cast<char*>(&address), sizeof(duint));
            memory_access_addresses.push_back(address);
        }
        for (size_t i = 0; i < memory_accesses; i++) {
            duint old_data = 0;
            f.read(reinterpret_cast<char*>(&old_data), sizeof(duint));
            memory_access_old_data.push_back(old_data);
        }
        for (size_t i = 0; i < memory_accesses; i++) {
            if ((memory_access_flags[i] & 1) == 0) {
                duint new_data = 0;
                f.read(reinterpret_cast<char*>(&new_data), sizeof(duint));
                memory_access_new_data.push_back(new_data);
            }
        }

        uint8_t reg_id = 0;
        for (size_t i = 0; i < register_change_position.size(); i++) {
            uint8_t change = register_change_position[i];
            reg_id += change;
            size_t reg_offset = (reg_id + i) * sizeof(duint);
            if (reg_offset < sizeof(TraceRegDump)) {
                *(duint*)(((uint8_t*)&reg_dump) + reg_offset) = register_change_new_data[i];
            }
        }
        inst_record.reg_dump = reg_dump;

        size_t new_data_counter = 0;
        for (size_t i = 0; i < memory_accesses; i++) {
            MemoryAccessRecord mem_acc{};

            uint8_t flag = memory_access_flags[i];
            mem_acc.old_data = memory_access_old_data[i];
            mem_acc.type = MemoryAccessRecordType::READ;
            if ((flag & 1) == 0) {
                mem_acc.new_data = memory_access_new_data[new_data_counter];
                mem_acc.type = MemoryAccessRecordType::WRITE;
                new_data_counter += 1;
            }
            else {
                mem_acc.overwritten_or_identical = true;
                // memory value didn't change (it is read or overwritten with identical value)
            }
            mem_acc.address = memory_access_addresses[i];

            inst_record.mem_accs.push_back(mem_acc);
        }

        row_id += 1;
        trace_data.record.push_back(inst_record);
        f.read(reinterpret_cast<char*>(&block_type), 1);       
    }

    f.close();
    return trace_data;
}
