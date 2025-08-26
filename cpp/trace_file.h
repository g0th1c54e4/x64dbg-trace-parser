#ifndef TRACE_FILE_H
#define TRACE_FILE_H

#include <string>
#include <map>
#include <fstream>
#include <filesystem>
#include <json/json.h>
#include <capstone/capstone.h>

#include "plugin.h"

enum class TraceDataArch { X86_32, X86_64 };

typedef struct {
	REGISTERCONTEXT regcontext;
	FLAGS flags;
	X87FPUREGISTER x87FPURegisters[8];
	unsigned long long mmx[8];
	MXCSRFIELDS MxCsrFields;
	X87STATUSWORDFIELDS x87StatusWordFields;
	X87CONTROLWORDFIELDS x87ControlWordFields;
	LASTERROR lastError;
	// LASTSTATUS lastStatus; // This field is not supported and not included in trace file.
} TraceRegDump;

enum class MemoryAccessType : uint8_t { READ, WRITE };
struct MemoryAccessRecord {
	MemoryAccessType type;
	bool read_and_write;
	bool overwritten_or_identical; // memory value didn't change
	uint8_t acc_size; // in bytes (e.g. qword dword word byte)
	duint acc_address; // including segment base address
	duint old_data;
	duint new_data;
};

struct InstructionRecord {
	duint ins_address; // eip(or rip) value
	std::vector<uint8_t> bytes;
	// uint8_t size;    // use 'bytes.size()' instead of 'size','size' means what is the lenght(in bytes) of instruction.
	std::vector<MemoryAccessRecord> mem_accs;
	std::unordered_map<size_t, std::pair<duint, duint>> reg_changes; // [key]: offset of regdump,  [value]: old value(first) and new value(second)
	uint32_t thread_id;
	TraceRegDump reg_dump;
	uint32_t id; // (when 'id' is 0, it means instruction is the first one in trace file)
	uint32_t dbg_id; // do not change!(It is convenient to compare in x64dbg)
};

struct TraceData {
	std::string trace_filename;
	Json::Value json_blob;
	size_t ptr_size;
	TraceDataArch arch;
	std::vector<InstructionRecord> record;
};

TraceData parse_x64dbg_trace(std::string filename);

#endif