#ifndef TRACE_FILE_H
#define TRACE_FILE_H

#include <string>
#include <map>
#include <fstream>
#include <json/json.h>

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

enum class MemoryAccessType { READ, WRITE };
struct MemoryAccessRecord {
	MemoryAccessType type;
	duint address;
	duint old_data;
	duint new_data;
	bool overwritten_or_identical; // memory value didn't change
};

struct InstructionRecord {
	std::vector<uint8_t> bytes;
	// uint8_t size;    // use 'bytes.size()' instead of 'size'.
	std::vector<MemoryAccessRecord> mem_accs;
	TraceRegDump reg_dump;
};

struct TraceData {
	int version;
	std::string trace_filename;
	std::string target_filename;
	std::string hashAlgorithm;
	std::string hash;
	std::string compression;

	TraceDataArch arch;
	std::vector<InstructionRecord> record;
};

TraceData parse_x64dbg_trace(std::string filename);

#endif