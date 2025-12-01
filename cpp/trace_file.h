#ifndef TRACE_FILE_H
#define TRACE_FILE_H

/*
* x64dbg trace file format specification: 
*   https://help.x64dbg.com/en/latest/developers/tracefile.html
*   https://deepwiki.com/x64dbg/x64dbg/5.1-trace-recording-and-analysis#trace-file-format
*/

#include <string>
#include <map>
#include <fstream>
#include <filesystem>
#include <json/json.h>
#include <capstone/capstone.h>

#include "plugin.h"

enum class TraceDataArch { X86_32, X86_64 };

// https://github.com/x64dbg/x64dbg/blob/e11f5b7eaa6286f4a5c9e92016fde9d090daa6ba/src/dbg/TraceRecord.cpp#L507
struct TraceJsonMetadata {
	std::string arch;			// Architecture ("x86" or "x64")
	std::string filepath;		// Original executable path
	std::string hashAlgorithm;	// Optional hash algorithm name
	std::string hash;			// Optional executable hash (for matching against debuggee)
	std::string compression;	// Compression method (empty string = none)
	int version;				// Format version
};

typedef struct {
	REGISTERCONTEXT regcontext;
	FLAGS flags;
	X87FPUREGISTER x87FPURegisters[8];
	unsigned long long mmx[8];
	MXCSRFIELDS MxCsrFields;
	X87STATUSWORDFIELDS x87StatusWordFields;
	X87CONTROLWORDFIELDS x87ControlWordFields;
	LASTERROR lastError;
	// LASTSTATUS lastStatus; // This field is not supported and is not included in the trace file.
} TraceRegDump;

enum class AccessType { READ, WRITE };
struct MemoryAccessRecord {
	AccessType type;

	// True when this memory access represents a combined read-and-write operation
	// performed by a single instruction. This applies to string move instructions
	// such as MOVSB, MOVSW, MOVSD, and MOVSQ, where the instruction reads from
	// a source address and writes to a different destination address as part of
	// one semantic operation. This flag does not indicate a traditional
	// read-modify-write (RMW) on the same address.
	bool read_and_write;

	bool overwritten_or_identical;	// means memory value didn't change
	uint8_t acc_size;				// in bytes
	duint acc_address;				// including segment base address

	duint old_data;
	duint new_data;
};

struct InstructionRecord {
	duint ins_address;
	std::vector<uint8_t> bytes;
	std::vector<MemoryAccessRecord> mem_accs;

	/*
		[key]: offset of regdump
		[value]:
		       std::pair.first	: old value
		       std::pair.second	: new value
	*/
	std::unordered_map<size_t, std::pair<duint, duint>> reg_changes;

	uint32_t thread_id;
	TraceRegDump reg_dump;

	// When id is 0, it means the instruction is the first one in the trace file.
	uint32_t id;

	// Do not change! (Used for easier comparison in x64dbg)
	uint32_t dbg_id;
};

struct TraceData {
	std::string trace_filename;
	TraceJsonMetadata meta;
	size_t ptr_size;
	TraceDataArch arch;
	std::vector<InstructionRecord> record;
};

TraceData parse_x64dbg_trace(std::string filename);

#endif