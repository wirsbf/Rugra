// C++ shim providing C ABI for Rugra's direct SLEIGH integration.
// Wraps Ghidra's Sleigh + LoadImage + Context into a single opaque handle.
// This IS Ghidra's design (PcodeOp flat struct), not an abstraction layer.

#include "sleigh.hh"
#include "loadimage.hh"
#include "pcodeparse.hh"
#include "context.hh"
#include "marshal.hh"
#include "slaformat.hh"
#include <cstdint>
#include <cstring>
#include <vector>
#include <fstream>
#include <sstream>

using namespace ghidra;

// ---- C-compatible flat structs (match Ghidra PcodeOp layout) ----

extern "C" {

struct VarnodeC {
    int32_t space;
    uint64_t offset;
    int32_t size;
};

struct PcodeOpC {
    int32_t opcode;       // CPUI_* value (opcodes.hh)
    int32_t num_inputs;
    int32_t has_output;
    VarnodeC output;
    VarnodeC inputs[16];  // Ghidra max inputs per op
};

}  // extern "C"

// ---- Rugra LoadImage: provides bytes from a flat buffer ----

class RugraLoadImage : public LoadImage {
    const uint8_t* data;
    size_t data_len;
    uintb base_addr;
public:
    RugraLoadImage() : LoadImage("rugra"), data(nullptr), data_len(0), base_addr(0) {}

    void setBytes(const uint8_t* bytes, size_t len, uintb base) {
        data = bytes;
        data_len = len;
        base_addr = base;
    }

    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        uintb offset = addr.getOffset() - base_addr;
        for (int4 i = 0; i < size; ++i) {
            if (offset + i < data_len)
                ptr[i] = data[offset + i];
            else
                ptr[i] = 0;
        }
    }

    string getArchType(void) const override { return "rugra"; }
    void adjustVma(long adjust) override {}
};

// ---- Rugra PcodeEmit: collects ops into flat array ----

class RugraPcodeEmit : public PcodeEmit {
public:
    std::vector<PcodeOpC> ops;

    void dump(const Address& addr, OpCode opc, VarnodeData* outvar, VarnodeData* vars,
              int4 isize) override {
        PcodeOpC op;
        op.opcode = (int32_t)opc;
        op.num_inputs = isize;
        op.has_output = (outvar != nullptr) ? 1 : 0;

        if (outvar) {
            op.output.space = outvar->space->getIndex();
            op.output.offset = outvar->offset;
            op.output.size = outvar->size;
        }

        for (int4 i = 0; i < isize && i < 16; ++i) {
            if ((opc == CPUI_STORE || opc == CPUI_LOAD) && i == 0) {
                AddrSpace* targetSpace = (AddrSpace*)(uintp)vars[i].offset;
                op.inputs[i].space = 0;
                op.inputs[i].offset = targetSpace->getIndex();
                op.inputs[i].size = vars[i].size;
            } else {
                op.inputs[i].space = vars[i].space->getIndex();
                op.inputs[i].offset = vars[i].offset;
                op.inputs[i].size = vars[i].size;
            }
        }

        ops.push_back(op);
    }
};

// ---- Sleigh context handle ----

struct RugraSleigh {
    RugraLoadImage loader;
    ContextInternal context;
    Sleigh* trans;
    Element* sla_root;

    RugraSleigh() : trans(nullptr), sla_root(nullptr) {}
    ~RugraSleigh() { delete trans; delete sla_root; }
};

// ---- C API functions ----

extern "C" {

// Create SLEIGH context from .sla file path.
// Returns opaque handle, or NULL on failure.
void* rugra_sleigh_create(const char* sla_path) {
    auto* s = new RugraSleigh();
    s->trans = new Sleigh(&(s->loader), &(s->context));

    // Parse .sla file
    istringstream sla_stream;
    try {
        DocumentStorage docstore;
        // Sleigh::initialize opens the .sla file from the "sleigh" tag content (file path)
        // Build a minimal XML document: <sleigh>path_to_sla</sleigh>
        string xml = "<sleigh>" + string(sla_path) + "</sleigh>";
        istringstream xml_stream(xml);
        Document* doc = docstore.parseDocument(xml_stream);
        docstore.registerTag(doc->getRoot());
        s->trans->initialize(docstore);
    } catch (...) {
        delete s;
        return nullptr;
    }
    return s;
}

void rugra_sleigh_set_image(void* handle, const uint8_t* bytes, uint64_t len, uint64_t base_addr) {
    auto* s = (RugraSleigh*)handle;
    s->loader.setBytes(bytes, (size_t)len, base_addr);
}

void rugra_sleigh_set_context(void* handle, const char* name, int32_t val) {
    auto* s = (RugraSleigh*)handle;
    try {
        s->context.setVariableDefault(name, val);
    } catch (...) {}
}

// Decode instruction at offset. Returns number of p-code ops, or -1 on failure.
// Fills ops array (caller allocates).
int32_t rugra_sleigh_decode(void* handle, uint64_t offset,
                             PcodeOpC* ops, int32_t max_ops) {
    auto* s = (RugraSleigh*)handle;

    Address addr(s->trans->getDefaultCodeSpace(), offset);
    RugraPcodeEmit emitter;
    try {
        s->trans->oneInstruction(emitter, addr);
    } catch (...) {
        return -1;
    }

    int32_t n = (int32_t)emitter.ops.size();
    if (n > max_ops) n = max_ops;
    for (int32_t i = 0; i < n; ++i)
        ops[i] = emitter.ops[i];
    return n;
}

// Get instruction length at offset
int32_t rugra_sleigh_instruction_length(void* handle, uint64_t offset) {
    auto* s = (RugraSleigh*)handle;
    Address addr(s->trans->getDefaultCodeSpace(), offset);
    try {
        return s->trans->instructionLength(addr);
    } catch (...) {
        return -1;
    }
}

// Get number of address spaces
int32_t rugra_sleigh_num_spaces(void* handle) {
    auto* s = (RugraSleigh*)handle;
    return s->trans->numSpaces();
}

// Get space info
void rugra_sleigh_space_info(void* handle, int32_t index,
                              int32_t* out_type, char* out_name, int32_t name_max) {
    auto* s = (RugraSleigh*)handle;
    AddrSpace* spc = s->trans->getSpace(index);
    if (out_type) *out_type = (int32_t)spc->getType();
    if (out_name && name_max > 0) {
        strncpy(out_name, spc->getName().c_str(), name_max);
        out_name[name_max - 1] = 0;
    }
}

// Get register count
int32_t rugra_sleigh_num_registers(void* handle) {
    auto* s = (RugraSleigh*)handle;
    map<VarnodeData,string> reglist;
    s->trans->getAllRegisters(reglist);
    return (int32_t)reglist.size();
}

// Get register info by index
void rugra_sleigh_register_info(void* handle, int32_t index,
                                 char* out_name, int32_t name_max,
                                 int32_t* out_space, uint64_t* out_offset,
                                 int32_t* out_size) {
    auto* s = (RugraSleigh*)handle;
    map<VarnodeData,string> reglist;
    s->trans->getAllRegisters(reglist);
    if (index < 0 || index >= (int32_t)reglist.size()) return;
    auto it = reglist.begin();
    advance(it, index);
    if (out_name && name_max > 0) {
        strncpy(out_name, it->second.c_str(), name_max);
        out_name[name_max - 1] = 0;
    }
    if (out_space) *out_space = it->first.space->getIndex();
    if (out_offset) *out_offset = it->first.offset;
    if (out_size) *out_size = it->first.size;
}

// Destroy SLEIGH context
void rugra_sleigh_destroy(void* handle) {
    delete (RugraSleigh*)handle;
}

}  // extern "C"
