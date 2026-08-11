// C++ shim providing a fail-closed C ABI for Rugra's direct SLEIGH integration.
// The shim owns every object and byte buffer that crosses the language boundary.

#include "sleigh.hh"
#include "loadimage.hh"
#include "pcodeparse.hh"
#include "context.hh"
#include "marshal.hh"
#include "slaformat.hh"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

using namespace ghidra;

namespace {

constexpr uint32_t RUGRA_SLEIGH_ABI_VERSION = 1;

std::mutex& sleighInitializationMutex() {
    static std::mutex mutex;
    return mutex;
}

enum RugraSleighErrorKind : uint32_t {
    RUGRA_SLEIGH_OK = 0,
    RUGRA_SLEIGH_UNIMPLEMENTED = 1,
    RUGRA_SLEIGH_BAD_DATA = 2,
    RUGRA_SLEIGH_DATA_UNAVAILABLE = 3,
    RUGRA_SLEIGH_SLEIGH_ERROR = 4,
    RUGRA_SLEIGH_LOWLEVEL_ERROR = 5,
    RUGRA_SLEIGH_DECODER_ERROR = 6,
    RUGRA_SLEIGH_STD_EXCEPTION = 7,
    RUGRA_SLEIGH_UNKNOWN_EXCEPTION = 8,
    RUGRA_SLEIGH_INVALID_ARGUMENT = 9,
    RUGRA_SLEIGH_INVALID_STATE = 10,
    RUGRA_SLEIGH_OUT_OF_MEMORY = 11,
};

}  // namespace

extern "C" {

struct RugraVarnodeC {
    int32_t space;
    uint32_t size;
    uint64_t offset;
    int32_t space_ref;
    uint32_t flags;
    uint64_t identity;
};

struct RugraPcodeOpC {
    int32_t address_space;
    uint32_t has_output;
    uint64_t address_offset;
    int32_t opcode;
    int32_t num_inputs;
    RugraVarnodeC output;
};

}  // extern "C"

static_assert(std::is_standard_layout<RugraVarnodeC>::value,
              "RugraVarnodeC must remain a C-compatible POD");
static_assert(sizeof(RugraVarnodeC) == 32, "unexpected RugraVarnodeC layout");
static_assert(offsetof(RugraVarnodeC, offset) == 8, "unexpected offset field layout");
static_assert(offsetof(RugraVarnodeC, identity) == 24, "unexpected identity field layout");
static_assert(std::is_standard_layout<RugraPcodeOpC>::value,
              "RugraPcodeOpC must remain a C-compatible POD");
static_assert(sizeof(RugraPcodeOpC) == 56, "unexpected RugraPcodeOpC layout");
static_assert(offsetof(RugraPcodeOpC, output) == 24, "unexpected output field layout");

namespace {

class RugraLoadImage : public LoadImage {
    std::vector<uint1> data;
    uintb base_addr;

public:
    RugraLoadImage() : LoadImage("rugra"), base_addr(0) {}

    void setBytes(const uint8_t* bytes, uint64_t len, uint64_t base) {
        if (bytes == nullptr && len != 0)
            throw LowlevelError("Null image pointer with non-zero length");
        if (len > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
            throw LowlevelError("Image length does not fit host size_t");

        std::vector<uint1> replacement;
        if (len != 0)
            replacement.assign(bytes, bytes + static_cast<size_t>(len));
        data.swap(replacement);  // Strong exception guarantee: publish only after the copy.
        base_addr = base;
    }

    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        if (size < 0)
            throw LowlevelError("Negative load-image request size");
        if (size == 0)
            return;
        if (ptr == nullptr)
            throw LowlevelError("Null load-image destination");

        const uintb start = addr.getOffset();
        // RawLoadImage performs this unsigned subtraction directly.  Preserve
        // its uint64 modulo behavior at the address-space wrap boundary.
        const uintb relative = start - base_addr;
        if (relative >= data.size()) {
            ostringstream message;
            message << "Unable to load " << dec << size << " bytes at " << addr.getShortcut();
            addr.printRaw(message);
            throw DataUnavailError(message.str());
        }

        const size_t requested = static_cast<size_t>(size);
        const size_t available = data.size() - static_cast<size_t>(relative);
        const size_t copied = std::min(requested, available);
        std::memcpy(ptr, data.data() + static_cast<size_t>(relative), copied);
        if (copied < requested)
            std::memset(ptr + copied, 0, requested - copied);
    }

    string getArchType(void) const override { return "rugra"; }
    void adjustVma(long adjust) override { (void)adjust; }
};

struct RugraOpRecord {
    RugraPcodeOpC op{};
    std::vector<RugraVarnodeC> inputs;
};

struct RugraSleighResult {
    uint32_t abi_version = RUGRA_SLEIGH_ABI_VERSION;
    uint32_t error_kind = RUGRA_SLEIGH_OK;
    int32_t step = 0;
    uint32_t has_instruction_length = 0;
    int32_t instruction_length = 0;
    std::string message;
    std::vector<RugraOpRecord> ops;
};

class RugraPcodeEmit : public PcodeEmit {
    RugraSleighResult& result;
    std::unordered_map<const VarnodeData*, uint64_t> identities;
    std::unordered_map<uint64_t, int32_t> space_pointer_indices;
    int32_t constant_space_index;
    uint64_t next_identity;

    int32_t requireSpaceIndex(const AddrSpace* space) const {
        if (space == nullptr)
            throw LowlevelError("SLEIGH emitted a null address space");
        const uint64_t pointer_value = static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(space));
        const auto known = space_pointer_indices.find(pointer_value);
        if (known == space_pointer_indices.end())
            throw LowlevelError("SLEIGH emitted an unknown address-space pointer");
        return known->second;
    }

    uint64_t identityFor(const VarnodeData* varnode) {
        const auto existing = identities.find(varnode);
        if (existing != identities.end())
            return existing->second;
        const uint64_t identity = next_identity++;
        identities.emplace(varnode, identity);
        return identity;
    }

    RugraVarnodeC copyVarnode(const VarnodeData* varnode, OpCode opcode,
                              int4 input_slot, bool is_input) {
        if (varnode == nullptr)
            throw LowlevelError("SLEIGH emitted an invalid VarnodeData pointer");

        RugraVarnodeC copied{};
        copied.space = requireSpaceIndex(varnode->space);
        copied.size = varnode->size;
        copied.offset = varnode->offset;
        copied.space_ref = -1;
        copied.identity = identityFor(varnode);

        if (is_input && input_slot == 0 &&
            (opcode == CPUI_LOAD || opcode == CPUI_STORE)) {
            if (copied.space != constant_space_index ||
                copied.size != static_cast<uint4>(sizeof(AddrSpace*)))
                throw LowlevelError("SLEIGH emitted an invalid LOAD/STORE space-id operand");
            const auto target = space_pointer_indices.find(varnode->offset);
            if (target == space_pointer_indices.end())
                throw LowlevelError("SLEIGH emitted an unknown LOAD/STORE address-space pointer");
            copied.offset = static_cast<uint64_t>(target->second);
            copied.space_ref = target->second;
        }
        return copied;
    }

public:
    RugraPcodeEmit(RugraSleighResult& target, const Translate& translator)
        : result(target), constant_space_index(-1), next_identity(0) {
        const int4 space_count = translator.numSpaces();
        for (int4 index = 0; index < space_count; ++index) {
            AddrSpace* space = translator.getSpace(index);
            if (space == nullptr)
                continue;
            const uint64_t pointer_value = static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(space));
            space_pointer_indices.emplace(pointer_value, space->getIndex());
        }
        constant_space_index = requireSpaceIndex(translator.getConstantSpace());
    }

    void dump(const Address& addr, OpCode opcode, VarnodeData* outvar,
              VarnodeData* vars, int4 input_count) override {
        if (input_count < 0)
            throw LowlevelError("SLEIGH emitted a negative input count");
        if (input_count != 0 && vars == nullptr)
            throw LowlevelError("SLEIGH emitted null inputs with a non-zero count");

        RugraOpRecord record;
        record.op.address_space = requireSpaceIndex(addr.getSpace());
        record.op.address_offset = addr.getOffset();
        record.op.opcode = static_cast<int32_t>(opcode);
        record.op.num_inputs = input_count;
        record.op.has_output = outvar == nullptr ? 0U : 1U;
        record.op.output.space_ref = -1;
        if (outvar != nullptr)
            record.op.output = copyVarnode(outvar, opcode, -1, false);

        record.inputs.reserve(static_cast<size_t>(input_count));
        for (int4 index = 0; index < input_count; ++index)
            record.inputs.push_back(copyVarnode(vars + index, opcode, index, true));
        result.ops.push_back(std::move(record));
    }
};

struct RugraSleigh {
    RugraLoadImage loader;
    ContextInternal context;
    std::unique_ptr<Sleigh> trans;
    bool decode_started;

    RugraSleigh() : trans(), decode_started(false) {}
};

RugraSleighResult* allocateResult() noexcept {
    try {
        return new RugraSleighResult();
    } catch (...) {
        return nullptr;
    }
}

void setError(RugraSleighResult& result, uint32_t kind, const char* message,
              bool has_instruction_length = false, int32_t instruction_length = 0) noexcept {
    result.error_kind = kind;
    result.step = 0;
    result.has_instruction_length = has_instruction_length ? 1U : 0U;
    result.instruction_length = instruction_length;
    result.ops.clear();
    try {
        result.message.assign(message == nullptr ? "" : message);
    } catch (...) {
        result.message.clear();
    }
}

void setError(RugraSleighResult& result, uint32_t kind, const std::string& message,
              bool has_instruction_length = false, int32_t instruction_length = 0) noexcept {
    result.error_kind = kind;
    result.step = 0;
    result.has_instruction_length = has_instruction_length ? 1U : 0U;
    result.instruction_length = instruction_length;
    result.ops.clear();
    try {
        result.message = message;
    } catch (...) {
        result.message.clear();
    }
}

void setLowlevelError(RugraSleighResult& result, uint32_t kind,
                      const LowlevelError& error) noexcept {
    setError(result, kind, error.explain);
}

void captureCurrentException(RugraSleighResult& result) noexcept {
    try {
        throw;
    } catch (const UnimplError& error) {
        setError(result, RUGRA_SLEIGH_UNIMPLEMENTED, error.explain, true,
                 error.instruction_length);
    } catch (const BadDataError& error) {
        setLowlevelError(result, RUGRA_SLEIGH_BAD_DATA, error);
    } catch (const DataUnavailError& error) {
        setLowlevelError(result, RUGRA_SLEIGH_DATA_UNAVAILABLE, error);
    } catch (const SleighError& error) {
        setLowlevelError(result, RUGRA_SLEIGH_SLEIGH_ERROR, error);
    } catch (const LowlevelError& error) {
        setLowlevelError(result, RUGRA_SLEIGH_LOWLEVEL_ERROR, error);
    } catch (const DecoderError& error) {
        setError(result, RUGRA_SLEIGH_DECODER_ERROR, error.explain);
    } catch (const std::bad_alloc& error) {
        setError(result, RUGRA_SLEIGH_OUT_OF_MEMORY, error.what());
    } catch (const std::exception& error) {
        setError(result, RUGRA_SLEIGH_STD_EXCEPTION, error.what());
    } catch (...) {
        setError(result, RUGRA_SLEIGH_UNKNOWN_EXCEPTION, "Unknown C++ exception");
    }
}

}  // namespace

extern "C" {

void* rugra_sleigh_create(const char* sla_path) noexcept {
    if (sla_path == nullptr)
        return nullptr;
    try {
        // Ghidra's XML parser stores scanner/parser state in process globals.
        // Serialize the complete initialization transaction so two safe Rust
        // constructors cannot enter non-reentrant xml_parse concurrently.
        std::lock_guard<std::mutex> initialization_lock(sleighInitializationMutex());
        AttributeId::initialize();
        ElementId::initialize();
        std::unique_ptr<RugraSleigh> state(new RugraSleigh());
        state->trans.reset(new Sleigh(&state->loader, &state->context));

        DocumentStorage document_storage;
        const string xml = "<sleigh>" + string(sla_path) + "</sleigh>";
        istringstream xml_stream(xml);
        Document* document = document_storage.parseDocument(xml_stream);
        document_storage.registerTag(document->getRoot());
        state->trans->initialize(document_storage);
        return state.release();
    } catch (...) {
        return nullptr;
    }
}

void* rugra_sleigh_set_image(void* handle, const uint8_t* bytes, uint64_t len,
                             uint64_t base_addr) noexcept {
    RugraSleighResult* result = allocateResult();
    if (result == nullptr)
        return nullptr;
    if (handle == nullptr) {
        setError(*result, RUGRA_SLEIGH_INVALID_ARGUMENT, "Null SLEIGH handle");
        return result;
    }

    RugraSleigh* state = static_cast<RugraSleigh*>(handle);
    if (state->decode_started) {
        setError(*result, RUGRA_SLEIGH_INVALID_STATE,
                 "Cannot replace a SLEIGH image after decoding has started");
        return result;
    }
    try {
        state->loader.setBytes(bytes, len, base_addr);
    } catch (...) {
        captureCurrentException(*result);
    }
    return result;
}

void* rugra_sleigh_set_context(void* handle, const char* name, int32_t value) noexcept {
    RugraSleighResult* result = allocateResult();
    if (result == nullptr)
        return nullptr;
    if (handle == nullptr || name == nullptr) {
        setError(*result, RUGRA_SLEIGH_INVALID_ARGUMENT,
                 "Null argument while setting SLEIGH context");
        return result;
    }

    RugraSleigh* state = static_cast<RugraSleigh*>(handle);
    if (state->decode_started) {
        setError(*result, RUGRA_SLEIGH_INVALID_STATE,
                 "Cannot change SLEIGH context after decoding has started");
        return result;
    }
    try {
        state->context.setVariableDefault(name, static_cast<uintm>(value));
    } catch (...) {
        captureCurrentException(*result);
    }
    return result;
}

void* rugra_sleigh_decode(void* handle, uint64_t offset) noexcept {
    RugraSleighResult* result = allocateResult();
    if (result == nullptr)
        return nullptr;
    if (handle == nullptr) {
        setError(*result, RUGRA_SLEIGH_INVALID_ARGUMENT, "Null SLEIGH handle");
        return result;
    }

    RugraSleigh* state = static_cast<RugraSleigh*>(handle);
    state->decode_started = true;
    try {
        const Address address(state->trans->getDefaultCodeSpace(), offset);
        RugraPcodeEmit emitter(*result, *state->trans);
        result->step = state->trans->oneInstruction(emitter, address);
    } catch (...) {
        captureCurrentException(*result);
    }
    return result;
}

uint32_t rugra_sleigh_result_abi_version(const void* result) noexcept {
    return result == nullptr ? 0U
                             : static_cast<const RugraSleighResult*>(result)->abi_version;
}

uint32_t rugra_sleigh_result_error_kind(const void* result) noexcept {
    return result == nullptr ? RUGRA_SLEIGH_INVALID_ARGUMENT
                             : static_cast<const RugraSleighResult*>(result)->error_kind;
}

int32_t rugra_sleigh_result_step(const void* result) noexcept {
    return result == nullptr ? 0 : static_cast<const RugraSleighResult*>(result)->step;
}

uint32_t rugra_sleigh_result_has_instruction_length(const void* result) noexcept {
    return result == nullptr
               ? 0U
               : static_cast<const RugraSleighResult*>(result)->has_instruction_length;
}

int32_t rugra_sleigh_result_instruction_length(const void* result) noexcept {
    return result == nullptr
               ? 0
               : static_cast<const RugraSleighResult*>(result)->instruction_length;
}

const uint8_t* rugra_sleigh_result_message_data(const void* result) noexcept {
    if (result == nullptr)
        return nullptr;
    const std::string& message = static_cast<const RugraSleighResult*>(result)->message;
    return message.empty() ? nullptr : reinterpret_cast<const uint8_t*>(message.data());
}

uint64_t rugra_sleigh_result_message_len(const void* result) noexcept {
    return result == nullptr ? 0U
                             : static_cast<uint64_t>(
                                   static_cast<const RugraSleighResult*>(result)->message.size());
}

uint64_t rugra_sleigh_result_num_ops(const void* result) noexcept {
    return result == nullptr ? 0U
                             : static_cast<uint64_t>(
                                   static_cast<const RugraSleighResult*>(result)->ops.size());
}

int32_t rugra_sleigh_result_op(const void* result, uint64_t index,
                               RugraPcodeOpC* output) noexcept {
    if (result == nullptr || output == nullptr)
        return 0;
    const std::vector<RugraOpRecord>& ops =
        static_cast<const RugraSleighResult*>(result)->ops;
    if (index >= ops.size())
        return 0;
    *output = ops[static_cast<size_t>(index)].op;
    return 1;
}

int32_t rugra_sleigh_result_input(const void* result, uint64_t op_index,
                                  uint64_t input_index, RugraVarnodeC* output) noexcept {
    if (result == nullptr || output == nullptr)
        return 0;
    const std::vector<RugraOpRecord>& ops =
        static_cast<const RugraSleighResult*>(result)->ops;
    if (op_index >= ops.size())
        return 0;
    const std::vector<RugraVarnodeC>& inputs =
        ops[static_cast<size_t>(op_index)].inputs;
    if (input_index >= inputs.size())
        return 0;
    *output = inputs[static_cast<size_t>(input_index)];
    return 1;
}

void rugra_sleigh_result_destroy(void* result) noexcept {
    delete static_cast<RugraSleighResult*>(result);
}

int32_t rugra_sleigh_instruction_length(void* handle, uint64_t offset) noexcept {
    if (handle == nullptr)
        return -1;
    RugraSleigh* state = static_cast<RugraSleigh*>(handle);
    state->decode_started = true;
    try {
        const Address address(state->trans->getDefaultCodeSpace(), offset);
        return state->trans->instructionLength(address);
    } catch (...) {
        return -1;
    }
}

int32_t rugra_sleigh_num_spaces(void* handle) noexcept {
    if (handle == nullptr)
        return -1;
    try {
        return static_cast<RugraSleigh*>(handle)->trans->numSpaces();
    } catch (...) {
        return -1;
    }
}

int32_t rugra_sleigh_space_info(void* handle, int32_t index, int32_t* out_type,
                                char* out_name, int32_t name_max) noexcept {
    if (handle == nullptr || index < 0 || out_type == nullptr || out_name == nullptr ||
        name_max <= 0)
        return 0;
    try {
        RugraSleigh* state = static_cast<RugraSleigh*>(handle);
        if (index >= state->trans->numSpaces())
            return 0;
        AddrSpace* space = state->trans->getSpace(index);
        if (space == nullptr)
            return 0;
        *out_type = static_cast<int32_t>(space->getType());
        std::strncpy(out_name, space->getName().c_str(), static_cast<size_t>(name_max));
        out_name[name_max - 1] = 0;
        return 1;
    } catch (...) {
        return 0;
    }
}

int32_t rugra_sleigh_num_registers(void* handle) noexcept {
    if (handle == nullptr)
        return -1;
    try {
        map<VarnodeData, string> registers;
        static_cast<RugraSleigh*>(handle)->trans->getAllRegisters(registers);
        if (registers.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max()))
            return -1;
        return static_cast<int32_t>(registers.size());
    } catch (...) {
        return -1;
    }
}

int32_t rugra_sleigh_register_info(void* handle, int32_t index, char* out_name,
                                   int32_t name_max, int32_t* out_space,
                                   uint64_t* out_offset, int32_t* out_size) noexcept {
    if (handle == nullptr || index < 0 || out_name == nullptr || name_max <= 0 ||
        out_space == nullptr || out_offset == nullptr || out_size == nullptr)
        return 0;
    try {
        map<VarnodeData, string> registers;
        static_cast<RugraSleigh*>(handle)->trans->getAllRegisters(registers);
        if (static_cast<size_t>(index) >= registers.size())
            return 0;
        auto iterator = registers.begin();
        std::advance(iterator, index);
        std::strncpy(out_name, iterator->second.c_str(), static_cast<size_t>(name_max));
        out_name[name_max - 1] = 0;
        *out_space = iterator->first.space->getIndex();
        *out_offset = iterator->first.offset;
        if (iterator->first.size > static_cast<uint4>(std::numeric_limits<int32_t>::max()))
            return 0;
        *out_size = static_cast<int32_t>(iterator->first.size);
        return 1;
    } catch (...) {
        return 0;
    }
}

void rugra_sleigh_destroy(void* handle) noexcept {
    try {
        delete static_cast<RugraSleigh*>(handle);
    } catch (...) {
    }
}

}  // extern "C"
