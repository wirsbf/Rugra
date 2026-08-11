#include "context.hh"
#include "loadimage.hh"
#include "marshal.hh"
#include "opcodes.hh"
#include "sleigh.hh"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using namespace ghidra;

const uintb IMAGE_BASE = 0x1000;
const char *const ARCHITECTURE = "x86:LE:64:default";
const char *const COMPILER_SPEC = "gcc";
const char *const LOADER_POLICY =
    "raw-uint64-modulo-start-tail-zero-fill";

struct ContextSetting {
  const char *name;
  uintm value;
};

const ContextSetting CONTEXT_SETTINGS[] = {
    {"addrsize", 2},
    {"opsize", 1},
    {"rexprefix", 0},
    {"longMode", 1},
};

std::string hex_uint(uintb value, int4 width) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::setfill('0') << std::setw(width)
         << value;
  return stream.str();
}

std::string hex_bytes(const std::vector<uint1> &bytes) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (std::vector<uint1>::const_iterator iter = bytes.begin();
       iter != bytes.end(); ++iter) {
    stream << std::setw(2) << static_cast<uint4>(*iter);
  }
  return stream.str();
}

std::string json_escape(const std::string &value) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (std::string::const_iterator iter = value.begin(); iter != value.end();
       ++iter) {
    const unsigned char character = static_cast<unsigned char>(*iter);
    switch (character) {
    case '"':
      stream << "\\\"";
      break;
    case '\\':
      stream << "\\\\";
      break;
    case '\b':
      stream << "\\b";
      break;
    case '\f':
      stream << "\\f";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (character < 0x20 || character >= 0x7f) {
        stream << "\\u" << std::setw(4) << static_cast<uint4>(character);
      } else {
        stream << static_cast<char>(character);
      }
      break;
    }
  }
  return stream.str();
}

struct SpaceRecord {
  int4 index;
  int4 type;
  std::string name;
};

SpaceRecord capture_space(const AddrSpace *space) {
  SpaceRecord record;
  if (space == (const AddrSpace *)0) {
    record.index = -1;
    record.type = -1;
    record.name = "<null>";
    return record;
  }
  record.index = space->getIndex();
  record.type = static_cast<int4>(space->getType());
  record.name = space->getName();
  return record;
}

void print_space(const SpaceRecord &space) {
  std::cout << "{\"index\":" << space.index << ",\"name\":\""
            << json_escape(space.name) << "\",\"type\":" << space.type
            << '}';
}

struct VarnodeRecord {
  bool is_space_id;
  SpaceRecord container_space;
  SpaceRecord target_space;
  uintb offset;
  uint4 size;
  uintb identity;
  std::string alias_key;
};

VarnodeRecord capture_varnode(OpCode opcode, int4 input_index,
                              const VarnodeData &varnode, uintb identity) {
  VarnodeRecord record;
  record.is_space_id =
      (opcode == CPUI_LOAD || opcode == CPUI_STORE) && input_index == 0;
  record.container_space = capture_space(varnode.space);
  record.offset = varnode.offset;
  record.size = varnode.size;
  record.identity = identity;

  std::ostringstream alias;
  if (record.is_space_id) {
    const AddrSpace *target =
        reinterpret_cast<const AddrSpace *>(static_cast<uintp>(varnode.offset));
    record.target_space = capture_space(target);
    alias << "spaceid:" << record.target_space.index << ':' << record.size;
  } else {
    record.target_space = capture_space((const AddrSpace *)0);
    alias << "varnode:" << record.container_space.index << ':'
          << hex_uint(record.offset, 16) << ':' << record.size;
  }
  record.alias_key = alias.str();
  return record;
}

void print_varnode(const VarnodeRecord &varnode) {
  if (varnode.is_space_id) {
    std::cout << "{\"alias_key\":\"" << json_escape(varnode.alias_key)
              << "\",\"container_space\":";
    print_space(varnode.container_space);
    std::cout << ",\"identity\":" << varnode.identity
              << ",\"kind\":\"spaceid\",\"size\":" << varnode.size
              << ",\"target_space\":";
    print_space(varnode.target_space);
    std::cout << '}';
    return;
  }

  std::cout << "{\"alias_key\":\"" << json_escape(varnode.alias_key)
            << "\",\"identity\":" << varnode.identity
            << ",\"kind\":\"varnode\",\"offset\":\""
            << hex_uint(varnode.offset, 16) << "\",\"size\":"
            << varnode.size << ",\"space\":";
  print_space(varnode.container_space);
  std::cout << '}';
}

struct OpRecord {
  SpaceRecord address_space;
  uintb address_offset;
  OpCode opcode;
  std::string opcode_name;
  int4 declared_input_count;
  bool has_output;
  VarnodeRecord output;
  std::vector<VarnodeRecord> inputs;
};

class RecordingPcodeEmit : public PcodeEmit {
  std::unordered_map<const VarnodeData *, uintb> identities;
  uintb next_identity;

  uintb identity_for(const VarnodeData *varnode) {
    std::unordered_map<const VarnodeData *, uintb>::const_iterator existing =
        identities.find(varnode);
    if (existing != identities.end())
      return existing->second;
    const uintb identity = next_identity++;
    identities[varnode] = identity;
    return identity;
  }

public:
  std::vector<OpRecord> operations;

  RecordingPcodeEmit() : next_identity(0) {}

  virtual void dump(const Address &address, OpCode opcode,
                    VarnodeData *output, VarnodeData *inputs, int4 input_count) {
    OpRecord record;
    record.address_space = capture_space(address.getSpace());
    record.address_offset = address.getOffset();
    record.opcode = opcode;
    record.opcode_name = get_opname(opcode);
    record.declared_input_count = input_count;
    record.has_output = output != (VarnodeData *)0;
    if (record.has_output)
      record.output =
          capture_varnode(opcode, -1, *output, identity_for(output));
    record.inputs.reserve(input_count);
    for (int4 index = 0; index < input_count; ++index)
      record.inputs.push_back(capture_varnode(
          opcode, index, inputs[index], identity_for(inputs + index)));
    operations.push_back(record);
  }
};

/// An owned buffer with the same short-read policy as RawLoadImage:
/// a request whose first byte is available is zero-filled past EOF, while a
/// request starting outside the image throws DataUnavailError.
class OwnedRawImage : public LoadImage {
  std::vector<uint1> bytes;
  uintb base_address;

  void throw_unavailable(int4 size, const Address &address) const {
    std::ostringstream message;
    message << "Unable to load " << std::dec << size << " bytes at "
            << address.getShortcut();
    address.printRaw(message);
    throw DataUnavailError(message.str());
  }

public:
  OwnedRawImage() : LoadImage("sleigh_decode_1204"), base_address(0) {}

  void set_image(const std::vector<uint1> &source, uintb base) {
    bytes = source;
    base_address = base;
  }

  virtual void loadFill(uint1 *destination, int4 size,
                        const Address &address) {
    const uintb requested = address.getOffset();
    // Exact RawLoadImage unsigned subtraction, including uint64 wrap.
    const uintb relative = requested - base_address;
    if (relative >= bytes.size())
      throw_unavailable(size, address);

    const uintb available = bytes.size() - relative;
    const int4 copied =
        static_cast<int4>(std::min<uintb>(static_cast<uintb>(size), available));
    std::copy(bytes.begin() + relative, bytes.begin() + relative + copied,
              destination);
    if (copied < size)
      std::fill(destination + copied, destination + size, 0);
  }

  virtual std::string getArchType(void) const { return ARCHITECTURE; }

  virtual void adjustVma(long adjust) {
    base_address = static_cast<uintb>(base_address + adjust);
  }
};

enum DecodeStatus {
  STATUS_OK,
  STATUS_UNIMPL,
  STATUS_BAD_DATA,
  STATUS_DATA_UNAVAILABLE,
  STATUS_OTHER,
};

const char *status_name(DecodeStatus status) {
  switch (status) {
  case STATUS_OK:
    return "OK";
  case STATUS_UNIMPL:
    return "UNIMPL";
  case STATUS_BAD_DATA:
    return "BAD_DATA";
  case STATUS_DATA_UNAVAILABLE:
    return "DATA_UNAVAILABLE";
  case STATUS_OTHER:
    return "OTHER";
  }
  return "OTHER";
}

struct DecodeResult {
  DecodeStatus status;
  bool has_step;
  int4 step;
  bool has_instruction_length;
  int4 instruction_length;
  std::string explain;
  std::vector<OpRecord> operations;

  DecodeResult()
      : status(STATUS_OTHER), has_step(false), step(0),
        has_instruction_length(false), instruction_length(0) {}
};

class FixtureEngine {
  OwnedRawImage loader;
  ContextInternal context;
  Sleigh translator;

public:
  explicit FixtureEngine(const std::string &sla_path)
      : translator(&loader, &context) {
    DocumentStorage storage;
    const std::string document = "<sleigh>" + sla_path + "</sleigh>";
    std::istringstream stream(document);
    Document *parsed = storage.parseDocument(stream);
    storage.registerTag(parsed->getRoot());
    translator.initialize(storage);
    for (uint4 index = 0;
         index < sizeof(CONTEXT_SETTINGS) / sizeof(CONTEXT_SETTINGS[0]);
         ++index) {
      translator.setContextDefault(CONTEXT_SETTINGS[index].name,
                                   CONTEXT_SETTINGS[index].value);
    }
  }

  void set_image(const std::vector<uint1> &bytes, uintb base) {
    loader.set_image(bytes, base);
  }

  DecodeResult decode(uintb offset) {
    DecodeResult result;
    RecordingPcodeEmit emitter;
    const Address address(translator.getDefaultCodeSpace(), offset);
    try {
      result.step = translator.oneInstruction(emitter, address);
      result.has_step = true;
      result.status = STATUS_OK;
      result.operations.swap(emitter.operations);
    } catch (const UnimplError &error) {
      result.status = STATUS_UNIMPL;
      result.has_instruction_length = true;
      result.instruction_length = error.instruction_length;
      result.explain = error.explain;
    } catch (const BadDataError &error) {
      result.status = STATUS_BAD_DATA;
      result.explain = error.explain;
    } catch (const DataUnavailError &error) {
      result.status = STATUS_DATA_UNAVAILABLE;
      result.explain = error.explain;
    } catch (const LowlevelError &error) {
      result.status = STATUS_OTHER;
      result.explain = error.explain;
    } catch (...) {
      result.status = STATUS_OTHER;
      result.explain = "unknown C++ exception";
    }
    return result;
  }
};

struct CaseInput {
  std::string id;
  std::vector<uint1> image;
  std::string image_sha256;
  uintb base;
  uintb offset;
  std::string setup;
  std::string source_after_hex;
};

void print_operation(const OpRecord &operation, uint4 index) {
  std::cout << "{\"address\":{\"offset\":\""
            << hex_uint(operation.address_offset, 16) << "\",\"space\":";
  print_space(operation.address_space);
  std::cout << "},\"declared_input_count\":"
            << operation.declared_input_count << ",\"index\":" << index
            << ",\"inputs\":[";
  for (uint4 input_index = 0; input_index < operation.inputs.size();
       ++input_index) {
    if (input_index != 0)
      std::cout << ',';
    print_varnode(operation.inputs[input_index]);
  }
  std::cout << "],\"opcode\":{\"name\":\""
            << json_escape(operation.opcode_name) << "\",\"value\":"
            << static_cast<int4>(operation.opcode) << "},\"output\":";
  if (operation.has_output)
    print_varnode(operation.output);
  else
    std::cout << "null";
  std::cout << '}';
}

void print_context(void) {
  std::cout << '[';
  for (uint4 index = 0;
       index < sizeof(CONTEXT_SETTINGS) / sizeof(CONTEXT_SETTINGS[0]);
       ++index) {
    if (index != 0)
      std::cout << ',';
    std::cout << "{\"name\":\"" << CONTEXT_SETTINGS[index].name
              << "\",\"value\":" << CONTEXT_SETTINGS[index].value << '}';
  }
  std::cout << ']';
}

void print_case(const CaseInput &input, const DecodeResult &result) {
  std::cout << "{\"architecture\":\"" << ARCHITECTURE
            << "\",\"case\":\"" << json_escape(input.id)
            << "\",\"compiler_spec\":\"" << COMPILER_SPEC
            << "\",\"input\":{\"base\":\"" << hex_uint(input.base, 16)
            << "\",\"context\":";
  print_context();
  std::cout << ",\"image_hex\":\"" << hex_bytes(input.image)
            << "\",\"image_sha256\":\"" << input.image_sha256
            << "\",\"loader_policy\":\"" << LOADER_POLICY
            << "\",\"offset\":\"" << hex_uint(input.offset, 16)
            << "\",\"setup\":\"" << json_escape(input.setup)
            << "\",\"source_after_hex\":";
  if (input.source_after_hex.empty())
    std::cout << "null";
  else
    std::cout << '"' << input.source_after_hex << '"';
  std::cout << "},\"result\":{\"explain\":";
  if (result.explain.empty())
    std::cout << "null";
  else
    std::cout << '"' << json_escape(result.explain) << '"';
  std::cout << ",\"instruction_length\":";
  if (result.has_instruction_length)
    std::cout << result.instruction_length;
  else
    std::cout << "null";
  std::cout << ",\"op_count\":" << result.operations.size()
            << ",\"ops\":[";
  for (uint4 index = 0; index < result.operations.size(); ++index) {
    if (index != 0)
      std::cout << ',';
    print_operation(result.operations[index], index);
  }
  std::cout << "],\"status\":\"" << status_name(result.status)
            << "\",\"step\":";
  if (result.has_step)
    std::cout << result.step;
  else
    std::cout << "null";
  std::cout << "},\"schema\":1}\n";
}

void run_fresh_case(const std::string &sla_path, const CaseInput &input) {
  FixtureEngine engine(sla_path);
  engine.set_image(input.image, input.base);
  print_case(input, engine.decode(input.offset));
}

std::vector<uint1> padded(const std::vector<uint1> &prefix, uint4 size) {
  std::vector<uint1> result(size, 0);
  std::copy(prefix.begin(), prefix.end(), result.begin());
  return result;
}

void print_unimpl_coverage(void) {
  std::cout
      << "{\"architecture\":\"x86:LE:64:default\","
         "\"case\":\"unimpl_x86_reachability\","
         "\"compiler_spec\":\"gcc\","
         "\"coverage\":{\"alignment\":1,\"constructors\":5707,"
         "\"null_templates\":0,\"reason\":\"locked x86-64 SLA has no "
         "reachable UnimplError path\",\"status\":\"UNTESTED\","
         "\"subtables\":236},\"schema\":1}\n";
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: sleigh_decode_1204 <x86-64.sla>\n";
    return 2;
  }

  try {
    AttributeId::initialize();
    ElementId::initialize();
    const std::string sla_path(argv[1]);

    const CaseInput cpuid = {
        "cpuid_78_ops",
        padded(std::vector<uint1>{0x0f, 0xa2}, 32),
        "14ccfec470ee23093cc1f8d012600da47d772d4914cfbd1b21e4d0f46898bf7a",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-image",
        "",
    };
    run_fresh_case(sla_path, cpuid);

    const CaseInput nop = {
        "nop_zero_ops",
        padded(std::vector<uint1>{0x90}, 32),
        "a3a2808c37da4f9cab6a51e07ddfc6c34f725988fe2486199d6a190c1be473a4",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-image",
        "",
    };
    run_fresh_case(sla_path, nop);

    const CaseInput jump_tail = {
        "jmp_short_one_byte_tail_zero_fill",
        std::vector<uint1>{0xeb},
        "f8d20e598df20877e4d826246fc31ffb4615cbc059aec9ec8e5b28951d844a3f",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-image-tail-zero-fill",
        "",
    };
    run_fresh_case(sla_path, jump_tail);

    const CaseInput modulo_wrap = {
        "nop_uint64_modulo_wrap",
        std::vector<uint1>{0x06, 0x90},
        "b54d7f43052bd9abe02ed4947f9c2c22cf2de16b1e20b5539b891dbfaea26571",
        std::numeric_limits<uintb>::max(),
        0,
        "fresh-owned-image-uint64-modulo-wrap",
        "",
    };
    run_fresh_case(sla_path, modulo_wrap);

    const CaseInput pointer_alias = {
        "mov_rax_ptr_rbx_pointer_alias",
        padded(std::vector<uint1>{0x48, 0x8b, 0x03}, 32),
        "5d2820090d89afc6a0c12333ec23d6a40bb6d63b0dd8829d9153fc45dd8b3a30",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-image-pointer-alias",
        "",
    };
    run_fresh_case(sla_path, pointer_alias);

    const CaseInput bad_data = {
        "bad_data",
        padded(std::vector<uint1>{0x0f, 0x04}, 32),
        "5804d1599a661578dbf83f3e674619c04e71d36df54c5172d75ecd8df992f2b9",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-image",
        "",
    };
    run_fresh_case(sla_path, bad_data);

    const CaseInput unavailable_empty = {
        "data_unavailable_empty_image",
        std::vector<uint1>(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        IMAGE_BASE,
        IMAGE_BASE,
        "fresh-owned-empty-image",
        "",
    };
    run_fresh_case(sla_path, unavailable_empty);

    const CaseInput unavailable_below = {
        "data_unavailable_below_base",
        std::vector<uint1>{0x90},
        "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
        IMAGE_BASE,
        IMAGE_BASE - 1,
        "fresh-owned-image-decode-below-base",
        "",
    };
    run_fresh_case(sla_path, unavailable_below);

    const CaseInput unavailable_after = {
        "data_unavailable_at_end",
        std::vector<uint1>{0x90},
        "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
        IMAGE_BASE,
        IMAGE_BASE + 1,
        "fresh-owned-image-decode-at-end",
        "",
    };
    run_fresh_case(sla_path, unavailable_after);

    {
      std::vector<uint1> source(1, 0x90);
      FixtureEngine engine(sla_path);
      engine.set_image(source, IMAGE_BASE);
      source[0] = 0x06;
      source.clear();
      source.shrink_to_fit();
      const CaseInput owned_mutation = {
          "owned_source_mutation",
          std::vector<uint1>{0x90},
          "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
          IMAGE_BASE,
          IMAGE_BASE,
          "RUGRA-GLUE owned copy; caller mutates 90 to 06 then releases source",
          "06",
      };
      print_case(owned_mutation, engine.decode(IMAGE_BASE));
    }

    {
      std::vector<uint1> sequence_image(64, 0);
      sequence_image[0] = 0x48;
      sequence_image[1] = 0x89;
      sequence_image[2] = 0xf8;
      sequence_image[32] = 0x0f;
      sequence_image[33] = 0x04;
      FixtureEngine engine(sla_path);
      engine.set_image(sequence_image, IMAGE_BASE);
      const std::string sequence_sha =
          "308f821b209c6665e83718770fe5117e2d270fae4f9f3bf39111ba7f06c58290";
      const CaseInput success = {
          "success_then_error_0_success",
          sequence_image,
          sequence_sha,
          IMAGE_BASE,
          IMAGE_BASE,
          "shared-engine-sequence-step-0",
          "",
      };
      print_case(success, engine.decode(success.offset));
      const CaseInput error = {
          "success_then_error_1_error",
          sequence_image,
          sequence_sha,
          IMAGE_BASE,
          IMAGE_BASE + 32,
          "shared-engine-sequence-step-1; error result must publish zero ops",
          "",
      };
      print_case(error, engine.decode(error.offset));
    }

    print_unimpl_coverage();
  } catch (const LowlevelError &error) {
    std::cerr << "sleigh_decode_1204 setup failed: " << error.explain << '\n';
    return 1;
  } catch (...) {
    std::cerr << "sleigh_decode_1204 setup failed: unknown C++ exception\n";
    return 1;
  }
  return 0;
}
