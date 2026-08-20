/*
 * COMMENT-WARNING-CODEC-0001: locked Ghidra 12.0.4 oracle for
 * Comment::{encode,decode} and CommentDatabaseInternal's ordered in-memory
 * add/deduplicate/filter/codec behavior.
 */

#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "comment.hh"
#include "marshal.hh"
#include "translate.hh"

using namespace ghidra;

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                              AddrSpace::hasphysical, 0, 0));
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(3);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

static void render_function(const CommentDatabaseInternal &db, const Address &fad) {
  bool first = true;
  CommentSet::const_iterator iter = db.beginComment(fad);
  CommentSet::const_iterator enditer = db.endComment(fad);
  std::cout << '[';
  for (; iter != enditer; ++iter) {
    const Comment *comment = *iter;
    if (!first)
      std::cout << ';';
    first = false;
    std::cout << comment->getType() << ':'
              << comment->getFuncAddr().getOffset() << ':'
              << comment->getAddr().getOffset() << ':'
              << comment->getUniq() << ':' << comment->getText();
  }
  std::cout << ']';
}

static void run_roundtrip(FixtureTranslate &translate) {
  AddrSpace *ram = translate.getSpace(3);
  Address fad(ram, 0x1000);
  CommentDatabaseInternal source;
  source.addComment(Comment::header, fad, fad, "Header");
  source.addComment(Comment::warning, fad, Address(ram, 0x2000), "Test warning");
  source.addComment(Comment::warning, fad, Address(ram, 0x2000), "Second warning");
  bool duplicate = source.addCommentNoDuplicate(
      Comment::user2, fad, Address(ram, 0x2000), "Test warning");
  bool inserted = source.addCommentNoDuplicate(
      Comment::user2, fad, Address(ram, 0x2000), "User note");

  std::ostringstream encoded;
  XmlEncode encoder(encoded, false);
  source.encode(encoder);
  std::string xml = encoded.str();
  bool schema_ok = xml.find("<addr space=\"ram\" offset=\"0x1000\"/>") != std::string::npos &&
                   xml.find("<addr space=\"ram\" offset=\"0x2000\"/>") != std::string::npos &&
                   xml.find("<text>Test warning</text>") != std::string::npos;

  std::istringstream input(xml);
  XmlDecode decoder(&translate);
  decoder.ingestStream(input);
  CommentDatabaseInternal decoded;
  decoded.decode(decoder);

  std::cout << "case=roundtrip|schema=" << (schema_ok ? 1 : 0)
            << "|duplicate=" << (duplicate ? 1 : 0)
            << "|inserted=" << (inserted ? 1 : 0) << "|comments=";
  render_function(decoded, fad);
  std::cout << '\n';
}

static void run_filter(FixtureTranslate &translate) {
  AddrSpace *ram = translate.getSpace(3);
  Address fad(ram, 0x1000);
  Address other_fad(ram, 0x5000);
  CommentDatabaseInternal db;
  db.addComment(Comment::warningheader, fad, fad, "Warning header");
  db.addComment(Comment::header, fad, fad, "Header");
  db.addComment(Comment::warning, fad, Address(ram, 0x2000), "Inline warning");
  db.addComment(Comment::user2, fad, Address(ram, 0x3000), "User note");
  db.addComment(Comment::warning, other_fad, Address(ram, 0x6000), "Other warning");
  db.clearType(fad, Comment::warning | Comment::warningheader);

  std::cout << "case=filter|f1000=";
  render_function(db, fad);
  std::cout << "|f5000=";
  render_function(db, other_fad);
  std::cout << '\n';
}

static void run_unknown_type_partial(FixtureTranslate &translate) {
  AddrSpace *ram = translate.getSpace(3);
  Comment comment(Comment::header, Address(ram, 0xaaaa), Address(ram, 0xbbbb),
                  7, "sentinel");
  comment.setEmitted(true);
  std::string error;
  try {
    std::istringstream input("<comment type=\"bogus\"/>");
    XmlDecode decoder(&translate);
    decoder.ingestStream(input);
    comment.decode(decoder);
  }
  catch (const LowlevelError &err) {
    error = err.explain;
  }
  std::cout << "case=unknown_type|error=" << error
            << "|type=" << comment.getType()
            << "|emitted=" << (comment.isEmitted() ? 1 : 0)
            << "|func=" << comment.getFuncAddr().getOffset()
            << "|addr=" << comment.getAddr().getOffset()
            << "|uniq=" << comment.getUniq()
            << "|text=" << comment.getText() << '\n';
}

static void run_missing_offset_partial(FixtureTranslate &translate) {
  AddrSpace *ram = translate.getSpace(3);
  Comment comment(Comment::header, Address(ram, 0xaaaa), Address(ram, 0xbbbb),
                  7, "sentinel");
  comment.setEmitted(true);
  std::string error;
  try {
    std::istringstream input(
        "<comment type=\"warning\"><addr space=\"ram\"/>"
        "<addr space=\"ram\" offset=\"0xbbbb\"/><text>replacement</text></comment>");
    XmlDecode decoder(&translate);
    decoder.ingestStream(input);
    comment.decode(decoder);
  }
  catch (const LowlevelError &err) {
    error = err.explain;
  }
  std::cout << "case=missing_offset|error=" << error
            << "|type=" << comment.getType()
            << "|emitted=" << (comment.isEmitted() ? 1 : 0)
            << "|func=" << comment.getFuncAddr().getOffset()
            << "|addr=" << comment.getAddr().getOffset()
            << "|uniq=" << comment.getUniq()
            << "|text=" << comment.getText() << '\n';
}

static void run_unknown_property_encode(FixtureTranslate &translate) {
  AddrSpace *ram = translate.getSpace(3);
  Comment comment(64, Address(ram, 0xaaaa), Address(ram, 0xbbbb),
                  7, "sentinel");
  comment.setEmitted(true);
  std::ostringstream encoded;
  XmlEncode encoder(encoded, false);
  std::string error;
  try {
    comment.encode(encoder);
  }
  catch (const LowlevelError &err) {
    error = err.explain;
  }
  std::cout << "case=unknown_property_encode|error=" << error
            << "|stream_empty=" << (encoded.str().empty() ? 1 : 0)
            << "|type=" << comment.getType()
            << "|emitted=" << (comment.isEmitted() ? 1 : 0)
            << "|func=" << comment.getFuncAddr().getOffset()
            << "|addr=" << comment.getAddr().getOffset()
            << "|uniq=" << comment.getUniq()
            << "|text=" << comment.getText() << '\n';
}

int main() {
  AttributeId::initialize();
  ElementId::initialize();
  FixtureTranslate translate;
  std::cout << "schema=1|fixture=COMMENT-WARNING-CODEC-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b\n";
  run_roundtrip(translate);
  run_filter(translate);
  run_unknown_type_partial(translate);
  run_missing_offset_partial(translate);
  run_unknown_property_encode(translate);
  return 0;
}
