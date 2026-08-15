/*
 * CSPEC-RANGEPROPS-0001: locked Ghidra 12.0.4 RangeProperties oracle.
 *
 * The fixture supplies a deterministic Decoder so every virtual call, source
 * attribute position, close operation, and decoder-open residue is observable.
 */
#include "address.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::string;
using std::vector;

struct RangePropertiesView {
  string spaceName;
  uintb first;
  uintb last;
  bool isRegister;
  bool seenLast;
};

static_assert(sizeof(RangePropertiesView) == sizeof(RangeProperties),
              "locked RangeProperties ABI layout changed");

const RangePropertiesView &view(const RangeProperties &properties)
{
  return *reinterpret_cast<const RangePropertiesView *>(&properties);
}

struct Attribute {
  uint4 id;
  bool isString;
  string stringValue;
  uintb unsignedValue;

  static Attribute text(uint4 id,const string &value)
  {
    Attribute result = { id, true, value, 0 };
    return result;
  }

  static Attribute number(uint4 id,uintb value)
  {
    Attribute result = { id, false, string(), value };
    return result;
  }

  static Attribute ignored(uint4 id)
  {
    Attribute result = { id, true, "ignored", 0 };
    return result;
  }
};

class TraceDecoder : public Decoder {
  uint4 elementId;
  vector<Attribute> attributes;
  size_t attributePosition;
  size_t currentAttribute;
  int4 childCount;
public:
  vector<string> trace;
  bool elementOpen;
  int4 childrenAtClose;
  int4 childOpenCount;
  int4 peekCount;

  TraceDecoder(uint4 id,const vector<Attribute> &attrs,int4 children = 0)
    : Decoder((const AddrSpaceManager *)0), elementId(id), attributes(attrs),
      attributePosition(0), currentAttribute(0), childCount(children),
      elementOpen(false), childrenAtClose(-1), childOpenCount(0), peekCount(0) {}

  virtual void ingestStream(std::istream &) {}

  virtual uint4 peekElement(void)
  {
    ++peekCount;
    return elementOpen && childCount != 0 ? 99 : 0;
  }

  virtual uint4 openElement(void)
  {
    if (elementOpen) {
      ++childOpenCount;
      trace.push_back("open-child:99");
      return 99;
    }
    elementOpen = true;
    trace.push_back("open:" + std::to_string(elementId));
    return elementId;
  }

  virtual uint4 openElement(const ElementId &expected)
  {
    uint4 id = openElement();
    if (id != expected.getId())
      throw DecoderError("unexpected fixture element");
    return id;
  }

  virtual void closeElement(uint4 id)
  {
    trace.push_back("close:" + std::to_string(id));
    childrenAtClose = childCount;
    elementOpen = false;
  }

  virtual void closeElementSkipping(uint4 id)
  {
    trace.push_back("close-skipping:" + std::to_string(id));
    childrenAtClose = childCount;
    elementOpen = false;
  }

  virtual uint4 getNextAttributeId(void)
  {
    if (attributePosition == attributes.size()) {
      trace.push_back("next:0");
      return 0;
    }
    currentAttribute = attributePosition;
    uint4 id = attributes[attributePosition].id;
    ++attributePosition;
    trace.push_back("next:" + std::to_string(id));
    return id;
  }

  virtual uint4 getIndexedAttributeId(const AttributeId &) { return 159; }

  virtual void rewindAttributes(void)
  {
    attributePosition = 0;
    currentAttribute = 0;
    trace.push_back("rewind");
  }

  virtual bool readBool(void) { return false; }
  virtual bool readBool(const AttributeId &) { return false; }
  virtual intb readSignedInteger(void) { return 0; }
  virtual intb readSignedInteger(const AttributeId &) { return 0; }
  virtual intb readSignedIntegerExpectString(const string &,intb value) { return value; }
  virtual intb readSignedIntegerExpectString(const AttributeId &,const string &,intb value) { return value; }

  virtual uintb readUnsignedInteger(void)
  {
    const Attribute &attribute(attributes[currentAttribute]);
    trace.push_back("uint:" + std::to_string(attribute.unsignedValue));
    return attribute.unsignedValue;
  }

  virtual uintb readUnsignedInteger(const AttributeId &) { return readUnsignedInteger(); }

  virtual string readString(void)
  {
    const string &value(attributes[currentAttribute].stringValue);
    trace.push_back("string:" + value);
    return value;
  }

  virtual string readString(const AttributeId &) { return readString(); }
  virtual AddrSpace *readSpace(void) { return (AddrSpace *)0; }
  virtual AddrSpace *readSpace(const AttributeId &) { return (AddrSpace *)0; }
  virtual OpCode readOpcode(void) { return CPUI_COPY; }
  virtual OpCode readOpcode(AttributeId &) { return CPUI_COPY; }
};

string joinTrace(const vector<string> &trace)
{
  std::ostringstream stream;
  for(size_t i=0;i<trace.size();++i) {
    if (i != 0) stream << ',';
    stream << trace[i];
  }
  return stream.str();
}

void observe(const string &name,const RangeProperties &props,const TraceDecoder &decoder,
             const string &result,const string &error)
{
  const RangePropertiesView &state(view(props));
  std::cout << "case=" << name
            << "|result=" << result
            << "|error=" << error
            << "|space=" << state.spaceName
            << "|first=" << state.first
            << "|last=" << state.last
            << "|is_register=" << state.isRegister
            << "|seen_last=" << state.seenLast
            << "|trace=" << joinTrace(decoder.trace)
            << "|decoder_open=" << decoder.elementOpen
            << "|children_at_close=" << decoder.childrenAtClose
            << "|child_opens=" << decoder.childOpenCount
            << "|peek_calls=" << decoder.peekCount << '\n';
}

void decodeAndObserve(const string &name,RangeProperties &props,TraceDecoder &decoder)
{
  try {
    props.decode(decoder);
    observe(name,props,decoder,"OK","-");
  }
  catch(const DecoderError &error) {
    observe(name,props,decoder,"DecoderError",error.explain);
  }
}

void observeTreeDecoder(const string &name,const RangeProperties &props,const vector<string> &trace,
                        const string &result,const string &error)
{
  const RangePropertiesView &state(view(props));
  std::cout << "case=" << name
            << "|result=" << result
            << "|error=" << error
            << "|space=" << state.spaceName
            << "|first=" << state.first
            << "|last=" << state.last
            << "|is_register=" << state.isRegister
            << "|seen_last=" << state.seenLast
            << "|trace=" << joinTrace(trace)
            << "|decoder_open=0"
            << "|children_at_close=0"
            << "|child_opens=0"
            << "|peek_calls=2" << '\n';
}

void decodeTreeAndObserve(const string &name,RangeProperties &props,Decoder &decoder,
                          const vector<string> &trace)
{
  try {
    props.decode(decoder);
    observeTreeDecoder(name,props,trace,"OK","-");
  }
  catch(const DecoderError &error) {
    observeTreeDecoder(name,props,trace,"DecoderError",error.explain);
  }
}

void run(void)
{
  std::cout << "schema=1|fixture=CSPEC-RANGEPROPS-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";

  RangeProperties defaults;
  TraceDecoder defaultsDecoder(ELEM_RANGE.getId(),vector<Attribute>());
  decodeAndObserve("defaults",defaults,defaultsDecoder);

  vector<Attribute> orderedAttributes;
  orderedAttributes.push_back(Attribute::text(ATTRIB_SPACE.getId(),"ram"));
  orderedAttributes.push_back(Attribute::ignored(159));
  orderedAttributes.push_back(Attribute::number(ATTRIB_FIRST.getId(),16));
  orderedAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),32));
  RangeProperties ordered;
  TraceDecoder orderedDecoder(ELEM_RANGE.getId(),orderedAttributes);
  decodeAndObserve("ordered_unknown",ordered,orderedDecoder);

  vector<Attribute> nameThenSpaceAttributes;
  nameThenSpaceAttributes.push_back(Attribute::text(ATTRIB_NAME.getId(),"RAX"));
  nameThenSpaceAttributes.push_back(Attribute::text(ATTRIB_SPACE.getId(),"register"));
  nameThenSpaceAttributes.push_back(Attribute::number(ATTRIB_FIRST.getId(),8));
  RangeProperties nameThenSpace;
  TraceDecoder nameThenSpaceDecoder(ELEM_REGISTER.getId(),nameThenSpaceAttributes);
  decodeAndObserve("name_then_space",nameThenSpace,nameThenSpaceDecoder);

  vector<Attribute> rangeNameAttributes;
  rangeNameAttributes.push_back(Attribute::text(ATTRIB_SPACE.getId(),"ram"));
  rangeNameAttributes.push_back(Attribute::text(ATTRIB_NAME.getId(),"RSP"));
  rangeNameAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),~((uintb)0)));
  RangeProperties rangeName;
  TraceDecoder rangeNameDecoder(ELEM_RANGE.getId(),rangeNameAttributes);
  decodeAndObserve("range_name",rangeName,rangeNameDecoder);

  vector<Attribute> duplicateAttributes;
  duplicateAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),5));
  duplicateAttributes.push_back(Attribute::text(ATTRIB_NAME.getId(),"RAX"));
  duplicateAttributes.push_back(Attribute::text(ATTRIB_SPACE.getId(),"ram"));
  duplicateAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),9));
  duplicateAttributes.push_back(Attribute::text(ATTRIB_NAME.getId(),"RBX"));
  RangeProperties duplicate;
  TraceDecoder duplicateDecoder(ELEM_RANGE.getId(),duplicateAttributes);
  decodeAndObserve("duplicates",duplicate,duplicateDecoder);

  vector<Attribute> firstPersistentAttributes;
  firstPersistentAttributes.push_back(Attribute::text(ATTRIB_NAME.getId(),"RDI"));
  firstPersistentAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),7));
  RangeProperties persistent;
  TraceDecoder firstPersistentDecoder(ELEM_REGISTER.getId(),firstPersistentAttributes);
  decodeAndObserve("persistent_first",persistent,firstPersistentDecoder);

  vector<Attribute> secondPersistentAttributes;
  secondPersistentAttributes.push_back(Attribute::number(ATTRIB_FIRST.getId(),3));
  TraceDecoder secondPersistentDecoder(ELEM_RANGE.getId(),secondPersistentAttributes);
  decodeAndObserve("persistent_second",persistent,secondPersistentDecoder);

  TraceDecoder invalidDecoder(77,vector<Attribute>());
  decodeAndObserve("invalid_after_success",persistent,invalidDecoder);

  vector<Attribute> childAttributes;
  childAttributes.push_back(Attribute::text(ATTRIB_SPACE.getId(),"ram"));
  RangeProperties child;
  TraceDecoder childDecoder(ELEM_RANGE.getId(),childAttributes,2);
  decodeAndObserve("child_unvisited",child,childDecoder);

  vector<Attribute> boundaryAttributes;
  boundaryAttributes.push_back(Attribute::number(ATTRIB_FIRST.getId(),0));
  boundaryAttributes.push_back(Attribute::number(ATTRIB_LAST.getId(),~((uintb)0)));
  RangeProperties boundary;
  TraceDecoder boundaryDecoder(ELEM_RANGE.getId(),boundaryAttributes);
  decodeAndObserve("u64_boundary",boundary,boundaryDecoder);

  // Real XmlDecode over an in-memory Element: an unregistered attribute name
  // must resolve through AttributeId::find to the locked unknown id 159 and
  // traversal must continue through the later first/last attributes.
  AttributeId::initialize();
  ElementId::initialize();
  Element unregisteredElement((Element *)0);
  unregisteredElement.setName("range");
  unregisteredElement.addAttribute("space","ram");
  unregisteredElement.addAttribute("xmlunknown-attr","ignored");
  unregisteredElement.addAttribute("first","16");
  unregisteredElement.addAttribute("last","32");

  vector<string> rawTrace;
  XmlDecode rawDecoder((const AddrSpaceManager *)0,&unregisteredElement);
  rawTrace.push_back("peek:" + std::to_string(rawDecoder.peekElement()));
  uint4 rawElementId = rawDecoder.openElement();
  rawTrace.push_back("open:" + std::to_string(rawElementId));
  for(;;) {
    uint4 rawAttribId = rawDecoder.getNextAttributeId();
    rawTrace.push_back("next:" + std::to_string(rawAttribId));
    if (rawAttribId == 0)
      break;
    if (rawAttribId == ATTRIB_SPACE.getId() || rawAttribId == ATTRIB_NAME.getId())
      rawTrace.push_back("string:" + rawDecoder.readString());
    else if (rawAttribId == ATTRIB_FIRST.getId() || rawAttribId == ATTRIB_LAST.getId())
      rawTrace.push_back("uint:" + std::to_string(rawDecoder.readUnsignedInteger()));
  }
  rawDecoder.closeElement(rawElementId);
  rawTrace.push_back("close:" + std::to_string(rawElementId));
  rawTrace.push_back("peek:" + std::to_string(rawDecoder.peekElement()));
  rawTrace.push_back("open:" + std::to_string(rawDecoder.openElement()));

  RangeProperties unregisteredProps;
  XmlDecode unregisteredDecoder((const AddrSpaceManager *)0,&unregisteredElement);
  decodeTreeAndObserve("tree_decoder_unregistered",unregisteredProps,unregisteredDecoder,rawTrace);
}

} // namespace

int main(void)
{
  run();
  return 0;
}
