#include "marshal.hh"
#include "marshal_id_generated.hh"

#include <iostream>
#include <string>

namespace ghidra {

#define DECLARE_ATTRIBUTE(symbol) extern AttributeId symbol;
ATTRIBUTE_OBJECTS(DECLARE_ATTRIBUTE)
#undef DECLARE_ATTRIBUTE

#define DECLARE_ELEMENT(symbol) extern ElementId symbol;
ELEMENT_OBJECTS(DECLARE_ELEMENT)
#undef DECLARE_ELEMENT

#define ATTRIBUTE_POINTER(symbol) &symbol,
static AttributeId *attributeObjects[] = {
  ATTRIBUTE_OBJECTS(ATTRIBUTE_POINTER)
};
#undef ATTRIBUTE_POINTER

#define ELEMENT_POINTER(symbol) &symbol,
static ElementId *elementObjects[] = {
  ELEMENT_OBJECTS(ELEMENT_POINTER)
};
#undef ELEMENT_POINTER

static const char *attributeNameById(uint4 id)

{
  for(size_t i=0;i<sizeof(attributeObjects)/sizeof(attributeObjects[0]);++i) {
    if (attributeObjects[i]->getId() == id)
      return attributeObjects[i]->getName().c_str();
  }
  return (const char *)0;
}

static const char *elementNameById(uint4 id)

{
  for(size_t i=0;i<sizeof(elementObjects)/sizeof(elementObjects[0]);++i) {
    if (elementObjects[i]->getId() == id)
      return elementObjects[i]->getName().c_str();
  }
  return (const char *)0;
}

static void emitTreeState(void)

{
  Element root((Element *)0);
  root.setName("data");
  root.addAttribute("size", "1");
  root.addAttribute("fixture_unknown_attribute", "2");
  root.addAttribute("space", "ram");

  Element *knownChild = new Element(&root);
  knownChild->setName("data");
  root.addChild(knownChild);
  Element *unknownChild = new Element(&root);
  unknownChild->setName("fixture_unknown_element");
  root.addChild(unknownChild);

  XmlDecode decoder((const AddrSpaceManager *)0, &root);
  uint4 peekRoot = decoder.peekElement();
  uint4 openRoot = decoder.openElement();
  uint4 attr0 = decoder.getNextAttributeId();
  uint4 attr1 = decoder.getNextAttributeId();
  uint4 attr2 = decoder.getNextAttributeId();
  uint4 attrEnd = decoder.getNextAttributeId();
  uint4 peekKnown = decoder.peekElement();
  uint4 openKnown = decoder.openElement();
  uint4 knownAttrEnd = decoder.getNextAttributeId();
  decoder.closeElement(openKnown);
  uint4 peekUnknown = decoder.peekElement();
  uint4 openUnknown = decoder.openElement();
  uint4 unknownAttrEnd = decoder.getNextAttributeId();
  decoder.closeElement(openUnknown);
  uint4 childEnd = decoder.peekElement();
  decoder.closeElement(openRoot);
  uint4 afterClosePeek = decoder.peekElement();
  uint4 afterCloseOpen = decoder.openElement();

  std::cout << "T|" << peekRoot << '|' << openRoot << '|'
            << attr0 << ',' << attr1 << ',' << attr2 << ',' << attrEnd << '|'
            << peekKnown << '|' << openKnown << '|' << knownAttrEnd << '|'
            << peekUnknown << '|' << openUnknown << '|' << unknownAttrEnd << '|'
            << childEnd << '|' << afterClosePeek << '|' << afterCloseOpen << '\n';
}

} // End namespace ghidra

int main(void)

{
  using namespace ghidra;
  const size_t attributeCount = sizeof(attributeObjects)/sizeof(attributeObjects[0]);
  const size_t elementCount = sizeof(elementObjects)/sizeof(elementObjects[0]);
  if (attributeCount != 146 || elementCount != 274)
    return 2;

  AttributeId::initialize();
  ElementId::initialize();
  AttributeId::initialize();
  ElementId::initialize();

  std::cout << "H|1|" << attributeCount << '|' << elementCount << '|'
            << ATTRIB_UNKNOWN.getId() << '|' << ELEM_UNKNOWN.getId() << '\n';
  for(size_t i=0;i<attributeCount;++i) {
    AttributeId *item = attributeObjects[i];
    const char *reverse = attributeNameById(item->getId());
    std::cout << "A|" << item->getId() << '|' << item->getName() << '|'
              << AttributeId::find(item->getName(), 0) << '|'
              << (reverse == (const char *)0 ? "NONE" : reverse) << '\n';
  }
  for(size_t i=0;i<elementCount;++i) {
    ElementId *item = elementObjects[i];
    const char *reverse = elementNameById(item->getId());
    std::cout << "E|" << item->getId() << '|' << item->getName() << '|'
              << ElementId::find(item->getName(), 0) << '|'
              << (reverse == (const char *)0 ? "NONE" : reverse) << '\n';
  }

  const char *attributeZero = attributeNameById(0);
  const char *elementZero = elementNameById(0);
  std::cout << "C|" << AttributeId::find("size", 0) << '|'
            << AttributeId::find("space", 0) << '|'
            << AttributeId::find("fixture_unknown_attribute", 0) << '|'
            << ElementId::find("fixture_unknown_element", 0) << '|'
            << AttributeId::find("size", 1) << '|'
            << ElementId::find("data", 1) << '|'
            << (attributeZero == (const char *)0 ? "NONE" : attributeZero) << '|'
            << (elementZero == (const char *)0 ? "NONE" : elementZero) << '|'
            << AttributeId::find("size", 0) << '|'
            << ElementId::find("data", 0) << '\n';
  emitTreeState();
  std::cout << "S|MATCH|420|0\n";
  return 0;
}
