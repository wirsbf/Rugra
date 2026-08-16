/* XML text ingestion oracle fixture (MARSHAL-XML-TEXT-0001).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 * Parses a battery of XML byte inputs through DocumentStorage / xml_tree and
 * prints a canonical projection of the resulting DOM (element names, ordered
 * attributes, significant content, child order), plus DocumentStorage
 * register/getTag/overwrite behavior, the null-slot partial state after a
 * malformed parse, and the exact parse/open error messages. The Rust fixture
 * must produce byte-identical output.
 */

#include "xml.hh"

#include <iostream>
#include <sstream>
#include <string>

using namespace ghidra;

static void dump_element(const Element *el, int4 depth)
{
  std::cout << "E|" << depth << '|' << el->getName() << '|' << el->getContent()
            << '|' << el->getNumAttributes() << '|' << el->getChildren().size() << '\n';
  for(int4 i=0;i<el->getNumAttributes();++i)
    std::cout << "A|" << depth << '|' << i << '|' << el->getAttributeName(i)
              << '=' << el->getAttributeValue(i) << '\n';
  List::const_iterator iter;
  for(iter=el->getChildren().begin();iter!=el->getChildren().end();++iter)
    dump_element(*iter, depth+1);
}

static void try_parse(const std::string &label, const std::string &text)
{
  try {
    std::istringstream stream(text);
    Document *doc = xml_tree(stream);
    std::cout << "P|" << label << "|OK\n";
    dump_element(doc->getRoot(), 0);
    delete doc;
  }
  catch (const DecoderError &e) {
    std::cout << "P|" << label << "|ERR|" << e.explain << '\n';
  }
}

int main(void)
{
  // -- successful parses: tree shape, ordered attributes, content rules --
  try_parse("basic_tree",
            "<compiler_spec><stackpointer register=\"rsp\" space=\"ram\" growth=\"down\"/></compiler_spec>");
  try_parse("content_ws_only", "<data>  \n\t  </data>");
  try_parse("content_split", "<data>keep <b/> this</data>");
  try_parse("cdata_ws_only", "<data><![CDATA[   ]]></data>");
  try_parse("cdata_markup", "<d><![CDATA[x<y & z]]></d>");
  try_parse("cdata_split", "<d>a<![CDATA[b]]>c</d>");
  try_parse("entity_attr_content", "<r a=\"&lt;&amp;&quot;\">&#65;&#x42;&amp;</r>");
  try_parse("single_quote", "<r a='it&quot;s'/>");
  try_parse("dup_attr", "<r a=\"1\" a=\"2\"/>");
  try_parse("empty_attr", "<r a=\"\"/>");
  try_parse("attr_ws_eq", "<r a = \"1\" />");
  try_parse("etag_ws", "<r>x</r >");
  try_parse("etag_nl", "<r>x</r\n>");
  try_parse("mismatch_etag", "<r>x</q>");
  try_parse("prolog_comment", "<!--c--><a/>");
  try_parse("prolog_multi_misc", "<!--a--> <!--b-->\n<a/>");
  try_parse("xmldecl_full", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>");
  try_parse("xmldecl_sp", "<?xml version = \"1.0\" ?><r/>");
  try_parse("xmldecl_comment", "<?xml version=\"1.0\"?><!--c--><a/>");
  try_parse("inner_comment", "<a> <!-- i --> <c/></a>");
  try_parse("empty_comment", "<a><!----></a>");
  try_parse("deep", "<a><b><c>t</c></b></a>");
  try_parse("trailing_ws", "<a/>  ");
  try_parse("charref_attr", "<r a=\"&#65;&#x42;\"/>");
  try_parse("amp_ref_attr", "<r a=\"a&amp;b\"/>");
  try_parse("raw_cdata_end_text", "<r>]]&gt;</r>");

  // -- parse failures with exact error messages --
  try_parse("trailing_comment", "<r/><!--c-->");
  try_parse("trailing_two_comments", "<r/><!--c--><!--d-->");
  try_parse("nested_mismatch", "<r><b></r>");
  try_parse("unclosed", "<r>");
  try_parse("unclosed_content", "<a>x");
  try_parse("pi_first", "<?php ?>");
  try_parse("pi_after_comment", "<!--c--><?php ?>");
  try_parse("pi_in_content", "<r><?php ?></r>");
  try_parse("dtd_first", "<!DOCTYPE x>");
  try_parse("dtd_after_comment", "<!--c--><!DOCTYPE x>");
  try_parse("dtd_after_ws", " <!DOCTYPE x>");
  try_parse("dtd_after_xmldecl", "<?xml version=\"1.0\"?><!DOCTYPE x>");
  try_parse("two_roots", "<r/><r/>");
  try_parse("empty_input", "");
  try_parse("missing_gt_stag", "<r <s/>");
  try_parse("lt_in_attr", "<r a=\"<\"/>");
  try_parse("comment_dashdash", "<a><!-- x -- y --></a>");
  try_parse("charref_hex_upper", "<r>&#x41;&#X42;</r>");
  try_parse("charref_nodigits", "<r>&#;</r>");

  // -- DocumentStorage: register/getTag, same-name overwrite, null-slot --
  DocumentStorage store;
  std::istringstream in1("<colors><red/></colors>");
  Document *d1 = store.parseDocument(in1);
  store.registerTag(d1->getRoot()->getChildren()[0]);
  std::cout << "T|getTag_red|" << (store.getTag("red") != (const Element *)0) << '\n';
  std::cout << "T|getTag_blue|" << (store.getTag("blue") != (const Element *)0) << '\n';
  std::istringstream in2("<other><red x=\"1\"/></other>");
  Document *d2 = store.parseDocument(in2);
  store.registerTag(d2->getRoot()->getChildren()[0]);
  std::cout << "T|overwrite|" << store.getTag("red")->getAttributeValue("x") << '\n';
  try {
    std::istringstream in3("<broken>");
    store.parseDocument(in3);
    std::cout << "X|broken|UNEXPECTED_OK\n";
  }
  catch (const DecoderError &e) {
    std::cout << "X|broken|" << e.explain << '\n';
  }
  std::istringstream in4("<ok/>");
  Document *d4 = store.parseDocument(in4);
  std::cout << "X|afterfail|" << d4->getRoot()->getName() << '\n';
  try {
    store.openDocument("/nonexistent/xml/text/dom/fixture.xml");
    std::cout << "X|openfail|UNEXPECTED_OK\n";
  }
  catch (const DecoderError &e) {
    std::cout << "X|openfail|" << e.explain << '\n';
  }
  std::cout << "S|DONE\n";
  return 0;
}
