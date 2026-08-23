// Locked-oracle GhidraScript for PROGRAM-FLOW-METADATA-FIXTURE-0001.
// @category Rugra.Oracle

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.NoReturnFunctionAnalyzer;
import ghidra.app.plugin.core.function.SharedReturnAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PatchPackedEncode;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramChangeRecord;

public class ProgramFlowMetadata1204 extends GhidraScript {

	private static final String ORACLE_COMMIT =
		"e40ed13014025f82488b1f8f7bca566894ac376b";
	private static final String ORACLE_TAG = "Ghidra_12.0.4_build";
	private static final String EXPECTED_VERSION = "12.0.4";
	private static final String LANGUAGE_ID = "x86:LE:64:default";
	private static final String COMPILER_SPEC_ID = "gcc";
	private static final String SHARED_RETURN_NAME = "Shared Return Calls";
	private static final String NO_RETURN_NAME = "Non-Returning Functions - Known";
	private static final String CONTIGUOUS_OPTION = "Assume Contiguous Functions Only";
	private static final String CONDITIONAL_OPTION = "Allow Conditional Jumps";
	private static final String BOOKMARK_OPTION = "Create Analysis Bookmarks";

	private static final List<String> FUNCTION_NAMES = Arrays.asList(
		"_start", "shared_ret", "tail_user", "cond_user", "exit", "noreturn_caller");
	private static final List<String> SITE_NAMES = Arrays.asList(
		"tail_jump_site", "cond_jump_site", "exit_call_site", "after_exit_site");

	private static Map<String, Object> object() {
		return new LinkedHashMap<>();
	}

	private static List<Object> array() {
		return new ArrayList<>();
	}

	private static String address(Address addr) {
		if (addr == null) {
			return null;
		}
		return addr.getAddressSpace().getName() + ":0x" +
			Long.toUnsignedString(addr.getOffset(), 16);
	}

	private static String hex(byte[] bytes) {
		StringBuilder result = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			result.append(String.format("%02x", value & 0xff));
		}
		return result.toString();
	}

	private static String sha256(byte[] bytes) throws Exception {
		return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
	}

	private static void jsonString(StringBuilder out, String value) {
		out.append('"');
		for (int i = 0; i < value.length(); ++i) {
			char ch = value.charAt(i);
			switch (ch) {
				case '"': out.append("\\\""); break;
				case '\\': out.append("\\\\"); break;
				case '\b': out.append("\\b"); break;
				case '\f': out.append("\\f"); break;
				case '\n': out.append("\\n"); break;
				case '\r': out.append("\\r"); break;
				case '\t': out.append("\\t"); break;
				default:
					if (ch < 0x20) {
						out.append(String.format("\\u%04x", (int) ch));
					}
					else {
						out.append(ch);
					}
			}
		}
		out.append('"');
	}

	@SuppressWarnings("unchecked")
	private static void jsonValue(StringBuilder out, Object value) {
		if (value == null) {
			out.append("null");
		}
		else if (value instanceof String || value instanceof Character || value instanceof Enum<?>) {
			jsonString(out, value.toString());
		}
		else if (value instanceof Boolean || value instanceof Number) {
			out.append(value.toString());
		}
		else if (value instanceof Map<?, ?>) {
			out.append('{');
			boolean first = true;
			for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
				if (!first) out.append(',');
				first = false;
				jsonString(out, entry.getKey().toString());
				out.append(':');
				jsonValue(out, entry.getValue());
			}
			out.append('}');
		}
		else if (value instanceof Iterable<?>) {
			out.append('[');
			boolean first = true;
			for (Object item : (Iterable<Object>) value) {
				if (!first) out.append(',');
				first = false;
				jsonValue(out, item);
			}
			out.append(']');
		}
		else {
			throw new IllegalArgumentException("unsupported JSON type: " + value.getClass());
		}
	}

	private static String toJson(Object value) {
		StringBuilder out = new StringBuilder();
		jsonValue(out, value);
		return out.toString();
	}

	private static Map<String, Object> flowType(RefType type) {
		if (type == null) {
			return null;
		}
		Map<String, Object> result = object();
		result.put("name", type.getName());
		result.put("value", type.getValue() & 0xff);
		result.put("is_flow", type.isFlow());
		result.put("is_call", type.isCall());
		result.put("is_jump", type.isJump());
		result.put("is_conditional", type.isConditional());
		result.put("is_unconditional", type.isUnConditional());
		result.put("is_computed", type.isComputed());
		result.put("is_terminal", type.isTerminal());
		result.put("has_fallthrough", type.hasFallthrough());
		result.put("is_override", type.isOverride());
		return result;
	}

	private static List<Object> addresses(Address[] values) {
		List<Object> result = array();
		if (values != null) {
			for (Address value : values) result.add(address(value));
		}
		return result;
	}

	private Map<String, Object> varnode(Varnode node) {
		if (node == null) return null;
		Map<String, Object> result = object();
		result.put("space", node.getAddress().getAddressSpace().getName());
		result.put("offset", "0x" + Long.toUnsignedString(node.getOffset(), 16));
		result.put("size", node.getSize());
		result.put("constant", node.isConstant());
		result.put("register", node.isRegister());
		result.put("unique", node.isUnique());
		result.put("address", node.isAddress());
		return result;
	}

	private List<Object> pcode(PcodeOp[] ops) {
		List<Object> result = array();
		for (int index = 0; index < ops.length; ++index) {
			PcodeOp op = ops[index];
			SequenceNumber seq = op.getSeqnum();
			Map<String, Object> item = object();
			item.put("index", index);
			item.put("mnemonic", op.getMnemonic());
			item.put("opcode", op.getOpcode());
			Map<String, Object> sequence = object();
			sequence.put("target", address(seq.getTarget()));
			sequence.put("time", seq.getTime());
			sequence.put("order", seq.getOrder());
			item.put("sequence", sequence);
			item.put("output", varnode(op.getOutput()));
			List<Object> inputs = array();
			for (int slot = 0; slot < op.getNumInputs(); ++slot) {
				inputs.add(varnode(op.getInput(slot)));
			}
			item.put("inputs", inputs);
			result.add(item);
		}
		return result;
	}

	private Map<String, Object> packedPcode(Instruction instruction, boolean overrides)
			throws Exception {
		PatchPackedEncode encoder = new PatchPackedEncode();
		encoder.clear();
		instruction.getPrototype().getPcodePacked(encoder,
			instruction.getInstructionContext(),
			overrides ? new InstructionPcodeOverride(instruction) : null);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		encoder.writeTo(bytes);
		byte[] encoded = bytes.toByteArray();
		Map<String, Object> result = object();
		result.put("size", encoded.length);
		result.put("sha256", sha256(encoded));
		result.put("hex", hex(encoded));
		return result;
	}

	private Map<String, Object> reference(Reference ref, int nativeIndex) {
		Map<String, Object> result = object();
		if (nativeIndex >= 0) result.put("native_index", nativeIndex);
		result.put("from", address(ref.getFromAddress()));
		result.put("to", address(ref.getToAddress()));
		result.put("type", flowType(ref.getReferenceType()));
		result.put("source", ref.getSource().toString());
		result.put("operand_index", ref.getOperandIndex());
		result.put("primary", ref.isPrimary());
		result.put("memory", ref.isMemoryReference());
		result.put("external", ref.isExternalReference());
		result.put("symbol_id", ref.getSymbolID());
		Symbol associated = ref.getSymbolID() < 0 ? null :
			currentProgram.getSymbolTable().getSymbol(ref.getSymbolID());
		result.put("associated_symbol", associated == null ? null :
			associated.getName(true) + "@" + address(associated.getAddress()));
		return result;
	}

	private static final Comparator<Reference> REFERENCE_ORDER = (left, right) -> {
		int cmp = left.getFromAddress().compareTo(right.getFromAddress());
		if (cmp != 0) return cmp;
		cmp = left.getToAddress().compareTo(right.getToAddress());
		if (cmp != 0) return cmp;
		cmp = Integer.compare(left.getReferenceType().getValue() & 0xff,
			right.getReferenceType().getValue() & 0xff);
		if (cmp != 0) return cmp;
		cmp = Integer.compare(left.getOperandIndex(), right.getOperandIndex());
		if (cmp != 0) return cmp;
		cmp = left.getSource().toString().compareTo(right.getSource().toString());
		if (cmp != 0) return cmp;
		cmp = Boolean.compare(left.isPrimary(), right.isPrimary());
		if (cmp != 0) return cmp;
		return Long.compare(left.getSymbolID(), right.getSymbolID());
	};

	private Map<String, Object> references(Instruction instruction) {
		Reference[] nativeRefs = instruction.getReferencesFrom();
		List<Object> nativeOrder = array();
		for (int index = 0; index < nativeRefs.length; ++index) {
			nativeOrder.add(reference(nativeRefs[index], index));
		}
		Reference[] sortedRefs = nativeRefs.clone();
		Arrays.sort(sortedRefs, REFERENCE_ORDER);
		List<Object> sorted = array();
		for (Reference ref : sortedRefs) sorted.add(reference(ref, -1));
		Map<String, Object> result = object();
		result.put("native", nativeOrder);
		result.put("canonical_sorted", sorted);
		return result;
	}

	private Map<String, Object> instruction(Instruction instruction) throws Exception {
		Map<String, Object> result = object();
		result.put("address", address(instruction.getMinAddress()));
		result.put("length", instruction.getLength());
		byte[] bytes = instruction.getBytes();
		result.put("bytes", hex(bytes));
		result.put("mnemonic", instruction.getMnemonicString());
		result.put("default_flow_type", flowType(instruction.getPrototype()
			.getFlowType(instruction.getInstructionContext())));
		result.put("effective_flow_type", flowType(instruction.getFlowType()));
		result.put("flow_override", instruction.getFlowOverride().toString());
		result.put("default_flows", addresses(instruction.getDefaultFlows()));
		result.put("effective_flows", addresses(instruction.getFlows()));
		result.put("default_fallthrough", address(instruction.getDefaultFallThrough()));
		result.put("effective_fallthrough", address(instruction.getFallThrough()));
		result.put("fall_from", address(instruction.getFallFrom()));
		Function at = currentProgram.getFunctionManager().getFunctionAt(instruction.getMinAddress());
		Function containing = currentProgram.getFunctionManager()
			.getFunctionContaining(instruction.getMinAddress());
		result.put("function_at", at == null ? null : at.getName());
		result.put("function_containing", containing == null ? null : containing.getName());
		result.put("references", references(instruction));
		result.put("raw_pcode", pcode(instruction.getPcode(false)));
		result.put("override_aware_pcode", pcode(instruction.getPcode(true)));
		result.put("raw_packed_pcode", packedPcode(instruction, false));
		result.put("override_aware_packed_pcode", packedPcode(instruction, true));
		return result;
	}

	private Function uniqueFunction(String name) throws Exception {
		List<Function> functions = currentProgram.getListing().getGlobalFunctions(name);
		if (functions.size() != 1) {
			throw new Exception("expected exactly one global function " + name +
				", got " + functions.size());
		}
		return functions.get(0);
	}

	private Address uniqueSymbolAddress(String name) throws Exception {
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
		Address found = null;
		int count = 0;
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (!symbol.getAddress().isMemoryAddress()) continue;
			found = symbol.getAddress();
			count += 1;
		}
		if (count != 1) {
			throw new Exception("expected exactly one memory symbol " + name + ", got " + count);
		}
		return found;
	}

	private Map<String, Object> function(Function function) throws Exception {
		Map<String, Object> result = object();
		result.put("name", function.getName());
		result.put("entry", address(function.getEntryPoint()));
		List<Object> ranges = array();
		AddressRangeIterator rangeIterator = function.getBody().getAddressRanges(true);
		while (rangeIterator.hasNext()) {
			AddressRange range = rangeIterator.next();
			Map<String, Object> item = object();
			item.put("min", address(range.getMinAddress()));
			item.put("max", address(range.getMaxAddress()));
			item.put("length", range.getLength());
			ranges.add(item);
		}
		result.put("body_ranges", ranges);
		result.put("external", function.isExternal());
		result.put("thunk", function.isThunk());
		List<Object> thunkChain = array();
		Function cursor = function;
		for (int depth = 0; depth < 16 && cursor != null && cursor.isThunk(); ++depth) {
			cursor = cursor.getThunkedFunction(false);
			if (cursor != null) {
				thunkChain.add(cursor.getName() + "@" + address(cursor.getEntryPoint()));
			}
		}
		result.put("thunk_chain", thunkChain);
		result.put("no_return", function.hasNoReturn());
		result.put("inline", function.isInline());
		result.put("call_fixup", function.getCallFixup());
		result.put("signature_source", function.getSignatureSource().toString());
		result.put("calling_convention", function.getCallingConventionName());
		List<Object> instructions = array();
		InstructionIterator iterator = currentProgram.getListing()
			.getInstructions(function.getBody(), true);
		while (iterator.hasNext()) instructions.add(instruction(iterator.next()));
		result.put("instructions", instructions);
		return result;
	}

	private Map<String, Object> analysisOptions() {
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		List<String> names = new ArrayList<>(options.getOptionNames());
		Collections.sort(names);
		Map<String, Object> result = new TreeMap<>();
		for (String name : names) {
			Map<String, Object> item = object();
			item.put("type", options.getType(name).toString());
			try {
				item.put("value", options.getValueAsString(name));
			}
			catch (RuntimeException error) {
				item.put("value", "<" + error.getClass().getSimpleName() + ">");
			}
			try {
				item.put("default", options.getDefaultValueAsString(name));
			}
			catch (RuntimeException error) {
				item.put("default", "<" + error.getClass().getSimpleName() + ">");
			}
			result.put(name, item);
		}
		return result;
	}

	private Map<String, Object> languageProperties() {
		List<String> keys = new ArrayList<>(currentProgram.getLanguage().getPropertyKeys());
		Collections.sort(keys);
		Map<String, Object> result = new TreeMap<>();
		for (String key : keys) {
			result.put(key, currentProgram.getLanguage().getProperty(key));
		}
		return result;
	}

	private Map<String, Object> stage(String name) throws Exception {
		Map<String, Object> result = object();
		result.put("name", name);
		result.put("analysis_options", analysisOptions());
		List<Object> functions = array();
		for (String functionName : FUNCTION_NAMES) {
			functions.add(function(uniqueFunction(functionName)));
		}
		result.put("functions", functions);
		List<Object> sites = array();
		for (String siteName : SITE_NAMES) {
			Address siteAddress = uniqueSymbolAddress(siteName);
			Instruction siteInstruction = currentProgram.getListing().getInstructionAt(siteAddress);
			if (siteInstruction == null) {
				throw new Exception("no instruction at site " + siteName + " " + siteAddress);
			}
			Map<String, Object> site = object();
			site.put("name", siteName);
			site.put("instruction", instruction(siteInstruction));
			sites.add(site);
		}
		result.put("named_sites", sites);
		return result;
	}

	private void assertStage(String lane, String stageName) throws Exception {
		Instruction tail = currentProgram.getListing().getInstructionAt(
			uniqueSymbolAddress("tail_jump_site"));
		Instruction conditional = currentProgram.getListing().getInstructionAt(
			uniqueSymbolAddress("cond_jump_site"));
		Function exit = uniqueFunction("exit");
		boolean baseline = stageName.equals("pre_target_analyzers");
		FlowOverride expectedTail = baseline ? FlowOverride.NONE : FlowOverride.CALL_RETURN;
		FlowOverride expectedConditional = (!baseline && lane.equals("conditional_enabled")) ?
			FlowOverride.CALL_RETURN : FlowOverride.NONE;
		if (tail.getFlowOverride() != expectedTail) {
			throw new Exception(stageName + " tail override=" + tail.getFlowOverride() +
				" expected=" + expectedTail);
		}
		if (conditional.getFlowOverride() != expectedConditional) {
			throw new Exception(stageName + " conditional override=" +
				conditional.getFlowOverride() + " expected=" + expectedConditional);
		}
		if (exit.hasNoReturn() != !baseline) {
			throw new Exception(stageName + " exit.noReturn=" + exit.hasNoReturn());
		}
		if (!baseline) {
			List<String> tailOps = new ArrayList<>();
			for (PcodeOp op : tail.getPcode(true)) tailOps.add(op.getMnemonic());
			if (!tailOps.contains("CALL") || !tailOps.contains("RETURN") ||
				tailOps.contains("BRANCH")) {
				throw new Exception("direct CALL_RETURN p-code shape wrong: " + tailOps);
			}
			if (lane.equals("conditional_enabled")) {
				List<String> condOps = new ArrayList<>();
				for (PcodeOp op : conditional.getPcode(true)) condOps.add(op.getMnemonic());
				if (!condOps.contains("CBRANCH") || !condOps.contains("CALL") ||
					!condOps.contains("RETURN")) {
					throw new Exception("conditional CALL_RETURN p-code shape wrong: " + condOps);
				}
			}
		}
	}

	private final class EventCapture implements DomainObjectListener {
		private final List<Object> records = array();
		private final IdentityHashMap<Object, Integer> identities = new IdentityHashMap<>();
		private int nextIdentity = 0;
		private String phase = "unassigned";

		public synchronized void setPhase(String value) {
			phase = value;
		}

		private synchronized int identity(Object value) {
			Integer known = identities.get(value);
			if (known != null) return known;
			int assigned = nextIdentity++;
			identities.put(value, assigned);
			return assigned;
		}

		private Object describe(Object value) {
			if (value == null) return null;
			if (value instanceof Address) return address((Address) value);
			if (value instanceof Function) {
				Function function = (Function) value;
				return function.getName() + "@" + address(function.getEntryPoint());
			}
			if (value instanceof Instruction) {
				return "Instruction@" + address(((Instruction) value).getMinAddress());
			}
			if (value instanceof CodeUnit) {
				return value.getClass().getSimpleName() + "@" +
					address(((CodeUnit) value).getMinAddress());
			}
			if (value instanceof Symbol) {
				Symbol symbol = (Symbol) value;
				return symbol.getName(true) + "@" + address(symbol.getAddress());
			}
			if (value instanceof Reference) {
				Reference ref = (Reference) value;
				return address(ref.getFromAddress()) + "->" + address(ref.getToAddress()) +
					":" + ref.getReferenceType().getName() + ":op" + ref.getOperandIndex();
			}
			if (value instanceof Enum<?> || value instanceof Number ||
				value instanceof Boolean || value instanceof String || value instanceof SourceType) {
				return value.toString();
			}
			return "<" + value.getClass().getName() + ">";
		}

		@Override
		public synchronized void domainObjectChanged(DomainObjectChangedEvent event) {
			for (DomainObjectChangeRecord record : event) {
				Map<String, Object> item = object();
				item.put("phase", phase);
				item.put("sequence", records.size());
				item.put("event_type", record.getEventType().toString());
				item.put("event_type_id", record.getEventType().getId());
				item.put("old", describe(record.getOldValue()));
				item.put("new", describe(record.getNewValue()));
				if (record instanceof ProgramChangeRecord) {
					ProgramChangeRecord programRecord = (ProgramChangeRecord) record;
					item.put("start", address(programRecord.getStart()));
					item.put("end", address(programRecord.getEnd()));
					Object affected = programRecord.getObject();
					item.put("affected", describe(affected));
					item.put("affected_identity", affected == null ? null : identity(affected));
				}
				records.add(item);
			}
		}

		public synchronized List<Object> snapshot() {
			return new ArrayList<>(records);
		}
	}

	private static List<Object> logLines(MessageLog log) {
		List<Object> result = array();
		for (String line : log.toString().split("\\R")) {
			if (!line.isEmpty()) result.add(line);
		}
		return result;
	}

	private void configureBaseline() throws Exception {
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		if (!options.contains(SHARED_RETURN_NAME) || !options.contains(NO_RETURN_NAME)) {
			throw new Exception("locked analyzer options are not registered");
		}
		options.setBoolean(SHARED_RETURN_NAME, false);
		options.setBoolean(NO_RETURN_NAME, false);
		if (options.getBoolean(SHARED_RETURN_NAME, true) ||
			options.getBoolean(NO_RETURN_NAME, true)) {
			throw new Exception("failed to disable target analyzers for baseline");
		}
		println("PROGRAM_FLOW_METADATA_CONFIGURED");
	}

	private Map<String, Object> invokeAnalyzers(String lane, EventCapture events)
			throws Exception {
		boolean conditional = lane.equals("conditional_enabled");
		AddressSetView set = currentProgram.getMemory().getLoadedAndInitializedAddressSet();

		MessageLog noReturnLog = new MessageLog();
		NoReturnFunctionAnalyzer noReturn = new NoReturnFunctionAnalyzer();
		if (!noReturn.canAnalyze(currentProgram)) {
			throw new Exception("Known No-Return analyzer cannot analyze fixture program");
		}
		Options noReturnOptions = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
			.getOptions(NO_RETURN_NAME);
		noReturn.registerOptions(noReturnOptions, currentProgram);
		noReturnOptions.setBoolean(BOOKMARK_OPTION, true);
		noReturn.optionsChanged(noReturnOptions, currentProgram);
		events.setPhase("known_no_return");
		boolean noReturnResult = noReturn.added(currentProgram, set, monitor, noReturnLog);
		currentProgram.flushEvents();

		MessageLog sharedLog = new MessageLog();
		SharedReturnAnalyzer shared = new SharedReturnAnalyzer();
		Options sharedOptions = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
			.getOptions(SHARED_RETURN_NAME);
		shared.registerOptions(sharedOptions, currentProgram);
		sharedOptions.setBoolean(CONTIGUOUS_OPTION, true);
		sharedOptions.setBoolean(CONDITIONAL_OPTION, conditional);
		shared.optionsChanged(sharedOptions, currentProgram);
		events.setPhase("shared_return");
		boolean sharedResult = shared.added(currentProgram, set, monitor, sharedLog);
		currentProgram.flushEvents();

		Map<String, Object> result = object();
		result.put("order", Arrays.asList(NO_RETURN_NAME, SHARED_RETURN_NAME));
		Map<String, Object> noReturnResultMap = object();
		noReturnResultMap.put("result", noReturnResult);
		noReturnResultMap.put("create_analysis_bookmarks", true);
		noReturnResultMap.put("log_status", noReturnLog.getStatus());
		noReturnResultMap.put("log", logLines(noReturnLog));
		result.put("known_no_return", noReturnResultMap);
		Map<String, Object> sharedResultMap = object();
		sharedResultMap.put("result", sharedResult);
		sharedResultMap.put("assume_contiguous_functions_only", true);
		sharedResultMap.put("allow_conditional_jumps", conditional);
		sharedResultMap.put("log_status", sharedLog.getStatus());
		sharedResultMap.put("log", logLines(sharedLog));
		result.put("shared_return", sharedResultMap);
		return result;
	}

	private void capture(String lane, Path output) throws Exception {
		if (!lane.equals("direct_only") && !lane.equals("conditional_enabled")) {
			throw new Exception("unknown lane: " + lane);
		}
		if (!Application.getApplicationVersion().equals(EXPECTED_VERSION)) {
			throw new Exception("Ghidra version=" + Application.getApplicationVersion() +
				" expected=" + EXPECTED_VERSION);
		}
		String language = currentProgram.getLanguageID().getIdAsString();
		String compilerSpec = currentProgram.getCompilerSpec()
			.getCompilerSpecID().getIdAsString();
		if (!language.equals(LANGUAGE_ID) || !compilerSpec.equals(COMPILER_SPEC_ID)) {
			throw new Exception("program architecture=" + language + "/" + compilerSpec);
		}

		Map<String, Object> root = object();
		root.put("schema", 1);
		root.put("fixture_id", "PROGRAM-FLOW-METADATA-FIXTURE-0001");
		Map<String, Object> oracle = object();
		oracle.put("tag", ORACLE_TAG);
		oracle.put("commit", ORACLE_COMMIT);
		oracle.put("ghidra_version", Application.getApplicationVersion());
		root.put("oracle", oracle);
		root.put("lane", lane);
		Map<String, Object> program = object();
		program.put("language_id", language);
		program.put("compiler_spec_id", compilerSpec);
		program.put("image_base", address(currentProgram.getImageBase()));
		program.put("executable_format", currentProgram.getExecutableFormat());
		program.put("language_properties", languageProperties());
		program.put("shared_return_language_default",
			currentProgram.getLanguage().getPropertyAsBoolean(
				GhidraLanguagePropertyKeys.ENABLE_SHARED_RETURN_ANALYSIS, true));
		program.put("contiguous_function_language_default",
			currentProgram.getLanguage().getPropertyAsBoolean(
				GhidraLanguagePropertyKeys.ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY, true));
		root.put("program", program);

		List<Object> stages = array();
		assertStage(lane, "pre_target_analyzers");
		stages.add(stage("pre_target_analyzers"));

		EventCapture events = new EventCapture();
		currentProgram.addListener(events);
		Map<String, Object> invocation;
		try {
			invocation = invokeAnalyzers(lane, events);
			assertStage(lane, "post_target_analyzers");
			stages.add(stage("post_target_analyzers"));

			events.setPhase("analysis_queue_settle");
			AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(null, monitor);
			currentProgram.flushEvents();
			assertStage(lane, "analysis_queue_settled");
			stages.add(stage("analysis_queue_settled"));
		}
		finally {
			currentProgram.removeListener(events);
		}
		root.put("manual_analyzer_invocation", invocation);
		root.put("stages", stages);
		root.put("events", events.snapshot());

		Files.writeString(output, toJson(root) + "\n", StandardCharsets.UTF_8);
		println("PROGRAM_FLOW_METADATA_CAPTURED lane=" + lane + " output=" + output);
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 1 && args[0].equals("configure")) {
			configureBaseline();
			return;
		}
		if (args.length == 3 && args[0].equals("capture")) {
			capture(args[1], Path.of(args[2]));
			return;
		}
		throw new Exception("usage: configure | capture LANE OUTPUT_JSON");
	}
}
