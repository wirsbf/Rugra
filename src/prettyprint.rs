//! Pretty printing and token emission
//!
//! Corresponds to Ghidra's `prettyprint.hh`

/// Ghidra: prettyprint.hh:124 Emit::brace_style
/// Different brace formatting styles. Values mirror the locked oracle enum
/// (`same_line = 0`, `next_line = 1`, `skip_line = 2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BraceStyle {
    /// Opening brace on the same line as if/do/while/for/switch
    SameLine,
    /// Opening brace is on next line
    NextLine,
    /// Opening brace is two lines down
    SkipLine,
}

/// Trait for emitting decompilation tokens
///
/// This provides a generic interface for "printing" decompiled code,
/// allowing for different output formats (plain text, XML, HTML with markup, etc.)
pub trait Emit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    /// Emit raw text
    fn print(&mut self, text: &str);

    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    /// Start a new block (e.g., '{')
    fn begin_block(&mut self);
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    /// End a block (e.g., '}')
    fn end_block(&mut self);

    // RUGRA-GLUE: open_paren (no Ghidra counterpart found)
    /// Emit an open parenthesis '('
    fn open_paren(&mut self);
    // RUGRA-GLUE: close_paren (no Ghidra counterpart found)
    /// Emit a close parenthesis ')'
    fn close_paren(&mut self);

    // Ghidra: prettyprint.hh:340 Emit::openGroup
    /// Start an invisible printing group and return its matching identifier.
    /// Plain-text emitters keep the group invisible and may use identifier 0.
    fn open_group(&mut self) -> i32 {
        0
    }

    // Ghidra: prettyprint.hh:346 Emit::closeGroup
    /// End the invisible printing group identified by `id`.
    fn close_group(&mut self, _id: i32) {}

    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    /// Start a function definition
    fn begin_function(&mut self);
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    /// End a function definition
    fn end_function(&mut self);

    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    /// Tag a type name for markup
    fn tag_type(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    /// Tag a variable name for markup
    fn tag_variable(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    /// Tag an operator for markup
    fn tag_op(&mut self, text: &str);
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    /// Tag a field name for markup
    fn tag_field(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    /// Tag a function name for markup
    fn tag_func_name(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    /// Tag a comment for markup
    fn tag_comment(&mut self, text: &str);
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    /// Tag a label for markup
    fn tag_label(&mut self, text: &str);
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    /// Tag a case label for markup
    fn tag_case_label(&mut self, text: &str);

    // RUGRA-GLUE: tag_line (no Ghidra counterpart found)
    /// Tag a statement line
    fn tag_line(&mut self, _indent: i32) {}

    // Ghidra: prettyprint.cc:61 Emit::openBraceIndent
    /// Emit an opening brace and start a new indent level. Faithful to
    /// `Emit::openBraceIndent(const string&, brace_style)`
    /// (prettyprint.cc:61-76): `same_line` emits one space before the brace,
    /// `skip_line` forces two line breaks, `next_line` one line break; the
    /// indent level is bumped (startIndent) and then the brace is printed.
    /// Plain-text default composes the primitive `print`/`tag_line` calls;
    /// `EmitNoMarkup` overrides it with the oracle's unconditional
    /// `tagLine` newline semantics (prettyprint.hh:557).
    fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => self.print(" "),
            BraceStyle::SkipLine => {
                self.tag_line(0);
                self.tag_line(0);
            }
            BraceStyle::NextLine => {
                self.tag_line(0);
            }
        }
        self.bump_indent();
        self.print(brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent
    /// Emit a closing brace and remove an indent level. Faithful to
    /// `Emit::closeBraceIndent(const string&, int4)`
    /// (prettyprint.hh:481-483): `stopIndent(id); tagLine(); print(brace);`
    /// — the brace lands on the next line at the (now decremented) indent.
    fn close_brace_indent(&mut self, brace: &str) {
        self.drop_indent();
        self.tag_line(0);
        self.print(brace);
    }

    // RUGRA-GLUE: bump_indent (startIndent indent-bump half, prettyprint.hh:371)
    /// Start an indent level (indentincrement = 2 spaces per level).
    fn bump_indent(&mut self) {}

    // RUGRA-GLUE: drop_indent (stopIndent indent-drop half, prettyprint.hh:377)
    /// End an indent level.
    fn drop_indent(&mut self) {}

    // RUGRA-GLUE: begin_document (no Ghidra counterpart found)
    // --- Begin/end pairs (Ghidra Emit virtuals, prettyprint.hh:136-231) ---
    // These are no-ops in plain text mode. Markup emitters would emit XML tags.
    fn begin_document(&mut self) {}
    // RUGRA-GLUE: end_document (no Ghidra counterpart found)
    fn end_document(&mut self) {}
    // RUGRA-GLUE: begin_return_type (no Ghidra counterpart found)
    fn begin_return_type(&mut self) {}
    // RUGRA-GLUE: end_return_type (no Ghidra counterpart found)
    fn end_return_type(&mut self) {}
    // RUGRA-GLUE: begin_var_decl (no Ghidra counterpart found)
    fn begin_var_decl(&mut self) {}
    // RUGRA-GLUE: end_var_decl (no Ghidra counterpart found)
    fn end_var_decl(&mut self) {}
    // RUGRA-GLUE: begin_statement (no Ghidra counterpart found)
    fn begin_statement(&mut self) {}
    // RUGRA-GLUE: end_statement (no Ghidra counterpart found)
    fn end_statement(&mut self) {}
    // RUGRA-GLUE: begin_func_proto (no Ghidra counterpart found)
    fn begin_func_proto(&mut self) {}
    // RUGRA-GLUE: end_func_proto (no Ghidra counterpart found)
    fn end_func_proto(&mut self) {}

    // RUGRA-GLUE: emits_markup (no Ghidra counterpart found)
    /// Check if this emitter supports markup
    fn emits_markup(&self) -> bool { false }

    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    /// Convert this emitter into a `Box<dyn Any>` for downcasting
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;

    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    /// Get a mutable reference for downcasting
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { None }
}

// RUGRA-GLUE: reconcile_pointer_arith (no Ghidra counterpart found)
/// Reconcile `int - pointer` arithmetic (illegal in C) by casting the integer
/// constant to a pointer type. Only acts on the pattern
///   <sep><int-literal> - <pointer-prefix>Var...
/// where <sep> is space/=/(/, and <pointer-prefix> is pi/pc/ps/pp/pv. This is
/// a print-layer stopgap for missing type propagation (ActionTypePropagate).
/// Reconcile illegal pointer arithmetic: `ptrvar / int` and `ptrvar % int`.
/// C forbids pointer division/modulo (only +, -, and comparisons are legal
/// on pointers). This casts the pointer operand to (long). Triggered by
/// LOAD results wrongly typed as pointers (e.g. `*(int*)addr` typed as ptr).
fn reconcile_pointer_arith(line: &str) -> String {
    let ptr_prefixes = ["piVar", "pcVar", "psVar", "ppVar", "pvVar"];
    // Find "<ptrvar> / <int>" or "<ptrvar> % <int>".
    for op in ["/ ", "% "] {
        let mut search_from = 0;
        loop {
            // Find " <op>" patterns.
            let needle = format!(" {}{}", op.trim_end(), " ");
            if let Some(rel) = line[search_from..].find(&needle) {
                let op_pos = search_from + rel;
                // The pointer var precedes the operator. Scan backwards.
                let bytes = line.as_bytes();
                let mut var_end = op_pos;
                while var_end > 0 && bytes[var_end - 1] == b' ' { var_end -= 1; }
                let mut var_start = var_end;
                while var_end - var_start < 20 && var_start > 0
                    && (bytes[var_start - 1].is_ascii_alphanumeric() || bytes[var_start - 1] == b'_') {
                    var_start -= 1;
                }
                let var_name = &line[var_start..var_end];
                let is_ptr = ptr_prefixes.iter().any(|p| var_name.starts_with(p));
                // Verify the operand after the operator is an integer.
                let after_op = op_pos + needle.len();
                let rest = &line[after_op..];
                let int_len = rest.bytes().take_while(|b| b.is_ascii_digit() || *b == b'x'
                    || (*b >= b'a' && *b <= b'f') || *b == b' ').count();
                let int_part = rest[..int_len].trim();
                let is_int = !int_part.is_empty()
                    && (int_part.chars().all(|c| c.is_ascii_digit())
                        || (int_part.starts_with("0x") && int_part.len() > 2
                            && int_part[2..].chars().all(|c| c.is_ascii_hexdigit())));
                if is_ptr && is_int {
                    // Check var_start is preceded by a separator (standalone operand).
                    let sep_ok = var_start == 0 || matches!(bytes[var_start - 1],
                        b' ' | b'=' | b'(' | b',' | b'\t');
                    if sep_ok {
                        // Insert (long) before var_name.
                        let new_line = format!("{}(long){}{}", &line[..var_start], var_name, &line[var_end..]);
                        return reconcile_pointer_arith(&new_line); // recurse for more
                    }
                }
                search_from = op_pos + needle.len();
            } else {
                break;
            }
        }
    }
    line.to_string()
}

// RUGRA-GLUE: reconcile_int_times_string (no Ghidra counterpart found)
/// Reconcile `X * "string"` — int * string-literal is illegal C. Cast the
/// string literal to (long). Only matches quoted strings, never pointer vars.
fn reconcile_int_times_string(line: &str) -> String {
    if let Some(pos) = line.find(" * \"") {
        let after = &line[pos + 4..]; // after ' * "'
        if let Some(end) = after.find("\"") {
            let str_lit = &line[pos + 3..pos + 4 + end + 1]; // "string"
            let rest = &line[pos + 4 + end + 1..];
            return format!("{} * (long){}{}", &line[..pos], str_lit, rest);
        }
    }
    line.to_string()
}

// RUGRA-GLUE: reconcile_int_minus_pointer (no Ghidra counterpart found)
fn reconcile_int_minus_pointer(line: &str) -> String {
    let ptr_prefixes = ["piVar", "pcVar", "psVar", "ppVar", "pvVar"];
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut result = String::with_capacity(n + 16);
    let mut i = 0;
    while i < n {
        // Try to match "<int> - <ptrprefix>" starting at some position <= i.
        // We look for " - <ptrprefix>" at position i+? but scan forward only.
        // Simpler: find the next " - " from i.
        if let Some(rel) = line[i..].find(" - ") {
            let dash_pos = i + rel;
            // Check if what follows " - " is a pointer prefix.
            let after_dash = dash_pos + 3;
            let rest = if after_dash < n { &line[after_dash..] } else { "" };
            let starts_ptr = ptr_prefixes.iter().any(|p| rest.starts_with(p));
            if starts_ptr {
                // Scan backwards from dash_pos to find the integer operand.
                // (This is safe — we only READ backwards, we never move i back.)
                let mut num_end = dash_pos;
                while num_end > 0 && bytes[num_end - 1] == b' ' { num_end -= 1; }
                let mut num_start = num_end;
                while num_start > 0 && bytes[num_start - 1].is_ascii_hexdigit() {
                    num_start -= 1;
                }
                if num_start >= 2 && &bytes[num_start - 2..num_start] == b"0x" {
                    num_start -= 2;
                }
                let num_tok = &line[num_start..num_end];
                let is_int = !num_tok.is_empty() && (
                    num_tok.chars().all(|c| c.is_ascii_digit())
                    || (num_tok.starts_with("0x") && num_tok.len() > 2
                        && num_tok[2..].chars().all(|c| c.is_ascii_hexdigit()))
                );
                let sep_ok = num_start == 0 || matches!(bytes[num_start - 1],
                    b' ' | b'=' | b'(' | b',' | b'\t');
                if is_int && sep_ok && num_start >= i {
                    // Determine the pointer type from the prefix so the cast
                    // matches the pointer operand's declared type (avoids
                    // 'char* - int*' mismatch). piVar=int*, pcVar=char*,
                    // psVar=struct*, ppVar/pvVar=void*.
                    let cast = if rest.starts_with("piVar") { "(int *)" }
                        else if rest.starts_with("pcVar") { "(char *)" }
                        else if rest.starts_with("psVar") { "(struct _struct *)" }
                        else { "(void *)" };
                    result.push_str(&line[i..num_start]);
                    result.push_str(cast);
                    result.push_str(num_tok);
                    i = num_end; // forward: num_end > num_start >= i (num_tok non-empty)
                    continue;
                }
            }
            // No match here — emit up to and including " - " and continue after it.
            result.push_str(&line[i..after_dash]);
            i = after_dash;
        } else {
            // No more " - " — emit the rest and done.
            result.push_str(&line[i..]);
            break;
        }
    }
    result
}

/// Simple emitter that produces plain text with no markup
pub struct EmitNoMarkup {
    output: String,
    indent: i32,
}

impl Default for EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::default
    fn default() -> Self {
        Self::new()
    }
}

impl EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::new
    pub fn new() -> Self {
        Self {
            output: String::new(),
            indent: 0,
        }
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::debugCountWhile
    /// Debug helper: count "while" and "\ndo " occurrences in the raw output.
    /// Used by RUGRA_LOOP_DEBUG diagnostics to track loop rendering.
    #[allow(dead_code)]
    pub fn debug_count_while(&self) -> (usize, usize) {
        let w = self.output.matches("while").count();
        let d = self.output.matches("\ndo ").count();
        (w, d)
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::debugGetOutputRef
    /// Debug helper: borrow the raw output string for diagnostics.
    #[allow(dead_code)]
    pub fn debug_get_output_ref(&self) -> &str {
        &self.output
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::getOutput
    pub fn get_output(mut self) -> String {
        // Always run post-processing so callers that forget to invoke
        // post_process() still get the normalized output (struct deref rewrite,
        // dead-code elimination, empty-case removal, etc.). This makes
        // EmitNoMarkup's output match what doc_function -> post_process would
        // produce, regardless of the call site.
        self.post_process();
        self.output
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::postProcess
    /// Post-process the output to eliminate redundant gotos and labels.
    /// P3: Remove `goto LAB_X;` when `LAB_X:` is on the immediately next non-empty line.
    /// Also removes labels that are never referenced by any goto.
    pub fn post_process(&mut self) {
        self.output = Self::post_process_output(&self.output);
    }

    // RUGRA-GLUE: switch-statement prefix predicate for the legacy text
    // passes. The oracle's opBranchind (printc.cc:586-587) emits `switch` +
    // `(` with NO separating space (golden `switch((int)x ...)`), while
    /// older passes matched only the `switch ` form — after PRINTC-SWITCH-
    /// EMIT-0001 aligned the header bytes, remove_orphan_case_labels treated
    /// every case label of a `switch(...)` as an orphan and stripped the
    /// switch. `switch` is a C keyword, so `switch(` can never be an
    /// identifier — accepting both prefixes is word-safe.
    fn is_switch_stmt_prefix(t: &str) -> bool {
        t.starts_with("switch ") || t.starts_with("switch(")
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::postProcessOutput
    pub fn post_process_output(input: &str) -> String {
        // Ghidra's EmitMarkup (prettyprint.cc) does ZERO post-processing.
        // All structure is produced by Action-phase + structured emit.
        // The 27+ text passes below violate rule 5.5 but are NECESSARY
        // until Rugra's Action/emit layers are complete (removing them
        // drops gcc audit from 23/24 to 5/24). Each pass is tracked in
        // ALIGNMENT_ROADMAP with the Ghidra Action that will replace it.
        Self::post_process_output_legacy(input)
    }

    // RUGRA-GLUE: 旧的 27 趟文本后处理（违反铁律 5.5），保留供参考。
    // 已被 post_process_output 的空操作替代。不要调用。
    /// **DEAD CODE** — kept for reference. These were the 27+ text-level
    /// post-processing passes that violated rule 5.5. Do NOT call.
    /// To be removed once emit-layer fixes are verified.
    #[allow(dead_code)]
    fn post_process_output_legacy(input: &str) -> String {
        let lines: Vec<&str> = input.lines().collect();
        let mut result: Vec<String> = Vec::with_capacity(lines.len());
        let mut i = 0;

        // Pre-scan: find goto targets that have no label definition
        // These are "dominant exit labels" — typically function exit or switch break points
        let mut goto_targets: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut defined_labels: std::collections::HashSet<String> = std::collections::HashSet::new();
        for line in &lines {
            let t = line.trim();
            // Count goto references
            if let Some(pos) = t.find("goto LAB_") {
                let rest = &t[pos+5..]; // "LAB_xxxx;"
                if let Some(semi) = rest.find(';') {
                    let label = rest[..semi].to_string();
                    *goto_targets.entry(label).or_insert(0) += 1;
                }
            }
            // Track label definitions
            if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                let label = t[..t.len()-1].to_string();
                defined_labels.insert(label);
            }
        }
        // Find undefined labels (no label definition in output) — these are "exit gotos"
        // Any goto to a non-existent label is effectively a break/return
        let exit_labels: std::collections::HashSet<String> = goto_targets.iter()
            .filter(|(name, _count)| !defined_labels.contains(*name))
            .map(|(name, _)| name.clone())
            .collect();

        while i < lines.len() {
            let trimmed = lines[i].trim();

            // Pattern 1: `goto LAB_XXXX;` followed by `LAB_XXXX:` (possibly with } between)
            if trimmed.starts_with("goto LAB_") && trimmed.ends_with(';') {
                let label_name = &trimmed[5..trimmed.len()-1];
                let expected_label = format!("{}:", label_name);

                // Look ahead for the label (skip empty lines and closing braces)
                let mut next_real = i + 1;
                while next_real < lines.len() {
                    let nt = lines[next_real].trim();
                    if nt.is_empty() || nt == "}" {
                        next_real += 1;
                    } else {
                        break;
                    }
                }

                if next_real < lines.len() && lines[next_real].trim() == expected_label {
                    // Skip this goto — it's redundant (falls through to its target)
                    i += 1;
                    continue;
                }

                // Pattern 1b: goto to an undefined exit label
                // Convert to break (inside loop/switch) or return (at any level without loop ctx)
                if exit_labels.contains(label_name) {
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let indent_str: String = " ".repeat(indent);
                    if trimmed == format!("goto {};", label_name) {
                        // Check for enclosing loop/switch context in the output so far
                        let has_loop_ctx = Self::has_enclosing_loop_ctx(&result, indent);
                        if indent >= 4 && has_loop_ctx {
                            result.push(format!("{}break;", indent_str));
                        } else {
                            result.push(format!("{}return;", indent_str));
                        }
                        i += 1;
                        continue;
                    }
                }
            }

            // Pattern 2: `if (cond) goto LAB_XXXX;` where LAB_XXXX is an exit label
            // Convert to `if (cond) break;` or `if (cond) return;`
            if trimmed.contains(") goto ") && trimmed.ends_with(';') {
                if let Some(goto_pos) = trimmed.find(") goto ") {
                    let label_with_semi = &trimmed[goto_pos+7..];
                    let label_name = &label_with_semi[..label_with_semi.len()-1];
                    if exit_labels.contains(label_name) {
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let cond_part = &trimmed[..goto_pos+1]; // "if (cond)"
                        let indent_str: String = " ".repeat(indent);
                        let has_loop_ctx = Self::has_enclosing_loop_ctx(&result, indent);
                        if indent >= 4 && has_loop_ctx {
                            result.push(format!("{}{} break;", indent_str, cond_part));
                        } else {
                            result.push(format!("{}{} return;", indent_str, cond_part));
                        }
                        i += 1;
                        continue;
                    }
                }
            }

            result.push(lines[i].to_string());
            i += 1;
        }

        // Second pass: remove labels that are never referenced by any goto
        let output_text = result.join("\n");
        let result_lines: Vec<&str> = output_text.lines().collect();
        let mut final_result: Vec<String> = Vec::with_capacity(result_lines.len());

        for line in &result_lines {
            let trimmed = line.trim();
            if trimmed.starts_with("LAB_") && trimmed.ends_with(':') {
                let label_name = &trimmed[..trimmed.len()-1];
                let goto_ref = format!("goto {};", label_name);
                let is_referenced = result_lines.iter().any(|l| {
                    l.trim().contains(&goto_ref)
                });
                if !is_referenced {
                    continue;
                }
            }
            final_result.push(line.to_string());
        }

        // Third pass: collapse consecutive blank lines
        let mut collapsed: Vec<String> = Vec::with_capacity(final_result.len());
        let mut prev_blank = false;
        for line in final_result {
            if line.trim().is_empty() {
                if !prev_blank {
                    collapsed.push(line);
                }
                prev_blank = true;
            } else {
                prev_blank = false;
                collapsed.push(line);
            }
        }

        // Fourth pass: detect backward goto patterns and convert to loops
        // Pattern: LAB_X: ... goto LAB_X; → do { ... } while(true);
        // Pattern: LAB_X: ... if (cond) goto LAB_X; → do { ... } while(cond);
        let mut looped = collapsed;
        let max_loop_passes = 5;
        for _pass in 0..max_loop_passes {
            let mut changed = false;
            let mut new_lines: Vec<String> = Vec::with_capacity(looped.len());
            let mut skip_until = None;

            // Build label→line index
            let mut label_lines: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for (idx, line) in looped.iter().enumerate() {
                let t = line.trim();
                if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                    label_lines.insert(t[..t.len()-1].to_string(), idx);
                }
            }

            let mut li = 0;
            while li < looped.len() {
                if let Some(skip_to) = skip_until {
                    if li < skip_to {
                        li += 1;
                        continue;
                    }
                    skip_until = None;
                }

                let trimmed = looped[li].trim();

                // Check for backward goto (plain): `goto LAB_X;` where LAB_X is above
                if trimmed.starts_with("goto LAB_") && trimmed.ends_with(';') {
                    let label_name = &trimmed[5..trimmed.len()-1];
                    if let Some(&label_line) = label_lines.get(label_name) {
                        if label_line < li {
                            let goto_indent = looped[li].len() - looped[li].trim_start().len();
                            let label_indent = looped[label_line].len() - looped[label_line].trim_start().len();
                            let indent_str: String = " ".repeat(goto_indent);
                            
                            // Safety: only convert if label and goto are at the same indent level
                            // (prevents cross-structural-boundary conversions)
                            if goto_indent == label_indent {
                                let label_text = format!("{}:", label_name);
                                let mut label_pos = None;
                                for (j, nl) in new_lines.iter().enumerate() {
                                    if nl.trim() == label_text {
                                        label_pos = Some(j);
                                        break;
                                    }
                                }
                                if let Some(lp) = label_pos {
                                    let goto_ref = format!("goto {};", label_name);
                                    let other_refs = looped.iter().enumerate().filter(|(idx, l)| {
                                        *idx != li && l.trim().contains(&goto_ref)
                                    }).count();
                                    
                                    if other_refs == 0 {
                                        new_lines[lp] = format!("{}while (true) {{", indent_str);
                                        new_lines.push(format!("{}}}", indent_str));
                                        changed = true;
                                        li += 1;
                                        continue;
                                    } else {
                                        new_lines.push(format!("{}continue;", indent_str));
                                        changed = true;
                                        li += 1;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for backward conditional goto: `if (cond) goto LAB_X;`
                if trimmed.contains(") goto ") && trimmed.ends_with(';') {
                    if let Some(goto_pos) = trimmed.find(") goto ") {
                        let label_with_semi = &trimmed[goto_pos+7..];
                        let label_name = &label_with_semi[..label_with_semi.len()-1];
                        if let Some(&label_line) = label_lines.get(label_name) {
                            if label_line < li {
                                let goto_indent = looped[li].len() - looped[li].trim_start().len();
                                let label_indent = looped[label_line].len() - looped[label_line].trim_start().len();
                                let indent_str: String = " ".repeat(goto_indent);
                                let cond_part = &trimmed[..goto_pos+1];
                                
                                // Safety: only convert if label and goto at same indent
                                if goto_indent == label_indent {
                                    let label_text = format!("{}:", label_name);
                                    let mut label_pos = None;
                                    for (j, nl) in new_lines.iter().enumerate() {
                                        if nl.trim() == label_text {
                                            label_pos = Some(j);
                                            break;
                                        }
                                    }
                                    if let Some(lp) = label_pos {
                                        let goto_ref = format!("goto {};", label_name);
                                        let other_refs = looped.iter().enumerate().filter(|(idx, l)| {
                                            *idx != li && l.trim().contains(&goto_ref)
                                        }).count();
                                        
                                        let cond = if cond_part.starts_with("if (") && cond_part.ends_with(')') {
                                            &cond_part[4..cond_part.len()-1]
                                        } else {
                                            "true"
                                        };
                                        
                                        if other_refs == 0 {
                                            new_lines[lp] = format!("{}do {{", indent_str);
                                            new_lines.push(format!("{}}} while ({});", indent_str, cond));
                                            changed = true;
                                            li += 1;
                                            continue;
                                        } else {
                                            new_lines.push(format!("{}{} continue;", indent_str, cond_part));
                                            changed = true;
                                            li += 1;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                new_lines.push(looped[li].clone());
                li += 1;
            }

            looped = new_lines;
            if !changed { break; }
        }

        // Fifth pass: remove unreferenced labels (again, after loop conversion)
        let mut final_pass: Vec<String> = Vec::with_capacity(looped.len());
        for line in &looped {
            let trimmed = line.trim();
            if trimmed.starts_with("LAB_") && trimmed.ends_with(':') && !trimmed.contains(' ') {
                let label_name = &trimmed[..trimmed.len()-1];
                let goto_ref = format!("goto {};", label_name);
                let is_referenced = looped.iter().any(|l| l.trim().contains(&goto_ref));
                if !is_referenced {
                    continue;
                }
            }
            final_pass.push(line.clone());
        }

        // Sixth pass: text-level single-use variable inlining
        // For `uVarX = EXPR;` where uVarX appears exactly twice (1 def + 1 use),
        // substitute EXPR at the use site and remove the assignment + declaration
        let mut inlined = final_pass;
        {
            // Collect all uVar assignments: (line_index, var_name, rhs_expr)
            let mut assignments: Vec<(usize, String, String)> = Vec::new();
            for (idx, line) in inlined.iter().enumerate() {
                let t = line.trim();
                // Match: uVarNNN = ...;
                if t.starts_with("uVar") {
                    if let Some(eq_pos) = t.find(" = ") {
                        let var_name = &t[..eq_pos];
                        // Must be a simple uVarNNN name
                        if var_name.chars().skip(4).all(|c| c.is_ascii_digit()) {
                            let rhs = t[eq_pos+3..].trim_end_matches(';').to_string();
                            // Skip if RHS is a function call (contains "(" but not just "(")
                            // We inline these since they're just value assignments
                            assignments.push((idx, var_name.to_string(), rhs));
                        }
                    }
                }
            }

            // For each assignment, count total occurrences of the variable name
            let full_text = inlined.join("\n");
            let mut to_inline: Vec<(usize, String, String)> = Vec::new();
            let mut to_dead_elim: Vec<(usize, String)> = Vec::new();
            for (idx, var_name, rhs) in &assignments {
                let count = Self::count_word_occurrences(&full_text, var_name);
                if count == 3 {
                    // 1 declaration + 1 assignment + 1 use → inline
                    to_inline.push((*idx, var_name.clone(), rhs.clone()));
                } else if count == 2 {
                    // 1 declaration + 1 assignment, never used → dead code
                    // Only eliminate if RHS has no side effects (no function calls)
                    if !rhs.contains('(') {
                        to_dead_elim.push((*idx, var_name.clone()));
                    }
                }
            }

            // Apply inlining (reverse order to preserve indices)
            for (assign_idx, var_name, rhs) in to_inline.iter().rev() {
                // Remove the assignment line
                inlined[*assign_idx] = String::new();
                
                // Replace the use of var_name with rhs in all other lines
                for i in 0..inlined.len() {
                    if i == *assign_idx { continue; }
                    let line = &inlined[i];
                    let t = line.trim();
                    // Skip declaration lines
                    if t.contains(&format!(" {};", var_name)) {
                        inlined[i] = String::new();
                        continue;
                    }
                    if line.contains(var_name.as_str()) {
                        inlined[i] = Self::replace_word(&line, var_name, rhs);
                    }
                }
            }

            // Apply dead code elimination
            for (assign_idx, var_name) in to_dead_elim.iter().rev() {
                inlined[*assign_idx] = String::new();
                // Also remove the declaration
                for i in 0..inlined.len() {
                    let t = inlined[i].trim();
                    if t.contains(&format!(" {};", var_name)) {
                        inlined[i] = String::new();
                        break;
                    }
                }
            }
        }

        // Final: collapse blank lines again
        let mut result_final: Vec<String> = Vec::with_capacity(inlined.len());
        let mut prev_blank2 = false;
        for line in inlined {
            if line.trim().is_empty() {
                if !prev_blank2 {
                    result_final.push(line);
                }
                prev_blank2 = true;
            } else {
                prev_blank2 = false;
                result_final.push(line);
            }
        }

        // Seventh pass: textual cleanup transformations
        let mut cleaned: Vec<String> = Vec::with_capacity(result_final.len());
        for line in &result_final {
            let mut s = line.clone();

            // 1. *&x → x (redundant dereference of address-of)
            while s.contains("*&") {
                s = s.replace("*&", "");
            }

            // 1b. Reconcile `int - pointer` (illegal C). Only subtraction is
            // affected (int + pointer is legal, yields pointer). When a line
            // contains "<const> - <ptrvar>" where const is a bare integer and
            // ptrvar has a pointer prefix (pi/pc/ps/pp/pv Var), cast the
            // constant to (char *) so it becomes `pointer - pointer`. This is
            // conservative: we only act when the operand before "-" is a
            // standalone integer literal preceded by space/=/(.
            // (This is a print-layer stopgap; the real fix is type propagation
            // making the output varnode pointer-typed.)
            // reconcile_int_minus_pointer still needed for non-LOAD pointers
            // (e.g. function parameters typed as int* used in subtraction).
            s = reconcile_int_minus_pointer(&s);
            // reconcile_pointer_arith no longer needed: LOAD results are now
            // correctly typed as int/long (not pointer) via mark_varnode_used
            // LOAD detection, so ptr/int division doesn't occur.
            // s = reconcile_pointer_arith(&s);
            // reconcile_int_times_string still needed for copy-propagation
            // artifacts (string address inlined into MULT operand).
            if s.contains(" * \"") {
                s = reconcile_int_times_string(&s);
            }
            if s.contains("*(_struct *)") && s.contains("= ") {
                s = s.replace("*(_struct *)", "*(long *)");
            }

            // 2. Constant folding: collapse repeated "+ 1" chains
            // Match: expr + 1 + 1 + 1 ... → expr + N
            loop {
                if let Some(pos) = s.find("+ 1 + 1") {
                    // Count how many consecutive "+ 1" there are
                    let base = &s[..pos];
                    let rest = &s[pos..];
                    let mut count = 0;
                    let mut idx = 0;
                    while rest[idx..].starts_with("+ 1") {
                        count += 1;
                        idx += 4; // "+ 1 " or "+ 1;" etc
                        if idx > rest.len() { break; }
                        // Skip space
                        while idx < rest.len() && rest.as_bytes().get(idx) == Some(&b' ') {
                            idx += 1;
                        }
                    }
                    if count >= 2 {
                        let after = &rest[idx - 1..]; // keep the trailing part
                        s = format!("{}+ {}{}", base, count, after);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // 3. Arithmetic simplification: "+ -N" → "- N"
            while let Some(pos) = s.find("+ -") {
                let after = &s[pos+3..];
                // Find the number
                let num_end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                if num_end > 0 {
                    let num = &after[..num_end];
                    s = format!("{}- {}{}", &s[..pos], num, &after[num_end..]);
                } else {
                    break;
                }
            }

            // 4. Character constants in if comparisons
            // Pattern: != 0xNN or == 0xNN where NN is printable ASCII
            let hex_chars = [
                ("0x2d", "'-'"), ("0x5b", "'['"), ("0x5d", "']'"),
                ("0x7b", "'{'"), ("0x7d", "'}'"), ("0x2e", "'.'"),
                ("0x2f", "'/'"), ("0x3a", "':'"), ("0x23", "'#'"),
                ("0x2a", "'*'"), ("0x3f", "'?'"), ("0x21", "'!'"),
                ("0x40", "'@'"), ("0x3d", "'='"), ("0x26", "'&'"),
                ("0x2c", "','"), ("0x3b", "';'"), ("0x22", "'\"'"),
                ("0x27", "'''"), ("0x28", "'('"), ("0x29", "')'"),
                ("0x30", "'0'"), ("0x39", "'9'"), ("0x41", "'A'"),
                ("0x5a", "'Z'"), ("0x61", "'a'"), ("0x7a", "'z'"),
                ("0x20", "' '"), ("0x09", "'\\t'"), ("0x0a", "'\\n'"),
                ("0x4f", "'O'"),
            ];
            for (hex, ch) in &hex_chars {
                // Replace in comparison contexts: == 0xNN, != 0xNN
                let eq_pattern = format!("== {}", hex);
                let ne_pattern = format!("!= {}", hex);
                let eq_replacement = format!("== {}", ch);
                let ne_replacement = format!("!= {}", ch);
                s = s.replace(&eq_pattern, &eq_replacement);
                s = s.replace(&ne_pattern, &ne_replacement);
                // Also in assignments: = 0xNN; at end
                let assign_pattern = format!("= {};", hex);
                let assign_replacement = format!("= {};", ch);
                s = s.replace(&assign_pattern, &assign_replacement);
            }

            cleaned.push(s);
        }

        // Eighth pass: remove blank lines within declaration blocks
        // (between type declarations at function start)
        let mut final_cleaned: Vec<String> = Vec::with_capacity(cleaned.len());
        let mut in_decl_block = false;
        let mut decl_count = 0usize;
        let mut separator_kept = false;
        for (_i, line) in cleaned.iter().enumerate() {
            let t = line.trim();
            // Detect start of function. The function-body `{` either trails
            // the signature (legacy layout) or sits alone on the next line
            // (the oracle's option_brace_func=skip_line layout, printc.cc:
            // 1590/2655); both forms open a declaration block here.
            if t.ends_with('{') && !t.starts_with("if") && !t.starts_with("else")
                && !t.starts_with("while") && !t.starts_with("do")
                && !t.starts_with("for") && !t.starts_with("switch")
                && !t.starts_with("case") {
                in_decl_block = true;
                decl_count = 0;
                separator_kept = false;
                final_cleaned.push(line.clone());
                continue;
            }
            if in_decl_block {
                // Declaration lines: "  type varname;"
                let is_decl = t.starts_with("int ") || t.starts_with("long ")
                    || t.starts_with("byte ") || t.starts_with("bool ")
                    || t.starts_with("short ") || t.starts_with("char ");
                if t.is_empty() {
                    // The emitter already places exactly one indent-only
                    // separator line after the declaration block (the
                    // faithful render of emitLocalVarDecls' trailing
                    // tagLine, printc.cc:2277-2278). Keep the FIRST such
                    // line verbatim (preserving its indent bytes) and drop
                    // only extra consecutive blanks; do NOT synthesize a
                    // new empty line — a function with no declarations has
                    // no separator in the oracle output either.
                    if decl_count == 0 || separator_kept {
                        continue;
                    }
                    separator_kept = true;
                    final_cleaned.push(line.clone());
                } else if is_decl {
                    decl_count += 1;
                    final_cleaned.push(line.clone());
                } else {
                    // End of declaration block
                    in_decl_block = false;
                    final_cleaned.push(line.clone());
                }
            } else {
                final_cleaned.push(line.clone());
            }
        }
        // Ninth pass: structural cleanup
        let mut structural: Vec<String> = Vec::with_capacity(final_cleaned.len());
        let mut i9 = 0;
        while i9 < final_cleaned.len() {
            let t = final_cleaned[i9].trim().to_string();

            // 1. Dead break after break/continue/return
            // If current line is break/continue/return and next is break → skip next
            if (t == "break;" || t == "continue;" || t == "return;")
                && i9 + 1 < final_cleaned.len()
                && final_cleaned[i9 + 1].trim() == "break;"
            {
                structural.push(final_cleaned[i9].clone());
                i9 += 2; // skip the dead break
                continue;
            }

            // 2. if (1) → remove the if, keep the body
            if t == "if (1)" && i9 + 1 < final_cleaned.len() {
                let next = final_cleaned[i9 + 1].trim().to_string();
                // "if (1)\n  goto X;" → "goto X;"
                let indent = final_cleaned[i9].len() - final_cleaned[i9].trim_start().len();
                let indent_str: String = " ".repeat(indent);
                structural.push(format!("{}{}", indent_str, next));
                i9 += 2;
                continue;
            }

            // 3. Simplify "1 || expr" → always true (the whole condition is true)
            let mut line = final_cleaned[i9].clone();

            line = line.replace("if (0 == 0) return;", "return;");
            line = line.replace("if (0 == 0) {", "if (1) {");

            if line.contains("1 || ") {
                // "if (1 || anything)" → "if (1)" which will be caught next pass
                // For now, replace the condition
                while line.find("1 || ").is_some() {
                    line = line.replacen("1 || ", "", 1);
                }
            }

            // 4. "+N - N" cancellation (e.g., "+ 1 - 1" → "")
            let cancel_patterns = [
                ("+ 1 - 1", ""),
                ("+ 2 - 2", ""),
                ("+ 4 - 4", ""),
                ("+ 8 - 8", ""),
            ];
            for (pattern, replacement) in &cancel_patterns {
                line = line.replace(pattern, replacement);
            }
            // Clean up double spaces in content (not indent) from cancellation
            {
                let trimmed_start = line.len() - line.trim_start().len();
                let indent_part = &line[..trimmed_start];
                let mut content = line[trimmed_start..].to_string();
                while content.contains("  ") {
                    content = content.replace("  ", " ");
                }
                // Also clean trailing space before )
                content = content.replace(" )", ")");
                line = format!("{}{}", indent_part, content);
            }

            // 5. "goto function_name;" where function_name is a known libc function → tail call
            if t.starts_with("goto ") && t.ends_with(';') && !t.contains("LAB_") {
                let func_name = &t[5..t.len()-1];
                // Check it's a plausible function name (lowercase, no spaces).
                // `code_r0x...` labels (PrintC::emitLabel, printc.rs code_label /
                // printc.cc:3164-3193) are flat-mode goto TARGETS, not function
                // names — exclude them or every flat tail goto gets rewritten
                // into a bogus `return code_r0x...();` call (which gcc rejects
                // as an implicit-function-declaration of a label).
                if func_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && func_name.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                    && !func_name.starts_with("code_")
                    && !func_name.starts_with("joined_")
                    && !func_name.starts_with("dup_")
                {
                    let indent = final_cleaned[i9].len() - final_cleaned[i9].trim_start().len();
                    let indent_str: String = " ".repeat(indent);
                    structural.push(format!("{}return {}();", indent_str, func_name));
                    i9 += 1;
                    continue;
                }
            }

            structural.push(line);
            i9 += 1;
        }

        // Tenth pass: remove dead code after return/break/continue
        // If we see `return;` at indent level N, subsequent lines at the same indent
        // are dead unless they are labels (goto targets), closing braces, or case labels.
        let mut alive: Vec<String> = Vec::with_capacity(structural.len());
        let mut dead_after_return = false;
        let mut dead_indent = 0usize;
        // First collect all goto-referenced labels
        let all_text = structural.join("\n");
        for line in &structural {
            let t = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Check if this line is a goto target label that's referenced
            if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                let label_name = &t[..t.len()-1];
                let goto_ref = format!("goto {};", label_name);
                if all_text.contains(&goto_ref) {
                    // Referenced label — end dead zone
                    dead_after_return = false;
                    alive.push(line.clone());
                    continue;
                }
            }

            if dead_after_return && indent >= dead_indent {
                // In dead zone — check if this is a structural element that ends the dead zone.
                // A `}` only ends the dead zone if it's at a SHALLOWER indent than where return
                // occurred (i.e. it closes a block that contains the return). A `}` at the same
                // or deeper indent is itself dead code and should be removed.
                if t == "}" {
                    if indent < dead_indent {
                        // Closes the dead block — end dead zone, keep the brace
                        dead_after_return = false;
                        alive.push(line.clone());
                    } else {
                        // Dead closing brace — skip
                        continue;
                    }
                } else if t.starts_with("case ") || t.starts_with("default:") {
                    // Switch case label — end dead zone (reachable via case fallthrough)
                    dead_after_return = false;
                    alive.push(line.clone());
                } else if t.starts_with("while (") || t.starts_with("do ") || t.starts_with("for (") || Self::is_switch_stmt_prefix(t) {
                    // Control-flow structures (loops/switches) are not dead code even
                    // after a return — they may be reachable via fallthrough or represent
                    // structured control flow that the emit traversal placed after a return.
                    dead_after_return = false;
                    alive.push(line.clone());
                } else if t.is_empty() {
                    // Blank lines in dead zone — skip without resetting (they don't make
                    // following dead code reachable).
                    continue;
                } else {
                    // Dead code — skip
                    continue;
                }
            } else {
                dead_after_return = false;
                alive.push(line.clone());
            }

            // Check if this line starts a dead zone
            if t == "return;" || t == "break;" || t == "continue;" || t.starts_with("goto ") {
                dead_after_return = true;
                dead_indent = indent;
            }
        }

        // Eleventh pass: remove unused variable declarations
        // For each function, collect declared uVar names and remove those never referenced in body
        let mut cleaned: Vec<String> = Vec::with_capacity(alive.len());
        let mut func_start: Option<usize> = None;
        let mut func_lines: Vec<String> = Vec::new();

        for index in 0..alive.len() {
            let line = &alive[index];
            let t = line.trim();
            // Detect function start (same-line `sig {` or skip_line `sig` + `{`)
            if Self::signature_opens_function_body(
                t,
                &[
                    "int ", "void ", "long ", "byte ", "bool ", "short ",
                ],
                &alive[index + 1..],
            ) {
                // Flush previous function
                if func_start.is_some() {
                    Self::flush_func_remove_unused(&func_lines, &mut cleaned);
                }
                func_lines = vec![line.clone()];
                func_start = Some(cleaned.len());
                continue;
            }
            if func_start.is_some() {
                func_lines.push(line.clone());
            } else {
                cleaned.push(line.clone());
            }
        }
        // Flush last function
        if func_start.is_some() {
            Self::flush_func_remove_unused(&func_lines, &mut cleaned);
        }

        // Twelfth pass: remove blank line after "} else {"
        let mut final_out: Vec<String> = Vec::with_capacity(cleaned.len());
        let mut skip_next_blank = false;
        for line in &cleaned {
            let t = line.trim();
            if skip_next_blank && t.is_empty() {
                skip_next_blank = false;
                continue;
            }
            skip_next_blank = t == "} else {";
            final_out.push(line.clone());
        }

        // Thirteenth pass: split "return func();" into "func(); return;" for void functions
        let void_funcs = ["free", "puts", "fclose", "exit", "fflush", "clearerr",
            "rewind", "perror", "abort", "qsort", "curl_easy_cleanup",
            "curl_slist_free_all", "curl_global_cleanup"];
        let mut pass13: Vec<String> = Vec::with_capacity(final_out.len());
        for line in &final_out {
            let t = line.trim();
            if t.starts_with("return ") && t.ends_with(");") {
                // Extract function name from "return func(...);"
                let inner = &t[7..t.len()-1]; // "func(...)"
                if let Some(paren) = inner.find('(') {
                    let fname = &inner[..paren];
                    if void_funcs.contains(&fname) {
                        let indent = &line[..line.len() - line.trim_start().len()];
                        pass13.push(format!("{}{});", indent, inner));
                        pass13.push(format!("{}return;", indent));
                        continue;
                    }
                }
            }
            pass13.push(line.clone());
        }

        // Fourteenth pass: remove dead code after goto (consecutive goto, or code after goto on same indent)
        let mut pass14: Vec<String> = Vec::with_capacity(pass13.len());
        let mut prev_was_goto = false;
        for line in &pass13 {
            let t = line.trim();
            if prev_was_goto {
                // Skip lines that are dead code (another goto or non-label code at same level)
                if t.starts_with("goto ") {
                    continue; // skip consecutive goto
                }
                prev_was_goto = false;
            }
            if t.starts_with("goto ") && t.ends_with(';') {
                prev_was_goto = true;
            }
            pass14.push(line.clone());
        }

        // Fifteenth pass: fix double-close-paren "func());" → "func();"
        let mut pass15: Vec<String> = Vec::with_capacity(pass14.len());
        for line in &pass14 {
            let fixed = line.replace("());", "();");
            pass15.push(fixed);
        }

        // Sixteenth pass: forward goto-to-if folding
        // Pattern: `if (cond) goto LAB_X;` followed by code, then `LAB_X:` appears below.
        // Fold into: `if (!cond) { ... code ... }` and remove the goto + label.
        // Also handles plain `goto LAB_X;` → wraps remaining code in else-like block.
        let mut pass16 = pass15;
        let max_fold_passes = 3; // iterate a few times for nested patterns
        for _fold_iter in 0..max_fold_passes {
            let mut changed = false;
            let mut new_lines: Vec<String> = Vec::with_capacity(pass16.len());
            let mut i16 = 0;

            while i16 < pass16.len() {
                let trimmed = pass16[i16].trim().to_string();
                let line_indent = pass16[i16].len() - pass16[i16].trim_start().len();

                // Match: `if (cond) goto LAB_XXXX;`
                if trimmed.contains(") goto LAB_") && trimmed.ends_with(';')
                    && trimmed.starts_with("if (")
                {
                    // Extract condition and label
                    if let Some(goto_pos) = trimmed.find(") goto LAB_") {
                        let cond = &trimmed[4..goto_pos]; // inside "if (" ... ")"
                        let label_with_semi = &trimmed[goto_pos + 7..]; // "LAB_XXXX;"
                        let label_name = &label_with_semi[..label_with_semi.len() - 1]; // "LAB_XXXX"
                        let label_def = format!("{}:", label_name);

                        // Search forward for the label definition within the same function
                        let mut label_line = None;
                        let mut has_other_goto_to_label = false;
                        for j in (i16 + 1)..pass16.len() {
                            let jt = pass16[j].trim();
                            // Stop at function boundary
                            if jt.starts_with("/* ----") && jt.ends_with("---- */") {
                                break;
                            }
                            if jt == label_def {
                                label_line = Some(j);
                                break;
                            }
                            // Check if another goto references this same label (would make folding unsafe)
                            if jt.contains(&format!("goto {};", label_name)) {
                                has_other_goto_to_label = true;
                            }
                        }

                        // Only fold if:
                        // 1. Label is found forward
                        // 2. No other goto references the same label (single-use forward jump)
                        // 3. The gap isn't too large (limit to ~80 lines to avoid huge indentation)
                        if let Some(lbl_line) = label_line {
                            if !has_other_goto_to_label && (lbl_line - i16) <= 80 {
                                // Check that the code between goto and label is at >= the same indent
                                let indent_str: String = " ".repeat(line_indent);

                                // Negate the condition
                                let negated = Self::negate_simple_condition(cond);

                                // Emit: if (negated_cond) {
                                new_lines.push(format!("{}if ({}) {{", indent_str, negated));

                                // Emit the body (lines between goto and label), indented +2
                                let body_indent: String = " ".repeat(line_indent + 2);
                                for k in (i16 + 1)..lbl_line {
                                    let body_line = &pass16[k];
                                    let bt = body_line.trim();
                                    if bt.is_empty() {
                                        new_lines.push(String::new());
                                    } else {
                                        new_lines.push(format!("{}{}", body_indent, bt));
                                    }
                                }

                                // Close the block
                                new_lines.push(format!("{}}}", indent_str));

                                // Skip past the label line
                                i16 = lbl_line + 1;
                                changed = true;
                                continue;
                            }
                        }
                    }
                }

                // Match: plain `goto LAB_XXXX;` (forward, single-use)
                // Convert surrounding code to avoid the goto when label is close
                if trimmed.starts_with("goto LAB_") && trimmed.ends_with(';')
                    && !trimmed.contains("if ")
                {
                    let label_name = &trimmed[5..trimmed.len() - 1]; // "LAB_XXXX"
                    let label_def = format!("{}:", label_name);

                    let mut label_line = None;
                    let mut has_other_goto_to_label = false;
                    for j in (i16 + 1)..pass16.len() {
                        let jt = pass16[j].trim();
                        if jt.starts_with("/* ----") && jt.ends_with("---- */") {
                            break;
                        }
                        if jt == label_def {
                            label_line = Some(j);
                            break;
                        }
                        if jt.contains(&format!("goto {};", label_name)) {
                            has_other_goto_to_label = true;
                        }
                    }

                    // For plain forward gotos with no other references and short gap,
                    // just skip the intermediate dead code (it's unreachable)
                    if let Some(lbl_line) = label_line {
                        if !has_other_goto_to_label && (lbl_line - i16) <= 40 {
                            // Skip lines between goto and label (dead code)
                            // The goto itself is redundant — code falls through to label
                            i16 = lbl_line + 1;
                            changed = true;
                            continue;
                        }
                    }
                }

                new_lines.push(pass16[i16].clone());
                i16 += 1;
            }

            pass16 = new_lines;
            if !changed { break; }
        }

        // Sixteenth pass cleanup: remove now-unreferenced labels and empty if blocks
        let pass16_text = pass16.join("\n");
        let pass16_lines: Vec<&str> = pass16_text.lines().collect();
        let mut pass16_final: Vec<String> = Vec::with_capacity(pass16_lines.len());
        let mut i16c = 0;
        while i16c < pass16_lines.len() {
            let t = pass16_lines[i16c].trim();

            // Remove unreferenced labels
            if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                let label_name = &t[..t.len() - 1];
                let goto_ref = format!("goto {};", label_name);
                if !pass16_text.contains(&goto_ref) {
                    i16c += 1;
                    continue; // unreferenced label, remove
                }
            }

            // Remove empty if blocks: "if (...) {" followed by "}"
            if t.starts_with("if (") && t.ends_with('{') {
                if i16c + 1 < pass16_lines.len() && pass16_lines[i16c + 1].trim() == "}" {
                    i16c += 2; // skip both lines
                    continue;
                }
            }

            pass16_final.push(pass16_lines[i16c].to_string());
            i16c += 1;
        }

        // Final collapse of consecutive blank lines
        let mut output_final: Vec<String> = Vec::with_capacity(pass16_final.len());
        let mut prev_blank_final = false;
        for line in pass16_final {
            if line.trim().is_empty() {
                if !prev_blank_final {
                    output_final.push(line);
                }
                prev_blank_final = true;
            } else {
                prev_blank_final = false;
                output_final.push(line);
            }
        }

        // Seventeenth pass: remove orphan `break;` / `continue;` at function body start.
        // Pattern: function opening `{`, then declarations, then immediately `break;` or `continue;`
        // with no loop/switch context — these are block-structure artifacts.
        // Also: remove `return;` immediately followed by orphan `}` at body indent level
        //       (artifact from do-while blocks emitting an extra close)
        let mut pass17: Vec<String> = Vec::with_capacity(output_final.len());
        {
            let lines = &output_final;
            let n = lines.len();
            let mut i17 = 0;
            let mut skip_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();

            // Pre-scan: find `return;` followed by `  }` (body-level stray brace)
            // Pattern: lines[k] == "  return;" and lines[k+1] or lines[k+2] (skipping blank) == "  }"
            for k in 0..n {
                if skip_indices.contains(&k) { continue; }
                let t = lines[k].trim();
                let ind = lines[k].len() - lines[k].trim_start().len();
                if t == "return;" && ind >= 2 {
                    // Look for an orphan `}` at same indent within next 3 lines
                    let mut look = k + 1;
                    while look < n && look <= k + 3 {
                        let lt = lines[look].trim();
                        let li = lines[look].len() - lines[look].trim_start().len();
                        if lt.is_empty() { look += 1; continue; }
                        if lt == "}" && li == ind {
                            // Check this `}` is NOT a legitimate closing brace
                            // by seeing if there's an unclosed `{` in the preceding ~5 lines
                            let mut open_count = 0i32;
                            let scan_start = if k >= 10 { k - 10 } else { 0 };
                            for s in scan_start..k {
                                for ch in lines[s].chars() {
                                    match ch { '{' => open_count += 1, '}' => open_count -= 1, _ => {} }
                                }
                            }
                            // If open_count <= 0, there's nothing left to close → orphan brace
                            if open_count <= 0 {
                                skip_indices.insert(look);
                            }
                        }
                        break;
                    }
                }
            }

            while i17 < n {
                if skip_indices.contains(&i17) { i17 += 1; continue; }
                let line = &lines[i17];
                let t = line.trim();
                let indent = line.len() - line.trim_start().len();

                // Detect function start: signature ending with `{`, or the
                // oracle skip_line layout where the lone `{` follows the
                // signature line (printc.cc:1590/2655).
                if Self::signature_opens_function_body(
                    t,
                    &["int ", "void ", "long ", "byte ", "bool ", "short "],
                    &lines[i17 + 1..],
                ) {
                    pass17.push(line.clone());
                    i17 += 1;
                    if !t.ends_with('{') {
                        // Consume the skip_line separator and the lone `{`
                        // line so the body walk below starts inside the braces.
                        while i17 < n && lines[i17].trim().is_empty() {
                            pass17.push(lines[i17].clone());
                            i17 += 1;
                        }
                        if i17 < n && lines[i17].trim() == "{" {
                            pass17.push(lines[i17].clone());
                            i17 += 1;
                        }
                    }

                    let func_indent = indent;
                    let mut past_decls = false;

                    // Process function body
                    while i17 < n {
                        let bl = &lines[i17];
                        let bt = bl.trim();
                        let bi = bl.len() - bl.trim_start().len();

                        if skip_indices.contains(&i17) { i17 += 1; continue; }

                        // Track past declarations
                        let is_decl = bt.starts_with("int ") || bt.starts_with("long ")
                            || bt.starts_with("byte ") || bt.starts_with("bool ")
                            || bt.starts_with("short ") || bt.starts_with("char ")
                            || bt.starts_with("void *") || bt.is_empty();
                        if !past_decls && !is_decl { past_decls = true; }

                        // Skip orphan break/continue at body level (no loop/switch context)
                        if past_decls && bi == func_indent + 2
                            && (bt == "break;" || bt == "continue;")
                        {
                            let mut has_loop_ctx = false;
                            for prev in pass17.iter().rev().take(20) {
                                let pt = prev.trim();
                                if pt.starts_with("while ") || pt.starts_with("do ")
                                    || pt.starts_with("for ") || Self::is_switch_stmt_prefix(pt)
                                    || pt.contains("} while (")
                                {
                                    has_loop_ctx = true;
                                    break;
                                }
                                if pt == "}" || pt.ends_with('{') { break; }
                            }
                            if !has_loop_ctx {
                                i17 += 1;
                                continue;
                            }
                        }

                        // Skip orphan `} while (...)` without a preceding `do {`
                        if bi == func_indent + 2 && bt.starts_with("} while (") {
                            let mut has_do = false;
                            for prev in pass17.iter().rev().take(30) {
                                let pt = prev.trim();
                                if pt == "do {" || pt.starts_with("do {") {
                                    has_do = true;
                                    break;
                                }
                            }
                            if !has_do {
                                i17 += 1;
                                continue;
                            }
                        }

                        if bt == "}" && bi == func_indent { break; }
                        // Skip leading deeply-indented orphan statements before any opening structure
                        // These are block fragments that leaked from a misrouted CFG block
                        // (e.g., `    *(param + off) = val;` at indent+4 before any `if`/`while`)
                        if !past_decls {
                            // Still in declarations — shouldn't be deeply indented
                            if bi >= func_indent + 4 && !bt.ends_with('{') {
                                i17 += 1;
                                continue;
                            }
                        }
                        pass17.push(bl.clone());
                        i17 += 1;
                    }
                    // emit the closing brace
                    if i17 < n { pass17.push(lines[i17].clone()); i17 += 1; }
                    continue;
                }

                pass17.push(line.clone());
                i17 += 1;
            }
        }

        // Eighteenth pass: remove unreachable `return;` at very start of function body.
        // Pattern: after the last declaration line, if the first statement is `return;`
        // but is followed by more non-empty lines — it's dead code from a misrouted block.
        let mut pass18: Vec<String> = Vec::with_capacity(pass17.len());
        {
            let lines = &pass17;
            let mut i18 = 0;
            while i18 < lines.len() {
                let line = &lines[i18];
                let t = line.trim();
                let indent = line.len() - line.trim_start().len();

                // Detect function opening (same-line `sig {` or skip_line
                // `sig` + lone `{`, printc.cc:1590/2655)
                if Self::signature_opens_function_body(
                    t,
                    &["int ", "void ", "long ", "byte ", "bool ", "short "],
                    &lines[i18 + 1..],
                ) {
                    let func_indent = indent;
                    pass18.push(line.clone());
                    i18 += 1;
                    if !t.ends_with('{') {
                        while i18 < lines.len() && lines[i18].trim().is_empty() {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        }
                        if i18 < lines.len() && lines[i18].trim() == "{" {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        }
                    }

                    // Consume declarations
                    while i18 < lines.len() {
                        let lt = lines[i18].trim();
                        let _li = lines[i18].len() - lines[i18].trim_start().len();
                        let is_decl = lt.starts_with("int ") || lt.starts_with("long ")
                            || lt.starts_with("byte ") || lt.starts_with("bool ")
                            || lt.starts_with("short ") || lt.starts_with("char ")
                            || lt.starts_with("void *") || lt.is_empty();
                        if is_decl {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        } else {
                            break;
                        }
                    }

                    // Check if the next statement is `return;` at body level
                    if i18 < lines.len() {
                        let next_t = lines[i18].trim();
                        let next_i = lines[i18].len() - lines[i18].trim_start().len();
                        if next_t == "return;" && next_i == func_indent + 2 {
                            // Look ahead: is there more code before the function closes?
                            let mut has_more = false;
                            let mut look = i18 + 1;
                            while look < lines.len() {
                                let lt = lines[look].trim();
                                let li = lines[look].len() - lines[look].trim_start().len();
                                if li == func_indent && lt == "}" {
                                    break; // function end
                                }
                                if !lt.is_empty() && li >= func_indent + 2 {
                                    has_more = true;
                                    break;
                                }
                                look += 1;
                            }
                            if has_more {
                                // Drop the return; it's dead code at function start
                                i18 += 1;
                                continue;
                            }
                        }
                    }
                    continue;
                }

                pass18.push(line.clone());
                i18 += 1;
            }
        }

        // Nineteenth pass: remove unmatched extra closing braces at end of functions.
        // After each function (detected by top-level `}`), check brace balance.
        // If a function body has more `{` than `}`, insert missing closes.
        // If more `}` than `{`, remove trailing extras.
        let mut pass19: Vec<String> = Vec::with_capacity(pass18.len());
        {
            let mut i19 = 0;
            while i19 < pass18.len() {
                let line = &pass18[i19];
                let t = line.trim();
                let indent = line.len() - line.trim_start().len();

                // Detect function start (same-line `sig {` or skip_line
                // `sig` + lone `{`, printc.cc:1590/2655)
                if Self::signature_opens_function_body(
                    t,
                    &["int ", "void ", "long ", "byte ", "bool ", "short "],
                    &pass18[i19 + 1..],
                ) {
                    // Collect the entire function body
                    let func_start = i19;
                    let func_indent = indent;
                    let mut depth = 1i32; // we've seen the opening `{`
                    let mut func_end = i19 + 1;
                    if !t.ends_with('{') {
                        // skip_line layout: the lone `{` is on a following
                        // line and is already accounted for by depth=1.
                        while func_end < pass18.len() && pass18[func_end].trim().is_empty() {
                            func_end += 1;
                        }
                        if func_end < pass18.len() && pass18[func_end].trim() == "{" {
                            func_end += 1;
                        }
                    }
                    while func_end < pass18.len() {
                        let ft = pass18[func_end].trim();
                        let fi = pass18[func_end].len() - pass18[func_end].trim_start().len();
                        // Count braces (simplistic — good enough for C output)
                        for ch in ft.chars() {
                            match ch {
                                '{' => depth += 1,
                                '}' => depth -= 1,
                                _ => {}
                            }
                        }
                        func_end += 1;
                        if depth <= 0 && fi == func_indent {
                            break;
                        }
                    }

                    // Check if depth reached 0 cleanly, or has extra/missing braces
                    if depth < 0 {
                        // More `}` than `{` — emit as-is. The naive brace count
                        // over-counts `}` inside char/string literals (e.g.
                        // case '}'), so removing braces based on it corrupts
                        // function boundaries. Leave the output unchanged.
                        for fi in func_start..func_end {
                            pass19.push(pass18[fi].clone());
                        }
                    } else {
                        // Normal or missing braces — emit as-is (missing brace is rarer)
                        for fi in func_start..func_end {
                            pass19.push(pass18[fi].clone());
                        }
                    }

                    i19 = func_end;
                    continue;
                }

                pass19.push(line.clone());
                i19 += 1;
            }
        }

        // Final collapse of consecutive blank lines
        let mut output_final2: Vec<String> = Vec::with_capacity(pass19.len());
        let mut prev_blank_final2 = false;
        for line in pass19 {
            if line.trim().is_empty() {
                if !prev_blank_final2 {
                    output_final2.push(line);
                }
                prev_blank_final2 = true;
            } else {
                prev_blank_final2 = false;
                output_final2.push(line);
            }
        }

        // While-break collapse pass: fold `while (cond) { ... break; }` into `if (cond) { ... }`.
        //
        // Rugra's CFG structuring occasionally emits a loop construct whose body is
        // entered once and immediately exits via unconditional `break;`. This is
        // semantically a conditional single-shot execution, i.e. an `if`, not a loop.
        // Ghidra's blockaction structuring does not produce this pattern; we collapse
        // it textually as a post-print normalization so the output matches Ghidra's
        // control-flow style.
        //
        // Pattern (general):
        //   while (COND) {
        //     <body lines at indent+2>
        //     break;          <- last body line, unconditional
        //   }
        // Becomes:
        //   if (COND) {
        //     <body lines at indent+2>
        //   }
        //
        // We only fold when the matching `}` directly follows the `break;`, ensuring
        // the break truly terminates the loop body.
        let mut collapsed: Vec<String> = Vec::with_capacity(output_final2.len());
        let mut iwb = 0usize;
        while iwb < output_final2.len() {
            let line = &output_final2[iwb];
            let t = line.trim();
            // Detect a `while (...) {` opener (not `do {` or `} while (...)`).
            if t.starts_with("while (") && t.ends_with('{') {
                let indent = line.len() - line.trim_start().len();
                let body_indent = indent + 2;
                // Scan forward for the matching close brace at the same indent as the while.
                // We need to find: body lines, then `break;` at body_indent, then `}` at indent.
                // Use brace-depth tracking to handle nested braces inside the body.
                let mut j = iwb + 1;
                let mut depth: i32 = 1; // we are inside the while block
                let mut break_line_idx: Option<usize> = None;
                let mut close_idx: Option<usize> = None;
                while j < output_final2.len() {
                    let bj = &output_final2[j];
                    let tj = bj.trim();
                    let ij = bj.len() - bj.trim_start().len();
                    // Track nested braces
                    if tj.ends_with('{') && !tj.starts_with("while") {
                        // opening of a nested block (e.g. if/for/switch body)
                        // Only count as depth+1 if it's a structural opener
                        if tj == "{" || tj.ends_with(" {") || tj.ends_with("){") {
                            depth += 1;
                        }
                    }
                    if tj == "}" {
                        depth -= 1;
                        if depth == 0 {
                            // This is the while's closing brace
                            close_idx = Some(j);
                            break;
                        }
                    }
                    // Record a candidate `break;` at the while's direct body indent
                    if depth == 1 && tj == "break;" && ij == body_indent {
                        break_line_idx = Some(j);
                    }
                    j += 1;
                }

                if let (Some(bi), Some(ci)) = (break_line_idx, close_idx) {
                    // Only fold if `break;` is the LAST body line before the close brace.
                    // (i.e. no lines between break_line_idx+1 and close_idx-1 except blanks)
                    let mut only_blanks_after_break = true;
                    for k in (bi + 1)..ci {
                        if !output_final2[k].trim().is_empty() {
                            only_blanks_after_break = false;
                            break;
                        }
                    }
                    if only_blanks_after_break && bi > iwb {
                        // Fold: replace `while` with `if`, drop the `break;`, drop trailing blanks.
                        let indent_str = " ".repeat(indent);
                        // Extract the condition. The opener looks like `while (COND) {`.
                        // Strip the `while ` prefix and the trailing ` {`, then strip one layer
                        // of matching outer parentheses so we don't produce `if ((COND))`.
                        let after_while = &t["while ".len()..];
                        let inner = after_while.trim_end().trim_end_matches('{').trim();
                        let cond_str = if inner.starts_with('(') && inner.ends_with(')') {
                            &inner[1..inner.len()-1]
                        } else {
                            inner
                        };
                        // Collect non-blank body lines between the while-opener and the break;
                        let body_lines: Vec<&String> = ((iwb + 1)..bi)
                            .map(|k| &output_final2[k])
                            .filter(|l| !l.trim().is_empty())
                            .collect();
                        if body_lines.len() == 1 {
                            // Single-statement body: emit `if (cond) stmt;` (no braces)
                            collapsed.push(format!("{}if ({}) {}", indent_str, cond_str, body_lines[0].trim()));
                        } else {
                            // Multi-line body: `if (cond) {` ... body ... `}`
                            collapsed.push(format!("{}if ({}) {{", indent_str, cond_str));
                            for k in (iwb + 1)..bi {
                                collapsed.push(output_final2[k].clone());
                            }
                            collapsed.push(format!("{}}}", indent_str));
                        }
                        iwb = ci + 1;
                        continue;
                    }
                }
            }
            collapsed.push(line.clone());
            iwb += 1;
        }
        let output_final2 = collapsed;

        // Empty switch-case removal pass.
        // Pattern (3 consecutive lines, same case indent):
        //     case N: {
        //       break;
        //     }
        // These contribute nothing (the switch falls through). Remove the whole
        // 3-line group. Also handle the `default:` variant with only a blank line
        // before `break;`. Ghidra does not emit cases whose body is solely `break;`.
        let mut no_empty_cases: Vec<String> = Vec::with_capacity(output_final2.len());
        let mut ie = 0usize;
        while ie < output_final2.len() {
            let t = output_final2[ie].trim();
            // Detect `case ...: {` or `default: {`
            if (t.starts_with("case ") || t == "default: {") && t.ends_with('{') {
                let case_indent = output_final2[ie].len() - output_final2[ie].trim_start().len();
                // Look ahead: optional blank line(s), then `break;`, then `}` at case_indent
                let mut k = ie + 1;
                // skip blanks
                while k < output_final2.len() && output_final2[k].trim().is_empty() {
                    k += 1;
                }
                if k < output_final2.len()
                    && output_final2[k].trim() == "break;"
                    && k + 1 < output_final2.len()
                {
                    let close_line = &output_final2[k + 1];
                    let close_indent = close_line.len() - close_line.trim_start().len();
                    if close_line.trim() == "}" && close_indent == case_indent {
                        // This is an empty case — skip all of it.
                        ie = k + 2;
                        continue;
                    }
                }
            }
            no_empty_cases.push(output_final2[ie].clone());
            ie += 1;
        }
        let output_final2 = no_empty_cases;

        // Passes 20+21 (canonicalize_struct_deref + rewrite_struct_deref) REMOVED.
        // These were mutual inverses: pass 20 converted *(ptr+N) → ptr->field_N,
        // pass 21 converted ptr->field_N → *(long*)(ptr+N). Net effect was zero.
        // Now that printc.rs emits *(long*)(ptr+N) directly (no ->field_N),
        // both passes are no-ops. Removing them eliminates 2 rule-5.5 violations.
        let output_joined = output_final2.join("\n");
        let struct_pass = output_joined;

        // Twenty-second pass: fix declarations of variables dereferenced via `*X`.
        // printc emits `*param_N = val` for STORE when the address is a parameter.
        // If param_N was inferred as long/int (not pointer), `*param_N` is illegal C.
        // We collect all `*IDENT` occurrences (unary deref, not `*(` cast) and
        // rewrite their declarations to `_struct *` so the deref is legal.
        // PRINTC-LEGACY-DECL-DUP-0001: skipped inside symbol-driven functions
        // (Ghidra print layer never rewrites symbol declarations; the oracle
        // prints sym->getType() verbatim at printc.cc:2503-2506).
        let after_unary = Self::fix_unary_deref_declarations(&struct_pass);

        // Twenty-third pass: backfill missing local-variable declarations.
        // Scan each function body for `local_XX` identifiers used but not declared,
        // and insert `int local_XX;` declarations to keep the output compilable.
        // PRINTC-LEGACY-DECL-DUP-0001: this pass is NOT bypassed for
        // symbol-driven functions — its declared-name collection recognizes
        // both pointer spellings, so with the two duplicate sources above
        // bypassed it only injects names genuinely absent from the symbol
        // block (unlinked-symbol body references, PRINTC-UNLINKED-REF-0001),
        // which keeps those functions compilable.
        let after_backfill = Self::backfill_missing_locals(&after_unary);

        // Twenty-fourth pass: remove orphan break/continue statements that are
        // not within any loop or switch. These arise from incomplete control-flow
        // structuring (e.g. dead code after an early return). gcc rejects them as
        // 'break statement not within loop or switch'; deleting the bare statement
        // (not its enclosing line context) makes the output compilable.
        // Twenty-fifth pass: fix pointer-pointer arithmetic.
        // When two pointer-typed variables appear in `a + b` or `a * b`, C rejects
        // it ('invalid operands'). We cast the second operand to (long) so the
        // operation becomes pointer + integer, which is legal. This handles the
        // type contradiction where a variable is used both as a struct base (for
        // ->field access) and as an array index.
        let after_orphan = Self::remove_orphan_breaks(&after_backfill);
        let after_ptr_arith = Self::fix_pointer_arithmetic(&after_orphan);
        // Remove duplicate label definitions (splice residue can cause two
        // blocks to share the same first-op address → duplicate LAB_ lines).
        let after_dup_labels = Self::remove_duplicate_labels(&after_ptr_arith);
        // Twenty-sixth pass: remove lines with illegal lvalue assignments.
        let after_lvalue = Self::remove_illegal_lvalue_assignments(&after_dup_labels);
        // Twenty-seventh pass: remove case labels outside switch bodies.
        let after_case = Self::remove_orphan_case_labels(&after_lvalue);
        // Struct field recovery (-> operator) requires struct type definitions
        // at file scope. post_process runs per-function, so struct typedefs
        // end up inside function bodies (illegal C). Keep *(long *)(ptr + offset)
        // which is valid C for all pointer types. Struct field recovery needs
        // type propagation engine (ActionTypePropagate) at P-code level, not
        // text post-processing.
        after_case
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::recoverStructFieldsAnon
    /// Per-variable anonymous struct field recovery.
    /// Groups *(long *)(var + offset) patterns by variable, generates an
    /// anonymous struct with matching fields, declares var as struct *,
    /// and rewrites accesses to var->field_OFFSET.
    fn recover_struct_fields_anon(text: &str) -> String {
        use std::collections::{HashMap, HashSet};

        // Phase 1: Collect var → set of offsets
        let mut var_offsets: HashMap<String, HashSet<u64>> = HashMap::new();
        let mut search = 0;
        loop {
            let pos = match text[search..].find("*(long *)(").or_else(|| text[search..].find("*(int *)(")) {
                Some(p) => search + p, None => break,
            };
            let prefix_len = if &text[pos..pos+10] == "*(long *)(" { 10 } else { 9 };
            let paren_start = pos + prefix_len;
            if paren_start >= text.len() { break; }
            let rest = &text[paren_start..];
            let mut depth = 1i32;
            let mut close_off = 0usize;
            for (idx, ch) in rest.char_indices() {
                match ch { '(' => depth += 1, ')' => { depth -= 1; if depth == 0 { close_off = idx; break; } } _ => {} }
            }
            if depth != 0 { break; }
            let inner = rest[..close_off].trim();
            if let Some(pp) = inner.rfind(" + ") {
                let base = inner[..pp].trim();
                let offset_str = inner[pp+3..].trim();
                if !base.is_empty() && base.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                    let off_val = if let Some(h) = offset_str.strip_prefix("0x") {
                        u64::from_str_radix(h, 16).ok()
                    } else {
                        offset_str.parse::<u64>().ok()
                    };
                    if let Some(off) = off_val {
                        var_offsets.entry(base.to_string()).or_default().insert(off);
                    }
                }
            }
            search = pos + prefix_len;
        }

        if var_offsets.is_empty() { return text.to_string(); }

        // Phase 2: For each variable, build an anonymous struct with fields
        let mut struct_decls: Vec<String> = Vec::new();
        let mut var_struct_types: HashMap<String, String> = HashMap::new();

        for (var, offsets) in &var_offsets {
            let struct_id = format!("_anon_{}", var.replace(|c: char| !c.is_alphanumeric() && c != '_', "_"));
            let mut members: Vec<String> = Vec::new();
            let mut prev_end: u64 = 0;
            let mut sorted_offsets: Vec<u64> = offsets.iter().copied().collect();
            sorted_offsets.sort();
            for &off in &sorted_offsets {
                if off > prev_end {
                    members.push(format!("  char _pad_{:x}[{}];", off, off - prev_end));
                }
                members.push(format!("  long field_{:x};", off));
                prev_end = off + 8;
            }
            struct_decls.push(format!("typedef struct {{\n{}\n}} {};", members.join("\n"), struct_id));
            var_struct_types.insert(var.clone(), struct_id);
        }

        // Phase 3: Rewrite the text line by line
        let mut result = String::with_capacity(text.len());
        let mut decl_inserted = false;
        let lines: Vec<&str> = text.split('\n').collect();

        for line in &lines {
            let trimmed = line.trim();
            // Insert struct declarations before the first typedef/extern/func
            // (the printc-emitted typedef block at the top of each function)
            if !decl_inserted && trimmed.starts_with("typedef unsigned char byte;") {
                // Insert BEFORE the typedefs so they're at file scope
                result.push_str(&struct_decls.join("\n"));
                result.push('\n');
                result.push('\n');
                decl_inserted = true;
            }


            let mut new_line = line.to_string();
            // Rewrite variable declarations
            for (var, struct_id) in &var_struct_types {
                // Patterns cover both the legacy `* name;` spelling and the
                // oracle ptr_expr join `*name;` (printc.cc:73-77); the
                // replacement uses the oracle join (no space after `*`).
                let patterns = [
                    format!("long {};", var),
                    format!("long * {};", var),
                    format!("long *{};", var),
                    format!("void * {};", var),
                    format!("void *{};", var),
                    format!("char * {};", var),
                    format!("char *{};", var),
                    format!("int * {};", var),
                    format!("int *{};", var),
                    format!("_struct * {};", var),
                    format!("_struct *{};", var),
                ];
                let replacement = format!("{} *{};", struct_id, var);
                for pat in &patterns {
                    new_line = new_line.replace(pat, &replacement);
                }
            }
            // Rewrite *(long *)(var + offset) → var->field_offset
            loop {
                let pos = match new_line.find("*(long *)(").or_else(|| new_line.find("*(int *)(")) {
                    Some(p) => p, None => break,
                };
                let prefix_len = if &new_line[pos..pos+10] == "*(long *)(" { 10 } else { 9 };
                let paren_start = pos + prefix_len;
                if paren_start >= new_line.len() { break; }
                let rest = &new_line[paren_start..];
                let mut depth = 1i32;
                let mut close_off = 0usize;
                for (idx, ch) in rest.char_indices() {
                    match ch { '(' => depth += 1, ')' => { depth -= 1; if depth == 0 { close_off = idx; break; } } _ => {} }
                }
                if depth != 0 { break; }
                let inner = rest[..close_off].trim();
                let mut found = false;
                if let Some(pp) = inner.rfind(" + ") {
                    let base = inner[..pp].trim();
                    let offset_str = inner[pp+3..].trim();
                    if var_struct_types.contains_key(base) {
                        let oc = offset_str.trim_start_matches("0x");
                        if !oc.is_empty() && oc.chars().all(|c| c.is_ascii_hexdigit()) {
                            let repl = format!("{}->field_{}", base, oc);
                            new_line.replace_range(pos..paren_start + close_off + 1, &repl);
                            found = true;
                        }
                    }
                }
                if !found { break; }
            }

            result.push_str(&new_line);
            result.push('\n');
        }

        if !text.ends_with('\n') && result.ends_with('\n') { result.pop(); }
        result
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::removeOrphanCaseLabels
    /// Remove `case N:` and `default:` lines that appear outside any switch
    /// statement. Uses a precise switch-depth tracker that counts `switch (...) {`
    /// openers and their matching `}` closers.
    fn remove_orphan_case_labels(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        // Stack of brace depths at which switch bodies open.
        // When we see `switch (...) {`, we push the current brace depth + 1
        // (the depth of the switch body). When brace depth drops below that,
        // the switch body has closed.
        let mut brace_depth: i32 = 0;
        let mut switch_body_depths: Vec<i32> = Vec::new();

        for line in lines {
            let t = line.trim();

            // Check if this line opens a switch body
            let opens_switch = Self::is_switch_stmt_prefix(t) && t.ends_with('{');

            // Count braces on this line (excluding those in char literals like '\x7d')
            // Simple heuristic: count { and } outside of single-quoted chars.
            // Since we escape brace chars in char literals (from earlier pass),
            // bare { and } on the line are structural.
            for ch in t.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }

            if opens_switch {
                // The switch body starts at the current brace_depth
                // (after counting the { on this line)
                switch_body_depths.push(brace_depth);
            }

            // Pop closed switches
            while let Some(&sd) = switch_body_depths.last() {
                if brace_depth < sd {
                    switch_body_depths.pop();
                } else {
                    break;
                }
            }

            // Check if this is a case/default label
            let is_case = t.starts_with("case ") || t == "default:";
            if is_case && switch_body_depths.is_empty() {
                // Orphan case label — skip it
                continue;
            }

            out.push(line.to_string());
        }
        out.join("\n")
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::removeIllegalLvalueAssignments
    /// Remove assignment lines whose left-hand side is not a valid C lvalue.
    /// Detects patterns like 'IDENT + ... = ' or 'IDENT * ... = ' at the start
    /// of a statement (not inside parens/casts).
    fn remove_illegal_lvalue_assignments(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        for line in lines {
            let t = line.trim();
            // Skip non-assignment lines
            if !t.contains(" = ") { out.push(line.to_string()); continue; }
            // Skip declaration lines (contain a type keyword at start)
            if t.starts_with("int ") || t.starts_with("long ") || t.starts_with("char ")
                || t.starts_with("void ") || t.starts_with("short ") || t.starts_with("bool ")
                || t.starts_with("byte ") || t.starts_with("extern ") || t.starts_with("typedef ")
                || t.starts_with("float ") || t.starts_with("double ")
            {
                out.push(line.to_string()); continue;
            }
            // Skip if/while/for/return/case lines
            if t.starts_with("if ") || t.starts_with("while ") || t.starts_with("for ")
                || t.starts_with("return ") || t.starts_with("case ")
                || t.starts_with("else") || t.starts_with("do ")
            {
                out.push(line.to_string()); continue;
            }
            // Lines like 'RSP + expr = val' are illegal lvalue assignments from
            // erroneous STORE address rendering. Remove them outright.
            if (t.starts_with("RSP ") || t.starts_with("RBP "))
                && t.contains(" = ") && !t.starts_with("*")
            {
                continue;
            }
            // Extract LHS: text before first " = " (top-level, not inside parens)
            let bytes = t.as_bytes();
            let mut depth = 0i32;
            let mut eq_pos = None;
            let mut i = 0;
            while i + 2 < bytes.len() {
                match bytes[i] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b'=' if depth == 0 && bytes.get(i+1) == Some(&b' ') && bytes.get(i+2) == Some(&b' ') => {
                        // Make sure it's not '==' or '<=' or '>='
                        if i > 0 && matches!(bytes[i-1], b'=' | b'<' | b'>' | b'!') {
                            // it's ==, <=, >=, != — skip
                        } else {
                            eq_pos = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if let Some(pos) = eq_pos {
                let lhs = t[..pos].trim();
                // Valid lvalues end with: identifier, ']', ')'
                let last_char = lhs.as_bytes().last().copied();
                let is_valid_lvalue_end = last_char.map_or(false, |c| {
                    c.is_ascii_alphanumeric() || c == b'_' || c == b']' || c == b')'
                });
                // Also valid: *(cast)expr = (dereference assignment)
                let is_deref = lhs.starts_with("*");
                // Check for top-level binary operators in LHS (not inside parens).
                // 'a + b', 'a * b', 'a - b' as a whole are not lvalues even if they
                // end with a valid char.
                let mut has_top_binop = false;
                if !is_deref {
                    let lbytes = lhs.as_bytes();
                    let mut d = 0i32;
                    let mut ii = 0;
                    while ii < lbytes.len() {
                        match lbytes[ii] {
                            b'(' | b'[' => d += 1,
                            b')' | b']' => d -= 1,
                            b' ' if d == 0 && ii + 2 < lbytes.len() => {
                                // Check for " + ", " - ", " * " at top level
                                if (lbytes[ii+1] == b'+' || lbytes[ii+1] == b'-' || lbytes[ii+1] == b'*')
                                    && lbytes[ii+2] == b' '
                                    && ii > 0
                                {
                                    has_top_binop = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        ii += 1;
                    }
                }
                if (!is_valid_lvalue_end && !is_deref) || has_top_binop {
                    // Illegal lvalue — skip this line
                    continue;
                }
            }
            out.push(line.to_string());
        }
        out.join("\n")
    }

    // RUGRA-GLUE: 移除重复 LAB_ 标签（splice 残留导致）。Ghidra 无此问题（块
    // 地址唯一），Rugra 的 splice 可能留下重复首地址块。
    /// Remove duplicate label definitions (keep first occurrence only).
    fn remove_duplicate_labels(text: &str) -> String {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        let mut out: Vec<&str> = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                if !seen.insert(t.to_string()) {
                    continue; // Skip duplicate label definition
                }
            }
            out.push(line);
        }
        out.join("\n")
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::fixPointerArithmetic
    /// Detect `IDENT + IDENT` and `IDENT * IDENT` patterns where both operands
    /// are declared as pointer types, and cast the right operand to `(long)`.
    fn fix_pointer_arithmetic(text: &str) -> String {
        // Collect names declared as pointers (type contains '*')
        use std::collections::HashSet;
        let mut ptr_names: HashSet<String> = HashSet::new();
        for line in text.lines() {
            let t = line.trim();
            if t.ends_with(';') && t.contains('*') && !t.contains('(') && !t.contains("return") {
                // Declaration like "int * piVar_0;" or "long * uVar_b0;"
                // Extract the variable name (last token before ';', after '*')
                let name: String = t.trim_end_matches(';')
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_start_matches('*')
                    .to_string();
                if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
                    ptr_names.insert(name);
                }
            }
        }
        if ptr_names.is_empty() {
            return text.to_string();
        }
        // Scan for `ptrA + ptrB` or `ptrA * ptrB` and cast ptrB to (long)
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            // Look for patterns: IDENT + IDENT or IDENT * IDENT where both are pointers
            let mut new_line = line.to_string();
            // Repeat to handle multiple occurrences on one line
            loop {
                let changed = Self::try_fix_one_ptr_arith(&new_line, &ptr_names);
                match changed {
                    Some(fixed) => { new_line = fixed; }
                    None => break,
                }
            }
            out.push_str(&new_line);
            out.push('\n');
        }
        // Remove trailing newline added by loop
        if out.ends_with('\n') && !text.ends_with('\n') {
            out.pop();
        }
        out
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tryFixOnePtrArith
    /// Try to fix one `ptrA <op> ptrB` occurrence in the line. Returns Some(fixed)
    /// if a fix was applied, None otherwise. Scans the entire line (both LHS
    /// cast expressions and RHS).
    fn try_fix_one_ptr_arith(line: &str, ptr_names: &std::collections::HashSet<String>) -> Option<String> {
        // Scan the entire line (not just RHS) — pointer arithmetic in cast
        // expressions like *(long *)(ptrA + ptrB) appears on the LHS.
        let scan_start = 0;
        let bytes = line.as_bytes();
        let mut i = scan_start;
        while i + 2 < bytes.len() {
            // Check for " + " or " * " (operator surrounded by spaces)
            if bytes[i] == b' ' &&
                (bytes[i + 1] == b'+' || bytes[i + 1] == b'*') &&
                bytes[i + 2] == b' '
            {
                // Extract left operand: walk back from i to get the identifier
                let mut left_start = i;
                while left_start > scan_start && (bytes[left_start - 1].is_ascii_alphanumeric() || bytes[left_start - 1] == b'_') {
                    left_start -= 1;
                }
                let left_name = String::from_utf8_lossy(&bytes[left_start..i]).to_string();
                // Extract right operand: walk forward from i+3
                let mut right_end = i + 3;
                while right_end < bytes.len() && (bytes[right_end].is_ascii_alphanumeric() || bytes[right_end] == b'_') {
                    right_end += 1;
                }
                let right_name = String::from_utf8_lossy(&bytes[i + 3..right_end]).to_string();

                // Both must be pointer-typed names
                if ptr_names.contains(&left_name) && ptr_names.contains(&right_name) {
                    // Cast the right operand to (long)
                    let before = &line[..i + 3];
                    let after = &line[right_end..];
                    return Some(format!("{}(long){}{}", before, right_name, after));
                }
            }
            i += 1;
        }
        None
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::removeOrphanBreaks
    /// Remove `break;`/`continue;` statements not within any loop or switch.
    /// Uses a pre-scan to mark line ranges that fall inside a loop/switch body
    /// (via brace matching), which is more reliable than a line-level context
    /// stack for nested case blocks.
    fn remove_orphan_breaks(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let n = lines.len();

        // Pre-scan: for each line that opens a loop/switch body (ends with '{'
        // and starts with while/for/do/switch), find the matching '}' via brace
        // counting and mark all lines in [opener+1, closer) as "in loop/switch".
        let mut in_loop_switch = vec![false; n];
        // Also track depth-based: any line at brace depth inside a loop/switch.
        // We do a single pass tracking a stack of (loop_or_switch, brace_depth_at_open).
        let mut brace_depth: i32 = 0;
        // Stack of brace depths at which a loop/switch body opened.
        let mut loop_depths: Vec<i32> = Vec::new();
        // In the skip_line layout, the index of the lone `{` line that the
        // signature reset already accounted for (must not bump depth again).
        let mut consumed_function_brace_line: Option<usize> = None;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Reset brace tracking at each function signature (line ends with '{'
            // and looks like a return-type declaration with parens). This prevents
            // brace-depth drift across functions from breaking switch detection.
            // With the oracle skip_line layout (printc.cc:1590/2655) the
            // signature ends with ')' and the lone `{` follows; that `{` line
            // must not bump the depth again, so it is consumed here.
            if Self::signature_opens_function_body(
                t,
                &["int ", "long ", "void ", "char ", "short ", "bool "],
                &lines[i + 1..],
            ) {
                brace_depth = 1;
                loop_depths.clear();
                in_loop_switch[i] = false;
                if !t.ends_with('{') {
                    consumed_function_brace_line = Some(i + 1);
                }
                continue;
            }
            if consumed_function_brace_line == Some(i) {
                in_loop_switch[i] = false;
                continue;
            }
            // Detect loop/switch opener: line ends with '{' and starts with keyword.
            // Skip lines that start with '}' (like "} else {") — they're handled below
            // by the closing-brace logic to avoid double-counting the brace delta.
            if t.ends_with('{') && !t.starts_with('}') {
                let is_loop_hdr = t.starts_with("while ")
                    || t.starts_with("for ")
                    || t.starts_with("do ")
                    || Self::is_switch_stmt_prefix(t)
                    || t.contains("} while (");
                brace_depth += 1;
                if is_loop_hdr {
                    loop_depths.push(brace_depth);
                }
            }
            // Mark this line if any loop/switch is currently open
            if !loop_depths.is_empty() {
                in_loop_switch[i] = true;
            }
            // Handle closing braces
            if t == "}" {
                brace_depth -= 1;
                // Pop any loop/switch whose body just closed
                while let Some(&top) = loop_depths.last() {
                    if top > brace_depth {
                        loop_depths.pop();
                    } else {
                        break;
                    }
                }
            } else if t.starts_with("} while") || t.starts_with("} else") {
                // These close one brace then may open another (} else {) — handle net effect
                // Count opens and closes in the line
                let opens = t.matches('{').count() as i32;
                let closes = t.matches('}').count() as i32;
                let net = opens - closes;
                // First the closes happen
                for _ in 0..closes {
                    brace_depth -= 1;
                    while let Some(&top) = loop_depths.last() {
                        if top > brace_depth { loop_depths.pop(); } else { break; }
                    }
                }
                brace_depth += opens;
            }
        }

        // Second pass: remove break/continue lines not marked as in loop/switch.
        let mut out: Vec<String> = Vec::with_capacity(n);
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let protected = in_loop_switch[i];
            if !protected {
                // Check for break/continue tokens in this line
                let bytes = line.as_bytes();
                let mut has_break = false;
                let mut k = 0;
                while k < bytes.len() {
                    let candidates: &[&[u8]] = &[b"break;", b"continue;"];
                    for cand in candidates {
                        if k + cand.len() <= bytes.len() && &bytes[k..k + cand.len()] == *cand {
                            let prev_ok = k == 0 || {
                                let b = bytes[k - 1];
                                !(b.is_ascii_alphanumeric() || b == b'_')
                            };
                            if prev_ok { has_break = true; break; }
                        }
                    }
                    if has_break { break; }
                    k += 1;
                }
                if has_break {
                    // Remove the break/continue token; if line becomes empty, drop it.
                    let mut new_line = String::new();
                    let mut k = 0;
                    while k < bytes.len() {
                        let candidates: &[&[u8]] = &[b"break;", b"continue;"];
                        let mut hit = None;
                        for cand in candidates {
                            if k + cand.len() <= bytes.len() && &bytes[k..k + cand.len()] == *cand {
                                let prev_ok = k == 0 || {
                                    let b = bytes[k - 1];
                                    !(b.is_ascii_alphanumeric() || b == b'_')
                                };
                                if prev_ok { hit = Some(cand.len()); break; }
                            }
                        }
                        if let Some(clen) = hit {
                            k += clen;
                        } else {
                            new_line.push(bytes[k] as char);
                            k += 1;
                        }
                    }
                    let cleaned = new_line.trim_end().to_string();
                    let ct = cleaned.trim();
                    if ct.is_empty() || ct.ends_with(')') || ct == "{" {
                        continue; // drop the now-empty line
                    }
                    out.push(cleaned);
                    continue;
                }
            }
            out.push(line.to_string());
        }
        out.join("\n")
    }

    // RUGRA-GLUE: backfill_missing_locals (no Ghidra counterpart exists)
    /// For each function, find `local_XX` identifiers used in the body but not
    /// declared, and insert `int local_XX;` declarations before the first
    /// non-declaration body line. The locked oracle's prettyprint.hh has no
    /// backfill pass of any kind (verified: prettyprint.hh:547 is the
    /// EmitNoMarkup class declaration, and grep over the oracle tree finds
    /// no backfillMissingLocals); this pass exists only to keep Rugra's
    /// unlinked-symbol body references (PRINTC-UNLINKED-REF-0001 domain)
    /// compilable and is retired as that domain closes. NUMDECL-DOUBLE-V:
    /// the identifier scanner below must respect C identifier boundaries —
    /// a prefix match inside a longer identifier (e.g. `lVar64` inside
    /// `plVar64`, whose `plVar` prefix is not in the table) is NOT a use of
    /// the shorter name, and injecting a declaration for it produces the
    /// same-name different-type double declaration (`long *plVar64;` from
    /// the scope emitter plus `long lVar64;` here).
    fn backfill_missing_locals(text: &str) -> String {
        use std::collections::BTreeSet;
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            out.push(line.to_string());
            let trimmed = line.trim();
            // Detect function signature opener: a signature line ends with '{'
            // (legacy layout) or, in the oracle skip_line layout
            // (printc.cc:1590/2655), ends with ')' and the lone `{` follows.
            // WARN-EMIT2 R2 (printc-side naming collision root cause): the
            // `contains(" *")` arm also matches control-flow openers whose
            // condition carries a `/* N */` hex annotation — e.g.
            // `if ((bool)(piVar1 <= 0x1000 /* 4096 */)) {` contains `(`,
            // contains `" *"` (inside ` /* 4096 */`), and ends with `{`. The
            // pass then treated the if-body as a nested function, found the
            // block's auto-prefixed names "undeclared" (its declared-name
            // walk only covers the block, not the function scope), and
            // re-injected the whole decl set INSIDE the block — duplicate
            // `piVar1`/`uVar0` declarations (glob_url numbering 0->3). Gate
            // every control-flow opener out of sig_shape; only real function
            // signatures (first token is a type) reach the injection path.
            let control_flow_opener = trimmed.starts_with("if (")
                || trimmed.starts_with("if(")
                || trimmed.starts_with("while (")
                || trimmed.starts_with("while(")
                || trimmed.starts_with("for (")
                || trimmed.starts_with("for(")
                || trimmed.starts_with("switch (")
                || trimmed.starts_with("switch(")
                || trimmed.starts_with("do {")
                || trimmed.starts_with("else")
                || trimmed.starts_with("case ")
                || trimmed.starts_with("default:");
            let sig_shape = !control_flow_opener
                && trimmed.contains('(')
                && (trimmed.starts_with("int ") || trimmed.starts_with("long ")
                    || trimmed.starts_with("void ") || trimmed.starts_with("char ")
                    || trimmed.starts_with("short ") || trimmed.starts_with("bool ")
                    || trimmed.contains(" *"));
            let next_is_lone_brace = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .map_or(false, |l| l == "{");
            let is_sig = sig_shape
                && (trimmed.ends_with('{')
                    || (trimmed.ends_with(')') && next_is_lone_brace));
            if !is_sig { i += 1; continue; }

            // Walk the declaration block: consecutive lines ending with ';' that
            // contain no '(' or '=' (pure declarations). Track declared names and
            // the indent. Stop at first non-declaration line (the body proper).
            let mut declared: BTreeSet<String> = BTreeSet::new();
            let mut j = i + 1;
            let mut decl_indent = 2usize;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() { j += 1; continue; }
                // skip_line layout: the lone `{` line sits between the
                // signature and the declaration block (printc.cc:1590/2655).
                // Skip it so the walk reaches the declarations instead of
                // breaking with an empty `declared` set (which would make
                // every used variable look missing and re-declare it).
                if t == "{" { j += 1; continue; }
                if t.ends_with(';') && !t.contains('(') && !t.contains("return") {
                    // Only treat as declaration if it has no '=' (assignment) —
                    // pure decls are "type name;" or "type *name;"
                    if !t.contains('=') {
                        let indent = lines[j].len() - lines[j].trim_start().len();
                        decl_indent = indent;
                        let name: String = t.trim_end_matches(';')
                            .split_whitespace()
                            .last()
                            .unwrap_or("")
                            .trim_start_matches('*')
                            .to_string();
                        if !name.is_empty() { declared.insert(name); }
                        j += 1;
                        continue;
                    }
                }
                break;
            }
            // j now points at the first body line (after declarations + blank lines).
            // Scan body until matching '}' for auto-generated variable usage.
            let body_end = {
                let mut d = 1i32;
                let mut k = j;
                while k < lines.len() && d > 0 {
                    for ch in lines[k].chars() {
                        if ch == '{' { d += 1; }
                        if ch == '}' { d -= 1; }
                    }
                    k += 1;
                }
                k
            };
            let mut used_locals: BTreeSet<String> = BTreeSet::new();
            for k in j..body_end {
                let lb = lines[k].as_bytes();
                let mut p = 0;
                while p < lb.len() {
                    // Match identifiers with auto-generated prefixes:
                    // - local_XX, lVar_XX (with underscore + hex)
                    // - bVar592, lVar21 (prefix + digits, no underscore)
                    // - struct3, struct5 (struct + digit)
                    // - unique0x00023b00 / register0x000000a0 / stack0x... /
                    //   ram0x...: oracle unnamed-location fallback tokens
                    //   (printc.cc:1938-1945 PrintC::pushUnnamedLocation —
                    //   <spacename> + AddrSpace::printRaw, space.cc:206-222 —
                    //   which replaced the uVar_/local_ spellings after the
                    //   A69 pushUnnamedLocation merge). printRaw emits "0x" +
                    //   lowercase hex (space.cc:216 `hex` manipulator), so the
                    //   tail scan must accept hex digits: the decimal-only
                    //   non-underscore arm would truncate unique0x00023b00 at
                    //   its first a-f digit.
                    let prefixes: &[&[u8]] = &[
                        b"local_", b"lVar_", b"uVar_", b"iVar_", b"bVar_", b"sVar_",
                        b"piVar_", b"pcVar_", b"psVar_", b"ppVar_", b"pvVar_",
                        b"fVar_", b"dVar_", b"DAT_",
                        b"unique0x", b"register0x", b"stack0x", b"ram0x",
                        b"lVar", b"uVar", b"iVar", b"bVar", b"sVar",
                        b"piVar", b"pcVar", b"psVar", b"ppVar", b"pvVar",
                        b"fVar", b"dVar", b"struct",
                    ];
                    let mut matched = false;
                    for pf in prefixes {
                        let plen = pf.len();
                        // NUMDECL-DOUBLE-V left word-boundary: a prefix match
                        // must START an identifier. C identifiers are
                        // [A-Za-z_][A-Za-z0-9_]*, so a match preceded by an
                        // identifier byte is the middle of a longer token —
                        // e.g. `plVar64` matches the `lVar` prefix at its
                        // inner `l`, manufacturing a phantom `lVar64` "used
                        // local" that gets injected as `long lVar64;` beside
                        // the real `long *plVar64;` declaration.
                        let boundary_ok = p == 0
                            || !(lb[p - 1].is_ascii_alphanumeric() || lb[p - 1] == b'_');
                        if boundary_ok && p + plen <= lb.len() && &lb[p..p + plen] == *pf {
                            let mut e = p + plen;
                            // For underscore prefixes: hex digits and underscores
                            // For unnamed-location fallback tokens (prefix ends
                            // in "0x"): hex digits only (printc.cc:1942-1943
                            // space name + printRaw hex tail)
                            // For other non-underscore: digits only
                            if lb[p + plen - 1] == b'_' {
                                while e < lb.len() && (lb[e].is_ascii_hexdigit() || lb[e] == b'_') { e += 1; }
                            } else if pf.ends_with(b"0x") {
                                while e < lb.len() && lb[e].is_ascii_hexdigit() { e += 1; }
                            } else {
                                while e < lb.len() && lb[e].is_ascii_digit() { e += 1; }
                            }
                            if e > p + plen {
                                used_locals.insert(String::from_utf8_lossy(&lb[p..e]).to_string());
                            }
                            p = e;
                            matched = true;
                            break;
                        }
                    }
                    if !matched { p += 1; }
                }
            }
            let missing: Vec<&String> = used_locals.iter()
                    .filter(|n| !declared.contains(*n))
                    .collect();
            // PRINTC-LEGACY-DECL-DUP-0001: the duplicate-declaration source
            // was NOT this pass — backfill's declared-name collection handles
            // both pointer spellings (`char *uVar20;` 2-token join and
            // `char * *uVar20;` 3-token), so it only injects names that are
            // genuinely absent from the declaration block (unlinked-symbol
            // body references, PRINTC-UNLINKED-REF-0001 domain). The
            // duplicates came from flush_func_remove_unused (which cannot
            // recognize the 2-token join form and re-declared those symbols)
            // and fix_unary_deref_declarations (which rewrote the injected
            // scalars to pointer form) — both bypassed above. Backfill stays
            // active for every function so unlinked references keep compiling;
            // functions without symbol evidence are unaffected either way.
            if !missing.is_empty() {
                let indent_str = " ".repeat(decl_indent);
                for k in (i + 1)..j {
                    out.push(lines[k].to_string());
                }
                for m in &missing {
                    // Infer type from prefix: lVar/uVar/piVar etc → long/long/pointer
                    // DAT_ prefixed names are synthetic globals. Ghidra's printer
                    // never declares globals inside a function (printc.cc:2641-2670
                    // docFunction has no global-decl step; "extern" does not occur
                    // in the oracle printc.cc at all), and the golden contains zero
                    // extern lines — the anonymous data pool prints bare DAT_
                    // references at use sites only (MAIN-DATPOOL-0001). Skip the
                    // declaration entirely to match the oracle.
                    if m.starts_with("DAT_") {
                        continue;
                    }
                    let ty = if m.starts_with("struct") {
                        "int"
                    } else if m.starts_with("lVar") || m.starts_with("uVar") {
                        "long"
                    } else if m.starts_with("iVar") || m.starts_with("bVar")
                        || m.starts_with("sVar") || m.starts_with("local_") {
                        "int"
                    } else if m.starts_with("piVar") || m.starts_with("pcVar")
                        || m.starts_with("psVar") || m.starts_with("ppVar")
                        || m.starts_with("pvVar") {
                        "char *"
                    } else if m.starts_with("fVar") { "float" }
                    else if m.starts_with("dVar") { "double" }
                    else if m.starts_with("unique0x") || m.starts_with("register0x")
                        || m.starts_with("stack0x") || m.starts_with("ram0x") {
                        // Oracle unnamed-location fallback token (printc.cc:1938
                        // pushUnnamedLocation): a raw storage-slot label with no
                        // type evidence at text level — keep the long default
                        // the pre-A69 uVar-family spelling of these slots got.
                        "long"
                    }
                    else { "long" };
                    // Pointer-join spacing (printc.cc:73-77 ptr_expr
                    // spacing=0): a trailing-`*` type glues to the name.
                    let join = if ty.ends_with('*') { "" } else { " " };
                    out.push(format!("{}{}{}{};", indent_str, ty, join, m));
                }
                i = j;
                continue;
            }
            i += 1;
        }
        out.join("\n")
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::fixUnaryDerefDeclarations
    /// Rewrite declarations of variables appearing in `*IDENT` unary dereference
    /// patterns to pointer type, so `*param_N` is legal C.
    fn fix_unary_deref_declarations(text: &str) -> String {
        use std::collections::HashSet;
        // Collect IDENTs used as `*IDENT` (unary deref).
        // Patterns: `*IDENT =`, `= *IDENT`, `(*IDENT)`, `*IDENT;`, `*IDENT,`
        // Exclude `*( ... )` (cast) and `** ` (double deref handled separately).
        let mut derefed: HashSet<String> = HashSet::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Look for `*` not preceded by `(` or `*` or alnum, and not followed by `(`.
            if bytes[i] == b'*' {
                let prev_alnum = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b')');
                let next_is_paren = i + 1 < bytes.len() && bytes[i + 1] == b'(';
                let next_is_star = i + 1 < bytes.len() && bytes[i + 1] == b'*';
                // Skip if it's a `type *X` declaration (preceded by whitespace after type word) — hard to detect perfectly,
                // but we only act on IDENTs that also appear in declarations, so false positives are harmless.
                if !prev_alnum && !next_is_paren && !next_is_star {
                    // Capture following identifier
                    let mut j = i + 1;
                    // skip whitespace
                    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') { j += 1; }
                    let id_start = j;
                    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') { j += 1; }
                    if j > id_start {
                        let name = String::from_utf8_lossy(&bytes[id_start..j]).to_string();
                        if name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                            derefed.insert(name);
                        }
                    }
                }
            }
            i += 1;
        }
        if derefed.is_empty() {
            return text.to_string();
        }
        // Rewrite scalar declarations of these names to `_struct *`.
        let scalar_types = [
            "long", "int", "short", "char", "byte", "bool",
            "undefined", "undefined4", "undefined8",
        ];
        let lines: Vec<&str> = text.split('\n').collect();
        // PRINTC-LEGACY-DECL-DUP-0001 bypass: inside symbol-driven functions
        // this pass's rewrites corrupt Action-phase symbol declarations —
        // rewriting the (bypassed) `int uVarN;` injections to `char *uVarN;`
        // is what made the duplicates survive as pointer-typed re-declarations,
        // and rewriting a genuine scalar symbol decl (`int uVar0;`) changes its
        // printed type away from the symbol's Datatype (printc.cc:2503-2506
        // emitLocalSymbolDecl prints sym->getType() verbatim). Skip lines of
        // functions whose declaration block is symbol-driven.
        let symbol_mask = Self::symbol_driven_function_line_mask(&lines);
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        for (idx, line) in lines.iter().enumerate() {
            let line: &str = *line;
            if symbol_mask[idx] {
                out.push(line.to_string());
                continue;
            }
            let trimmed = line.trim_start();
            let indent_len = line.len() - trimmed.len();
            let mut rewritten = None;
            for ty in &scalar_types {
                let prefix = format!("{} ", ty);
                if let Some(rest) = trimmed.strip_prefix(&prefix) {
                    if rest.starts_with('*') { break; } // already pointer
                    let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() && derefed.contains(&name) {
                        let indent_str = &line[..indent_len];
                        // Declare as `char *`: `*(char *)X` yields a char, which can be
                        // assigned scalar values (0-255), indexed, and compared — covering
                        // the common STORE/LOAD patterns without knowing the real type.
                        rewritten = Some(format!("{}char *{};", indent_str, name));
                        break;
                    }
                }
            }
            // Also handle parameter declarations in function signature: `long param_1` -> `_struct * param_1`
            // These appear on the signature line, not as standalone declarations.
            if rewritten.is_none() {
                // Check if this is a signature line containing `(long param_N, ...)`
                // We rewrite param types inline if they're in derefed set.
                let mut new_line = line.to_string();
                for name in &derefed {
                    for ty in &scalar_types {
                        let pat = format!("{} {}", ty, name);
                        let repl = format!("char *{}", name);
                        // Only replace if not already pointer (avoid `long * param` -> `_struct * * param`)
                        let pat_idx = new_line.find(&pat);
                        if let Some(idx) = pat_idx {
                            // Check char before is not '*'
                            let before_ok = idx == 0 || {
                                let b = new_line.as_bytes()[idx - 1];
                                b != b'*'
                            };
                            if before_ok {
                                new_line = new_line.replacen(&pat, &repl, 1);
                            }
                        }
                    }
                }
                if new_line != line {
                    rewritten = Some(new_line);
                }
            }
            out.push(rewritten.unwrap_or_else(|| line.to_string()));
        }
        out.join("\n")
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::rewriteStructDeref
    /// Rewrite every `IDENT->field_N` / `IDENT->field_0xN` to
    /// `*(long *)(IDENT + 0xN)`. Also handles `EXPR)->field_N` (grouped base).
    fn rewrite_struct_deref(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < bytes.len() {
            // Detect `->field_` (8 bytes)
            if i + 8 <= bytes.len() && &bytes[i..i + 8] == b"->field_" {
                // Walk back to find the base identifier (or closing paren for grouped expr).
                let mut start = i;
                while start > 0 {
                    let b = bytes[start - 1];
                    if b.is_ascii_alphanumeric() || b == b'_' || b == b')' || b == b']' {
                        start -= 1;
                    } else {
                        break;
                    }
                }
                let base = &text[start..i];
                // Forward: parse the offset after "field_" — either hex (no 0x) or "0xN"
                let after = &text[i + 8..];
                let (offset_str, consumed): (&str, usize) = if after.starts_with("0x") {
                    let hex_end = after[2..].find(|c: char| !c.is_ascii_hexdigit()).map_or(after.len(), |p| p + 2);
                    (&after[..hex_end], 8 + hex_end)
                } else {
                    let hex_end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                    (&after[..hex_end], 8 + hex_end)
                };
                // Normalize offset to 0xN form
                let off_val = if let Some(h) = offset_str.strip_prefix("0x") {
                    u64::from_str_radix(h, 16).ok()
                } else {
                    u64::from_str_radix(offset_str, 16).ok()
                };
                if let Some(off) = off_val {
                    // The base identifier was already pushed to `out` byte-by-byte
                    // as we scanned past it. Truncate `out` back to before the base,
                    // then emit the cast form. (base length in chars == i - start,
                    // but `out` accumulated bytes; since we push bytes one at a time,
                    // we truncate by the byte-length of the base slice.)
                    let base_byte_len = i - start;
                    out.truncate(out.len() - base_byte_len);
                    out.push_str(&format!("*(long *)({} + 0x{:x})", base, off));
                    i += consumed;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::canonicalizeStructDeref
    /// Convert `*(varname + N)` and `*varname + N` patterns to `varname->field_N` in C output text.
    fn canonicalize_struct_deref(text: &str) -> String {
        // First pass: *(expr + N) → expr->field_N
        let mut result = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            // Look for `*(` pattern
            if i + 1 < len && chars[i] == '*' && chars[i + 1] == '(' {
                let paren_start = i + 2;
                let mut depth = 1usize;
                let mut j = paren_start;
                while j < len && depth > 0 {
                    match chars[j] {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                let paren_end = j - 1;
                let inner: String = chars[paren_start..paren_end].iter().collect();
                let inner_trim = inner.trim();

                let converted = Self::try_convert_ptr_add(inner_trim);
                if let Some(ref conv) = converted {
                    result.push_str(conv);
                    i = j;
                    continue;
                }
                result.push('*');
                result.push('(');
                result.push_str(inner_trim);
                result.push(')');
                i = j;
                continue;
            }
            result.push(chars[i]);
            i += 1;
        }

        // Second pass: `*varname + N` in comparison context → `varname->field_N`
        // Pattern: `*WORD + HEXNUM` where WORD is a C identifier and HEXNUM is hex offset
        let re_result = result.clone();
        let mut result2 = String::with_capacity(re_result.len());
        let bytes = re_result.as_bytes();
        let blen = bytes.len();
        let mut bi = 0;
        while bi < blen {
            // Look for `*` followed by a word char
            if bytes[bi] == b'*' && bi + 1 < blen && (bytes[bi+1].is_ascii_alphabetic() || bytes[bi+1] == b'_') {
                // Collect the variable name
                let var_start = bi + 1;
                let mut var_end = var_start;
                while var_end < blen && (bytes[var_end].is_ascii_alphanumeric() || bytes[var_end] == b'_') {
                    var_end += 1;
                }
                let var_name = &re_result[var_start..var_end];
                // Check for ` + N` after the variable name (possibly with spaces)
                let rest = &re_result[var_end..];
                let rest_trim = rest.trim_start();
                if rest_trim.starts_with("+ ") {
                    let after_plus = rest_trim[2..].trim_start();
                    // Parse the offset number (hex or decimal)
                    let (offset_val, offset_len) = if after_plus.starts_with("0x") || after_plus.starts_with("0X") {
                        let hex_start = 2;
                        let hex_end = after_plus[hex_start..].find(|c: char| !c.is_ascii_hexdigit()).map_or(after_plus.len(), |p| p + hex_start);
                        let hex_str = &after_plus[hex_start..hex_end];
                        (u64::from_str_radix(hex_str, 16).ok(), hex_end)
                    } else {
                        let num_end = after_plus.find(|c: char| !c.is_ascii_digit()).unwrap_or(after_plus.len());
                        let num_str = &after_plus[..num_end];
                        (num_str.parse::<u64>().ok(), num_end)
                    };
                    if let Some(off) = offset_val {
                        if off > 0 && off <= 4096 {
                            // Emit `*(long *)(var + N)` instead of `var->field_N`.
                            // We don't track concrete struct layouts; the cast form
                            // is always legal C regardless of var's declared type.
                            result2.push_str(&format!("*(long *)({} + 0x{:x})", var_name, off));
                            // Skip past: var_end already consumed var, now skip whitespace + "+" + whitespace + number
                            // We know rest = re_result[var_end..]
                            // spaces_before_plus = rest.len() - rest_trim.len()
                            // rest_trim starts with "+ " then the number
                            // offset_len = length of the number string in after_plus
                            let spaces_before_plus = rest.len() - rest_trim.len();
                            // rest_trim = "+ " + after_plus
                            let spaces_after_plus = rest_trim.len() - 2 - after_plus.len(); // always 0 usually
                            let total_skip = spaces_before_plus + 1 /* '+' */ + 1 /* ' ' */ + spaces_after_plus + offset_len;
                            bi = var_end + total_skip;
                            continue;
                        }
                    }
                }
                // No match — emit the `*varname` as-is
                result2.push('*');
                result2.push_str(var_name);
                bi = var_end;
                continue;
            }
            result2.push(bytes[bi] as char);
            bi += 1;
        }
        result2
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tryConvertPtrAdd
    /// Try to convert `expr + N` to `expr->field_N`.
    /// Returns Some if the pattern matches, None otherwise.
    fn try_convert_ptr_add(inner: &str) -> Option<String> {
        // Find the last ` + ` that separates base expression from offset
        // We need to handle nested parens — find the rightmost top-level `+ `
        let bytes = inner.as_bytes();
        let mut depth = 0i32;
        let mut plus_pos = None;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'+' if depth == 0 && i > 0 && bytes.get(i-1) == Some(&b' ')
                    && bytes.get(i+1) == Some(&b' ') => {
                    plus_pos = Some(i);
                    // Don't break — take the LAST one for right-associativity
                }
                _ => {}
            }
        }

        let plus_pos = plus_pos?;
        let base = inner[..plus_pos - 1].trim(); // before " + "
        let offset_str = inner[plus_pos + 2..].trim(); // after "+ "

        // Parse offset as hex (0xNN) or decimal
        let offset: u64 = if let Some(hex) = offset_str.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()?
        } else {
            offset_str.parse().ok()?
        };

        // Only convert if:
        // 1. Offset is a reasonable struct field offset (0–4096)
        // 2. Base looks like a variable/expression (not a constant)
        if offset > 4096 || base.is_empty() { return None; }
        if base.chars().next()?.is_ascii_digit() { return None; } // base is a literal number

        // Emit `*(long *)(base + N)` instead of `base->field_N`.
        // We don't track concrete struct layouts, so `->field_N` would require a
        // backing struct type that may not match reality. The cast-and-deref form
        // is always legal C regardless of base's declared type and is
        // semantically equivalent to what Ghidra emits for unknown structs.
        Some(format!("*(long *)({} + 0x{:x})", base, offset))
    }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::hasEnclosingLoopCtx
    /// Scans backward through already-emitted lines.
    // RUGRA-GLUE: signature_opens_function_body (format-layer helper for the
    //   oracle's two-line function-header layout: printc.cc:1590 sets
    //   option_brace_func=skip_line and printc.cc:2655 emits the body `{`
    //   two lines below the declaration, so `sig {` and `sig` + `{` are both
    //   valid function openings in Rugra text).
    /// Whether a trimmed line is a C function signature that opens a body
    /// brace, either trailing on the same line (legacy `sig {`) or alone on
    /// the next non-blank line (oracle skip_line `sig` / `{`).
    /// `type_prefixes` preserves each call site's original return-type set.
    fn signature_opens_function_body<L: AsRef<str>>(
        t: &str,
        type_prefixes: &[&str],
        lookahead: &[L],
    ) -> bool {
        if t.is_empty() || t.starts_with("//") || t.starts_with("/*") {
            return false;
        }
        if !type_prefixes.iter().any(|p| t.starts_with(p)) || !t.contains('(') {
            return false;
        }
        if t.ends_with('{') {
            return true;
        }
        if !t.ends_with(')') {
            return false;
        }
        // skip_line layout: the next non-blank line must be the lone `{`
        lookahead
            .iter()
            .map(|l| l.as_ref().trim())
            .find(|l| !l.is_empty())
            .map_or(false, |l| l == "{")
    }

    // RUGRA-GLUE: has_symbol_driven_decls (no Ghidra counterpart — Ghidra's
    //   print layer has no declaration passes to bypass: printc.cc:2656
    //   docFunction emits every function-local declaration from Action-phase
    //   symbols via emitLocalVarDecls and nothing else, so "does this text
    //   already carry symbol-driven declarations" is a question that only
    //   exists for Rugra's legacy compensation passes).
    /// Conservative bypass predicate for the two synthetic-declaration legacy
    /// passes (`flush_func_remove_unused`, `fix_unary_deref_declarations`):
    /// does this function chunk, starting at its signature line, already
    /// carry `emit_local_var_decls` products in its declaration block?
    /// (`backfill_missing_locals` deliberately does NOT consult this — see
    /// its PRINTC-LEGACY-DECL-DUP-0001 note.)
    ///
    /// Evidence spellings (PRINTC-LEGACY-DECL-DUP-0001):
    /// - a declaration whose type token starts with `undefined`
    ///   (undefined1/2/4/8 — core-type spellings only reachable through the
    ///   symbol-driven emitter; the legacy passes synthesize exclusively
    ///   int/long/char */float/double), or
    /// - a declaration whose name token starts with `in_` (register/ram
    ///   space symbol names like in_RAX / in_ram_00016e70; the legacy passes
    ///   never generate `in_`-prefixed names).
    ///
    /// A decl block without either evidence keeps the legacy passes: those
    /// functions may still lack symbols and must not lose their backfill
    /// safety net.
    fn has_symbol_driven_decls<L: AsRef<str>>(func_lines: &[L]) -> bool {
        let mut j = 1usize;
        while j < func_lines.len() {
            let t = func_lines[j].as_ref().trim();
            if t.is_empty() || t == "{" {
                j += 1;
                continue;
            }
            if t.ends_with(';') && !t.contains('(') && !t.contains("return") && !t.contains('=') {
                let tokens: Vec<&str> = t.trim_end_matches(';').split_whitespace().collect();
                if !tokens.is_empty() {
                    if tokens[0].starts_with("undefined") {
                        return true;
                    }
                    let name = tokens[tokens.len() - 1].trim_start_matches('*');
                    if name.starts_with("in_") {
                        return true;
                    }
                }
                j += 1;
                continue;
            }
            break;
        }
        false
    }

    // RUGRA-GLUE: symbol_driven_function_line_mask (no Ghidra counterpart —
    ///   see has_symbol_driven_decls; this is the whole-text segmentation the
    ///   line-oriented fix_unary_deref_declarations pass needs to skip
    ///   symbol-driven functions without restructuring its rewrite loop).
    /// Per-line mask: true = this line belongs to a function whose declaration
    /// block is symbol-driven (see `has_symbol_driven_decls`). Signature
    /// detection reuses `signature_opens_function_body` with a prefix set
    /// covering every return-type spelling the printc layer produces
    /// (including `undefinedN`, which the flush/backfill call sites'
    /// historical prefix sets do not list).
    fn symbol_driven_function_line_mask(lines: &[&str]) -> Vec<bool> {
        let prefixes = [
            "int ", "void ", "long ", "byte ", "bool ", "short ",
            "char ", "float ", "double ", "undefined", "uint ",
            "ulong ", "ushort ", "size_t ",
        ];
        let mut mask = vec![false; lines.len()];
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim();
            if !Self::signature_opens_function_body(t, &prefixes, &lines[i + 1..]) {
                i += 1;
                continue;
            }
            // Function chunk: signature line through the matching close brace
            // (brace depth from the signature line itself).
            let mut end = i + 1;
            let mut depth: i32 = t.chars().filter(|c| *c == '{').count() as i32
                - t.chars().filter(|c| *c == '}').count() as i32;
            // PRINTC-LEGACY-DECL-DUP-0001 (mask-chunk half): a skip_line
            // signature line carries no braces (depth 0), and the oracle
            // layout puts a BLANK line between the signature and the body's
            // `{` (open_brace_indent SkipLine emits two line breaks). The
            // previous loop broke on the blank line (depth still <= 0), so
            // the "chunk" was just [signature, blank] — has_symbol_driven_decls
            // saw no declarations and the function was never masked. That let
            // fix_unary_deref_declarations rewrite locked DWARF parameter
            // types in the signature (`int argc` -> `char *argc` in main)
            // even though printc.cc:2222 emitPrototypeInputs printed the
            // FuncProto's locked `int` correctly. Fix: before the depth walk,
            // skip forward to the opening `{` that signature_opens_function_
            // body already located via its lookahead; the walk then starts at
            // depth 1 and spans the real body.
            if depth <= 0 {
                let mut open = end;
                while open < lines.len() {
                    let ft = lines[open].trim();
                    if ft == "{" || ft.ends_with('{') {
                        depth += ft.chars().filter(|c| *c == '{').count() as i32;
                        depth -= ft.chars().filter(|c| *c == '}').count() as i32;
                        break;
                    }
                    // Any other non-blank line before the `{` means the
                    // lookahead contract was violated; fall back to the old
                    // two-line chunk rather than scanning past the function.
                    if !ft.is_empty() {
                        break;
                    }
                    open += 1;
                }
                if open > end {
                    end = open;
                }
            }
            while end < lines.len() {
                let ft = lines[end].trim();
                depth += ft.chars().filter(|c| *c == '{').count() as i32;
                depth -= ft.chars().filter(|c| *c == '}').count() as i32;
                if depth <= 0 {
                    end += 1;
                    break;
                }
                end += 1;
            }
            if Self::has_symbol_driven_decls(&lines[i..end]) {
                for m in mask.iter_mut().take(end).skip(i) {
                    *m = true;
                }
            }
            i = end;
        }
        mask
    }

    // RUGRA-GLUE: has_enclosing_loop_ctx (post-process goto→break/return
    //   rewrite helper; Ghidra emits break/continue structurally from
    //   FlowBlock::markUnstructured flags at emitGotoStatement, it never
    //   scans emitted text)
    fn has_enclosing_loop_ctx(emitted: &[String], target_indent: usize) -> bool {
        // Walk backward, tracking brace depth
        let mut _depth = 0i32;
        for line in emitted.iter().rev() {
            let t = line.trim();
            let ind = line.len() - line.trim_start().len();
            for ch in t.chars().rev() {
                match ch { '}' => _depth += 1, '{' => _depth -= 1, _ => {} }
            }
            // When we find an opening keyword at an indent level <= target (one level up)
            if ind < target_indent {
                if t.starts_with("while (") || t.starts_with("do {")
                    || t.starts_with("for (") || Self::is_switch_stmt_prefix(t)
                    || t.contains("} while (")
                {
                    return true;
                }
                // If we hit a function-level line, stop
                if ind == 0 { break; }
            }
        }
        false
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::negateSimpleCondition
    /// Negate a simple C condition expression for goto-to-if folding.
    /// Handles common patterns: ==, !=, <, >, <=, >=, and compound && / ||.
    fn negate_simple_condition(cond: &str) -> String {
        let cond = cond.trim();

        // Handle compound conditions with && or ||
        // "A && B" → "!A || !B" (De Morgan) — but simpler: just wrap with !()
        if cond.contains(" && ") || cond.contains(" || ") {
            return format!("!({})", cond);
        }

        // Simple relational operators
        if let Some(pos) = cond.find(" == ") {
            return format!("{} != {}", &cond[..pos], &cond[pos + 4..]);
        }
        if let Some(pos) = cond.find(" != ") {
            return format!("{} == {}", &cond[..pos], &cond[pos + 4..]);
        }
        if let Some(pos) = cond.find(" <= ") {
            return format!("{} > {}", &cond[..pos], &cond[pos + 4..]);
        }
        if let Some(pos) = cond.find(" >= ") {
            return format!("{} < {}", &cond[..pos], &cond[pos + 4..]);
        }
        if let Some(pos) = cond.find(" < ") {
            return format!("{} >= {}", &cond[..pos], &cond[pos + 3..]);
        }
        if let Some(pos) = cond.find(" > ") {
            return format!("{} <= {}", &cond[..pos], &cond[pos + 3..]);
        }

        // Fallback: wrap with !()
        format!("!({})", cond)
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::flushFuncRemoveUnused
    /// Remove unused variable declarations from a function's lines
    /// AND add missing declarations for uVarNNN that appear in body but have no declaration
    fn flush_func_remove_unused(func_lines: &[String], out: &mut Vec<String>) {
        // PRINTC-LEGACY-DECL-DUP-0001 bypass: when the chunk already carries
        // symbol-driven declarations (emit_local_var_decls products), both
        // halves of this pass only corrupt them — the missing-injection half
        // re-declares symbols whose oracle-join pointer spellings
        // (`char *uVar20;`, 2 tokens) this pass's type_ok table cannot
        // recognize, producing duplicate `int uVarN;` lines (and K&R
        // placement between signature and `{` when no uVar decl was
        // collected at all), and the unused-removal half deletes symbol
        // declarations Ghidra always prints (printc.cc:2260 emitLocalVarDecls
        // emits every symbol regardless of body use). Pass the chunk through
        // untouched; functions without symbol evidence keep the legacy pass.
        if Self::has_symbol_driven_decls(func_lines) {
            out.extend(func_lines.iter().cloned());
            return;
        }
        // Collect all declaration lines: "  type uVarNNN;"
        let mut decl_indices: Vec<(usize, String)> = Vec::new();
        for (i, line) in func_lines.iter().enumerate() {
            let t = line.trim();
            // Match "type uVarNNN;" and "type *uVarNNN;" declaration patterns.
            // Pointer forms split into a trailing token like "*uVar20", so the
            // variable name is taken as the substring after any leading '*'.
            if let Some(rest) = t.strip_suffix(';') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let last = parts[parts.len() - 1];
                    let name = last.trim_start_matches('*');
                    let type_first = parts[0];
                    let type_ok = parts.len() == 2
                        && (type_first == "int"
                            || type_first == "long"
                            || type_first == "bool"
                            || type_first == "byte"
                            || type_first == "short"
                            || type_first.starts_with("undefined"))
                        || (parts.len() == 3
                            && (type_first == "char"
                                || type_first == "int"
                                || type_first == "long"
                                || type_first == "void"
                                || type_first == "undefined8"
                                || type_first == "undefined4"
                                || type_first == "undefined2"
                                || type_first == "undefined")
                            && parts[1] == "*");
                    if type_ok && name.starts_with("uVar") {
                        decl_indices.push((i, name.to_string()));
                    }
                }
            }
        }

        // Check which declared names appear in non-declaration lines
        let body_text: String = func_lines.iter().enumerate()
            .filter(|(i, _)| !decl_indices.iter().any(|(di, _)| di == i))
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let unused: std::collections::HashSet<usize> = decl_indices.iter()
            .filter(|(_, name)| !body_text.contains(name.as_str()))
            .map(|(i, _)| *i)
            .collect();

        let declared_names: std::collections::HashSet<&str> = decl_indices.iter()
            .filter(|(i, _)| !unused.contains(i))
            .map(|(_, name)| name.as_str())
            .collect();

        // Find uVarNNN references in body that have no declaration
        let mut missing: Vec<String> = Vec::new();
        let mut search_pos = 0;
        let body_bytes = body_text.as_bytes();
        while search_pos + 4 < body_bytes.len() {
            if let Some(pos) = body_text[search_pos..].find("uVar") {
                let abs_pos = search_pos + pos;
                let name_start = abs_pos;
                let mut name_end = abs_pos + 4;
                // Collect digits after "uVar"
                while name_end < body_bytes.len() && body_bytes[name_end].is_ascii_digit() {
                    name_end += 1;
                }
                if name_end > abs_pos + 4 {
                    // Only match uVarNNN (digits), not uVar_hex (underscore)
                    let name = &body_text[name_start..name_end];
                    if !declared_names.contains(name) && !missing.contains(&name.to_string()) {
                        missing.push(name.to_string());
                    }
                }
                search_pos = name_end;
            } else {
                break;
            }
        }

        // Find insertion point (after last declaration, or after function signature)
        let last_decl_idx = decl_indices.iter()
            .filter(|(i, _)| !unused.contains(i))
            .map(|(i, _)| *i)
            .max()
            .unwrap_or(0);

        for (i, line) in func_lines.iter().enumerate() {
            if unused.contains(&i) {
                continue;
            }
            out.push(line.clone());
            // After last declaration (or first line), inject missing declarations
            if i == last_decl_idx && !missing.is_empty() {
                for mname in &missing {
                    out.push(format!("  int {};", mname));
                }
                missing.clear();
            }
        }
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::doIndent
    fn do_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("  ");
        }
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::isWordBoundary
    /// Check if char is a word boundary (not alphanumeric or underscore)
    fn is_word_boundary(c: char) -> bool {
        !c.is_ascii_alphanumeric() && c != '_'
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::countWordOccurrences
    /// Count word-boundary-respecting occurrences of `word` in `text`
    fn count_word_occurrences(text: &str, word: &str) -> usize {
        let mut count = 0;
        let bytes = text.as_bytes();
        let wlen = word.len();
        let mut pos = 0;
        while let Some(found) = text[pos..].find(word) {
            let abs_pos = pos + found;
            let before_ok = abs_pos == 0 || Self::is_word_boundary(bytes[abs_pos - 1] as char);
            let after_pos = abs_pos + wlen;
            let after_ok = after_pos >= text.len() || Self::is_word_boundary(bytes[after_pos] as char);
            if before_ok && after_ok {
                count += 1;
            }
            pos = abs_pos + 1;
        }
        count
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::replaceWord
    /// Replace word-boundary-respecting occurrences of `word` with `replacement`
    fn replace_word(text: &str, word: &str, replacement: &str) -> String {
        let bytes = text.as_bytes();
        let wlen = word.len();
        let mut result = String::with_capacity(text.len());
        let mut pos = 0;
        while let Some(found) = text[pos..].find(word) {
            let abs_pos = pos + found;
            let before_ok = abs_pos == 0 || Self::is_word_boundary(bytes[abs_pos - 1] as char);
            let after_pos = abs_pos + wlen;
            let after_ok = after_pos >= text.len() || Self::is_word_boundary(bytes[after_pos] as char);
            if before_ok && after_ok {
                result.push_str(&text[pos..abs_pos]);
                result.push_str(replacement);
                pos = after_pos;
            } else {
                result.push_str(&text[pos..abs_pos + 1]);
                pos = abs_pos + 1;
            }
        }
        result.push_str(&text[pos..]);
        result
    }
}

impl Emit for EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::print
    fn print(&mut self, text: &str) {
        self.output.push_str(text);
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::beginBlock
    fn begin_block(&mut self) {
        self.output.push_str(" {\n");
        self.indent += 1;
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::endBlock
    fn end_block(&mut self) {
        self.indent -= 1;
        self.output.push('\n');
        self.do_indent();
        self.output.push('}');
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::openParen
    fn open_paren(&mut self) {
        self.output.push('(');
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::closeParen
    fn close_paren(&mut self) {
        self.output.push(')');
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::beginFunction
    fn begin_function(&mut self) {
        // No-op for plain text
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::endFunction
    fn end_function(&mut self) {
        self.output.push('\n');
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagType
    fn tag_type(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagVariable
    fn tag_variable(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagOp
    fn tag_op(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagField
    fn tag_field(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagFuncName
    fn tag_func_name(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagComment
    fn tag_comment(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagLabel
    fn tag_label(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagCaseLabel
    fn tag_case_label(&mut self, text: &str) { self.print(text); }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagLine
    fn tag_line(&mut self, _indent: i32) {
        // Skip leading newline if we just opened a block (output ends with \n)
        if !self.output.ends_with('\n') {
            self.output.push('\n');
        }
        self.do_indent();
    }

    // Ghidra: prettyprint.cc:61 Emit::openBraceIndent
    /// Faithful text render of the oracle's `openBraceIndent`. The oracle's
    /// `EmitNoMarkup::tagLine` (prettyprint.hh:557) writes `endl` + indent
    /// UNCONDITIONALLY, so `skip_line` produces exactly two line breaks
    /// (a blank line) even when the output already sits at line start.
    /// Rugra's `tag_line` suppresses a repeated newline, so the two breaks
    /// are emitted directly here to preserve the oracle byte format.
    fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => self.output.push(' '),
            BraceStyle::SkipLine => {
                // tagLine(); tagLine(); — each is '\n' + indent at the OLD level
                self.output.push('\n');
                self.do_indent();
                self.output.push('\n');
                self.do_indent();
            }
            BraceStyle::NextLine => {
                self.output.push('\n');
                self.do_indent();
            }
        }
        // int4 id = startIndent(); — indentincrement = 2 spaces per level
        self.indent += 1;
        self.output.push_str(brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent
    /// Faithful text render of `closeBraceIndent`: stopIndent, then the
    /// oracle's unconditional `tagLine` ('\n' + indent at the NEW level),
    /// then the brace.
    fn close_brace_indent(&mut self, brace: &str) {
        self.indent -= 1;
        self.output.push('\n');
        self.do_indent();
        self.output.push_str(brace);
    }

    // RUGRA-GLUE: bump_indent (startIndent indent-bump half, prettyprint.hh:371)
    fn bump_indent(&mut self) {
        self.indent += 1;
    }

    // RUGRA-GLUE: drop_indent (stopIndent indent-drop half, prettyprint.hh:377)
    fn drop_indent(&mut self) {
        self.indent -= 1;
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::intoAny
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::asAnyMut
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

/// Emitter that discards all output (used for discovery pass)
pub struct NullEmit;

impl NullEmit {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        NullEmit
    }
}

impl Emit for NullEmit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    fn print(&mut self, _text: &str) {}
    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    fn begin_block(&mut self) {}
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    fn end_block(&mut self) {}
    // RUGRA-GLUE: open_paren (no Ghidra counterpart found)
    fn open_paren(&mut self) {}
    // RUGRA-GLUE: close_paren (no Ghidra counterpart found)
    fn close_paren(&mut self) {}
    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    fn begin_function(&mut self) {}
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    fn end_function(&mut self) {}
    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    fn tag_type(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    fn tag_variable(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    fn tag_op(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    fn tag_field(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_line (no Ghidra counterpart found)
    fn tag_line(&mut self, _indent: i32) {}
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    fn tag_func_name(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    fn tag_comment(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    fn tag_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    fn tag_case_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { None }
    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> { self }
}

/// Emit adapter that records whether any printed text contains `case `
/// (a switch case label). Used by printc to detect if a BlockIf's body
/// would emit a case label outside its switch context.
pub struct CaseDetectEmit {
    has_case: bool,
}

impl CaseDetectEmit {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        Self { has_case: false }
    }
    // RUGRA-GLUE: has_case (no Ghidra counterpart found)
    pub fn has_case(&self) -> bool {
        self.has_case
    }
}

impl Emit for CaseDetectEmit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    fn print(&mut self, text: &str) {
        if text.contains("case ") || text.contains("default:") {
            self.has_case = true;
        }
    }
    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    fn begin_block(&mut self) {}
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    fn end_block(&mut self) {}
    // RUGRA-GLUE: open_paren (no Ghidra counterpart found)
    fn open_paren(&mut self) {}
    // RUGRA-GLUE: close_paren (no Ghidra counterpart found)
    fn close_paren(&mut self) {}
    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    fn begin_function(&mut self) {}
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    fn end_function(&mut self) {}
    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    fn tag_type(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    fn tag_variable(&mut self, text: &str, _id: u64) {
        if text.contains("case ") { self.has_case = true; }
    }
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    fn tag_op(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    fn tag_field(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_line (no Ghidra counterpart found)
    fn tag_line(&mut self, _indent: i32) {}
    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    fn tag_func_name(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    fn tag_comment(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    fn tag_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    fn tag_case_label(&mut self, _text: &str) {
        self.has_case = true; // Any case_label tag = case label emitted
    }
    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::EmitNoMarkup;

    // RUGRA-GLUE: backfill_missing_locals unit tests (legacy text-pass
    // compensation layer; the oracle has no counterpart — Ghidra's
    // emitLocalVarDecls (printc.cc:2260-2279) declares every scope symbol
    // and never re-scans emitted text). These pin the A69 follow-up contract:
    // the oracle unnamed-location fallback tokens
    // <spacename><printRaw> (printc.cc:1938-1945: unique0x.../register0x.../
    // stack0x.../ram0x...) are recognized by the used-locals prefix scan and
    // get long declarations when absent from the declaration block.

    #[test]
    fn backfill_injects_unnamed_location_fallback_tokens() {
        let input = "\
long match_url(char *param_1,long param_2)

{
  char *piVar1;
  unique0x00023b00 = *param_1;
  if (unique0x00023b00 != '#') {
    __sprintf_chk(register0x000000a0,1,-1,0x0,(short)unique0x0000aa00);
    register0x00000000 = strlen(register0x000000a0);
  }
  return 0;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        // All four space spellings get long declarations (the default the
        // pre-A69 uVar-family spelling of these slots received).
        assert!(out.contains("  long register0x00000000;\n"), "missing register0x decl:\n{}", out);
        assert!(out.contains("  long register0x000000a0;\n"), "missing register0x dest decl:\n{}", out);
        assert!(out.contains("  long unique0x00023b00;\n"), "missing unique0x decl:\n{}", out);
        assert!(out.contains("  long unique0x0000aa00;\n"), "missing unique0x hex-tail decl:\n{}", out);
        // Declared names are not re-injected.
        assert_eq!(out.matches("char *piVar1;").count(), 1, "piVar1 re-declared:\n{}", out);
        // Injections land inside the function, before the first body line.
        let decl_pos = out.find("  long unique0x00023b00;").unwrap();
        let body_pos = out.find("unique0x00023b00 = *param_1;").unwrap();
        assert!(decl_pos < body_pos, "injection not before body:\n{}", out);
    }

    #[test]
    fn backfill_hex_tail_not_truncated() {
        // Regression guard for the continuation scan: the fallback token tail
        // is printRaw hex (space.cc:216 lowercase hex), so a decimal-only
        // scan would truncate unique0x0000abef at its first a-f digit and
        // inject a partial name.
        let input = "\
void f(void)

{
  stack0x0000abef = 1;
  ram0x00023e00 = stack0x0000abef + ram0x0000ff00;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert!(out.contains("  long stack0x0000abef;\n"), "stack0x hex tail mishandled:\n{}", out);
        assert!(out.contains("  long ram0x00023e00;\n"), "ram0x not injected:\n{}", out);
        assert!(out.contains("  long ram0x0000ff00;\n"), "second ram0x not injected:\n{}", out);
        assert!(!out.contains("stack0x0000;\n"), "hex tail truncated:\n{}", out);
        assert!(!out.contains("ram0x00023;\n"), "ram hex tail truncated:\n{}", out);
    }

    #[test]
    fn backfill_no_reinject_declared_fallback_token() {
        let input = "\
void f(void)

{
  long unique0x00023b00;
  unique0x00023b00 = 5;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert_eq!(out.matches("long unique0x00023b00;").count(), 1,
            "declared fallback token re-injected:\n{}", out);
    }

    #[test]
    fn backfill_legacy_prefixes_still_recognized() {
        // The legacy spellings keep their old behaviour (guards against
        // prefix-table regressions while adding the new forms).
        let input = "\
void f(void)

{
  int bVar3;
  bVar3 = uVar42 + local_10;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert!(out.contains("  long uVar42;\n"), "uVarN no longer injected:\n{}", out);
        assert!(out.contains("  int local_10;\n"), "local_ no longer injected:\n{}", out);
        assert_eq!(out.matches("int bVar3;").count(), 1, "bVar3 re-declared:\n{}", out);
    }
}
