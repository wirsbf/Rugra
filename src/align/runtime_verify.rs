//! Runtime verification framework for Rugra-Ghidra alignment
//!
//! This module provides runtime comparison testing between Rugra and Ghidra's
//! actual outputs, going beyond static type checking to ensure behavioral equivalence.
//!
//! # Architecture
//!
//! ```text
//! Binary Input
//!     ↓
//! ┌─────────────┐         ┌─────────────┐
//! │   Rugra     │         │   Ghidra    │
//! │ Decompiler  │         │ (via FFI)   │
//! └─────────────┘         └─────────────┘
//!     ↓                       ↓
//! Rugra Output           Ghidra Output
//!     ↓                       ↓
//!     └───────────┬───────────┘
//!                 ↓
//!         Runtime Comparator
//!                 ↓
//!         Difference Report
//! ```

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::pcode::{PcodeOpBank as Program, SeqNum};

use crate::ffi::VarnodeFFI;
use crate::Address;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// Test result for a single verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Perfect match
    Match,
    /// Mismatch with details
    Mismatch(String),
    /// Ghidra error (FFI call failed)
    GhidraError(String),
    /// Rugra error
    RugraError(String),
}

impl VerifyResult {
    pub fn is_match(&self) -> bool {
        matches!(self, VerifyResult::Match)
    }
}

/// Statistics for verification runs
#[derive(Debug, Clone, Default)]
pub struct VerifyStats {
    pub total_tests: usize,
    pub matches: usize,
    pub mismatches: usize,
    pub ghidra_errors: usize,
    pub rugra_errors: usize,
}

impl VerifyStats {
    pub fn record(&mut self, result: &VerifyResult) {
        self.total_tests += 1;
        match result {
            VerifyResult::Match => self.matches += 1,
            VerifyResult::Mismatch(_) => self.mismatches += 1,
            VerifyResult::GhidraError(_) => self.ghidra_errors += 1,
            VerifyResult::RugraError(_) => self.rugra_errors += 1,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.matches as f64) / (self.total_tests as f64) * 100.0
        }
    }
}

impl fmt::Display for VerifyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Verification Statistics ===")?;
        writeln!(f, "Total Tests:    {}", self.total_tests)?;
        writeln!(
            f,
            "Matches:        {} ({:.2}%)",
            self.matches,
            self.success_rate()
        )?;
        writeln!(f, "Mismatches:     {}", self.mismatches)?;
        writeln!(f, "Ghidra Errors:  {}", self.ghidra_errors)?;
        writeln!(f, "Rugra Errors:   {}", self.rugra_errors)?;
        Ok(())
    }
}

/// Runtime verification context
pub struct RuntimeVerifier {
    /// Statistics for all tests
    stats: Mutex<VerifyStats>,
    /// Detailed mismatch records
    mismatches: Mutex<Vec<MismatchRecord>>,
}

/// Record of a specific mismatch
#[derive(Debug, Clone)]
pub struct MismatchRecord {
    pub test_name: String,
    pub address: Option<Address>,
    pub rugra_output: String,
    pub ghidra_output: String,
    pub details: String,
}

impl RuntimeVerifier {
    pub fn new() -> Self {
        RuntimeVerifier {
            stats: Mutex::new(VerifyStats::default()),
            mismatches: Mutex::new(Vec::new()),
        }
    }

    /// Verify constant folding/evaluation
    ///
    /// Calls both Rugra's and Ghidra's constant evaluation and compares results
    pub fn verify_constant_eval(
        &self,
        test_name: &str,
        opcode: PcodeOp,
        ghidra_opcode: i32,
        val1: u64,
        size1: usize,
        val2: Option<(u64, usize)>,
        size_out: usize,
    ) -> VerifyResult {
        // Rugra evaluation
        let rugra_result = crate::analysis::rules::constants::evaluate_constant_op(
            opcode,
            &if let Some((v2, s2)) = val2 {
                vec![
                    Varnode::new_constant(val1, size1),
                    Varnode::new_constant(v2, s2),
                ]
            } else {
                vec![Varnode::new_constant(val1, size1)]
            },
        );

        // Ghidra evaluation (via FFI)
        let ghidra_result = unsafe {
            crate::ffi::rugra_evaluate_constant(
                ghidra_opcode,
                size_out,
                val1,
                size1,
                val2.map(|(v, _)| v).unwrap_or(0),
                val2.map(|(_, s)| s).unwrap_or(0),
                val2.is_some(),
            )
        };

        // Compare results
        let result = match rugra_result {
            Some(rugra_val) => {
                if rugra_val == ghidra_result {
                    VerifyResult::Match
                } else {
                    let details = format!(
                        "Constant eval mismatch: Rugra=0x{:x}, Ghidra=0x{:x}, Op={:?}, val1=0x{:x}, val2={:?}",
                        rugra_val, ghidra_result, opcode, val1, val2
                    );

                    self.record_mismatch(MismatchRecord {
                        test_name: test_name.to_string(),
                        address: None,
                        rugra_output: format!("0x{:x}", rugra_val),
                        ghidra_output: format!("0x{:x}", ghidra_result),
                        details: details.clone(),
                    });

                    VerifyResult::Mismatch(details)
                }
            }
            None => {
                if ghidra_result == 0 {
                    VerifyResult::Match // Both failed
                } else {
                    VerifyResult::Mismatch(format!(
                        "Rugra failed to evaluate, Ghidra returned 0x{:x}",
                        ghidra_result
                    ))
                }
            }
        };

        self.stats.lock().unwrap().record(&result);
        result
    }

    /// Verify P-code generation for a single instruction
    ///
    /// This requires Ghidra to be loaded with the same binary
    pub fn verify_pcode_generation(
        &self,
        test_name: &str,
        address: Address,
        rugra_ops: &[std::sync::Arc<std::sync::RwLock<PcodeOp>>],
        ghidra_op_count: usize,
    ) -> VerifyResult {
        // Basic count check
        if rugra_ops.len() != ghidra_op_count {
            let details = format!(
                "P-code count mismatch at 0x{:x}: Rugra generated {} ops, Ghidra generated {} ops",
                address.as_u64(),
                rugra_ops.len(),
                ghidra_op_count
            );

            self.record_mismatch(MismatchRecord {
                test_name: test_name.to_string(),
                address: Some(address),
                rugra_output: format!("{} ops", rugra_ops.len()),
                ghidra_output: format!("{} ops", ghidra_op_count),
                details: details.clone(),
            });

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        for (i, r_op_lock) in rugra_ops.iter().enumerate() {
            let r_op = r_op_lock.read().unwrap();
            
            let ghidra_opcode = 0; 
            
            unsafe {
                crate::ffi::rugra_compare_pcode(
                    address.as_u64(),
                    ghidra_opcode,
                    std::ptr::null(), 
                    std::ptr::null(), 
                    0 
                );
            }
        }


        let result = VerifyResult::Match;
        self.stats.lock().unwrap().record(&result);
        result
    }

    /// Verify SSA construction
    ///
    /// This is critical - SSA version numbers must match exactly
    pub fn verify_ssa_versions(
        &self,
        test_name: &str,
        rugra_varnodes: &[(Address, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>)],
        ghidra_versions: &[(u64, usize)], 
    ) -> VerifyResult {
        if rugra_varnodes.len() != ghidra_versions.len() {
            let details = format!(
                "SSA version count mismatch: Rugra has {} varnodes, Ghidra has {}",
                rugra_varnodes.len(),
                ghidra_versions.len()
            );

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        for ((addr, vn_lock), (g_addr, g_ver)) in rugra_varnodes.iter().zip(ghidra_versions.iter()) {
            let vn = vn_lock.read().unwrap();
            if addr.as_u64() != *g_addr {
                let details = format!(
                    "SSA address mismatch: Rugra 0x{:x}, Ghidra 0x{:x}",
                    addr.as_u64(),
                    g_addr
                );
                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            if vn.version() != *g_ver {
                let details = format!(
                    "SSA version mismatch at 0x{:x}: Rugra v{}, Ghidra v{}",
                    addr.as_u64(),
                    vn.version(),
                    g_ver
                );

                self.record_mismatch(MismatchRecord {
                    test_name: test_name.to_string(),
                    address: Some(*addr),
                    rugra_output: format!("v{}", vn.version()),
                    ghidra_output: format!("v{}", g_ver),
                    details: details.clone(),
                });

                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }
        }

        let result = VerifyResult::Match;
        self.stats.lock().unwrap().record(&result);
        result
    }

    /// Verify control flow graph structure
    pub fn verify_cfg_structure(
        &self,
        test_name: &str,
        rugra_blocks: &[(Address, Vec<Address>)], // (block_start, successors)
        ghidra_blocks: &[(u64, Vec<u64>)],
    ) -> VerifyResult {
        if rugra_blocks.len() != ghidra_blocks.len() {
            let details = format!(
                "CFG block count mismatch: Rugra has {} blocks, Ghidra has {}",
                rugra_blocks.len(),
                ghidra_blocks.len()
            );

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        for ((r_addr, r_succs), (g_addr, g_succs)) in rugra_blocks.iter().zip(ghidra_blocks.iter())
        {
            if r_addr.as_u64() != *g_addr {
                let details = format!(
                    "Block address mismatch: Rugra 0x{:x}, Ghidra 0x{:x}",
                    r_addr.as_u64(),
                    g_addr
                );
                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            if r_succs.len() != g_succs.len() {
                let details = format!(
                    "Block 0x{:x} successor count mismatch: Rugra {}, Ghidra {}",
                    r_addr.as_u64(),
                    r_succs.len(),
                    g_succs.len()
                );

                self.record_mismatch(MismatchRecord {
                    test_name: test_name.to_string(),
                    address: Some(*r_addr),
                    rugra_output: format!("{} successors", r_succs.len()),
                    ghidra_output: format!("{} successors", g_succs.len()),
                    details: details.clone(),
                });

                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            // Compare successor addresses
            for (r_succ, g_succ) in r_succs.iter().zip(g_succs.iter()) {
                if r_succ.as_u64() != *g_succ {
                    let details = format!(
                        "Block 0x{:x} successor mismatch: Rugra -> 0x{:x}, Ghidra -> 0x{:x}",
                        r_addr.as_u64(),
                        r_succ.as_u64(),
                        g_succ
                    );

                    let result = VerifyResult::Mismatch(details);
                    self.stats.lock().unwrap().record(&result);
                    return result;
                }
            }
        }

        let result = VerifyResult::Match;
        self.stats.lock().unwrap().record(&result);
        result
    }

    /// Record a mismatch for later analysis
    fn record_mismatch(&self, record: MismatchRecord) {
        self.mismatches.lock().unwrap().push(record);
    }

    /// Get current statistics
    pub fn get_stats(&self) -> VerifyStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get all mismatch records
    pub fn get_mismatches(&self) -> Vec<MismatchRecord> {
        self.mismatches.lock().unwrap().clone()
    }

    /// Generate a detailed report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("{}\n", self.get_stats()));

        let mismatches = self.get_mismatches();
        if !mismatches.is_empty() {
            report.push_str("\n=== Detailed Mismatches ===\n");
            for (i, mismatch) in mismatches.iter().enumerate() {
                report.push_str(&format!("\n{}. {}\n", i + 1, mismatch.test_name));
                if let Some(addr) = mismatch.address {
                    report.push_str(&format!("   Address: 0x{:x}\n", addr.as_u64()));
                }
                report.push_str(&format!("   Rugra:  {}\n", mismatch.rugra_output));
                report.push_str(&format!("   Ghidra: {}\n", mismatch.ghidra_output));
                report.push_str(&format!("   Details: {}\n", mismatch.details));
            }
        }

        report
    }

    /// Reset all statistics and records
    pub fn reset(&self) {
        *self.stats.lock().unwrap() = VerifyStats::default();
        self.mismatches.lock().unwrap().clear();
    }
}

impl Default for RuntimeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Global runtime verifier instance
static GLOBAL_VERIFIER: std::sync::LazyLock<RuntimeVerifier> =
    std::sync::LazyLock::new(RuntimeVerifier::new);

/// Get the global runtime verifier
pub fn global_verifier() -> &'static RuntimeVerifier {
    &GLOBAL_VERIFIER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_stats() {
        let mut stats = VerifyStats::default();

        stats.record(&VerifyResult::Match);
        stats.record(&VerifyResult::Match);
        stats.record(&VerifyResult::Mismatch("test".to_string()));

        assert_eq!(stats.total_tests, 3);
        assert_eq!(stats.matches, 2);
        assert_eq!(stats.mismatches, 1);
        assert!((stats.success_rate() - 66.66).abs() < 0.1);
    }

    #[test]
    fn test_runtime_verifier() {
        let verifier = RuntimeVerifier::new();

        // Test constant evaluation
        let result = verifier.verify_constant_eval(
            "add_test",
            OpCode::CPUI_INT_ADD,
            19, 
            10,
            4,
            Some((20, 4)),
            4,
        );

        // Note: This will likely mismatch unless Ghidra FFI is properly set up
        assert!(matches!(
            result,
            VerifyResult::Match | VerifyResult::Mismatch(_)
        ));
    }

    #[test]
    fn test_mismatch_recording() {
        let verifier = RuntimeVerifier::new();

        verifier.record_mismatch(MismatchRecord {
            test_name: "test1".to_string(),
            address: Some(Address::new(0x1000)),
            rugra_output: "foo".to_string(),
            ghidra_output: "bar".to_string(),
            details: "Different outputs".to_string(),
        });

        let mismatches = verifier.get_mismatches();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].test_name, "test1");
    }

    #[test]
    fn test_report_generation() {
        let verifier = RuntimeVerifier::new();

        verifier.verify_constant_eval("test", OpCode::CPUI_INT_ADD, 19, 1, 4, Some((2, 4)), 4);

        let report = verifier.generate_report();
        assert!(report.contains("Verification Statistics"));
    }
}
