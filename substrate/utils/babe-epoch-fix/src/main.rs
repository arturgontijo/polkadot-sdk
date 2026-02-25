//! Emergency BABE epoch recovery tool.
//!
//! This tool patches the `babe_epoch_changes` key in the Substrate ParityDB auxiliary
//! storage to fix an epoch that was announced with an empty authority set.
//!
//! ─────────────────────────────────────────────────────────────────────────────
//! MODES OF OPERATION
//! ─────────────────────────────────────────────────────────────────────────────
//!
//!   PATCH (default)
//!     babe-epoch-fix patch <db-path> [--dry-run] [--backup <file>]
//!
//!     Reads babe_epoch_changes from ParityDB, locates the broken epoch 39644
//!     (the one with 0 authorities), replaces its authority list with the 6
//!     authorities from epoch 39643, and writes the result back.
//!
//!     A backup of the original bytes is ALWAYS written before any write
//!     (default: <db-path>/babe_epoch_changes.bak).  Use --backup to choose a
//!     different path.
//!
//!     --dry-run performs every step except the final DB write and does NOT
//!     create a backup file.
//!
//!   RESTORE
//!     babe-epoch-fix restore <db-path> <backup-file>
//!
//!     Reads <backup-file> (created by a previous patch run) and writes its
//!     contents back into the database verbatim.  Use this to undo a patch.
//!
//!   INFO
//!     babe-epoch-fix info <db-path>
//!
//!     Reads babe_epoch_changes and reports:
//!       • total blob size
//!       • whether the broken epoch 39644 pattern is present
//!       • whether the patched pattern (epoch 39644 with ≥1 authority) is present
//!
//! ─────────────────────────────────────────────────────────────────────────────
//! CHAIN-SPECIFIC CONSTANTS (edit for a different chain / incident)
//! ─────────────────────────────────────────────────────────────────────────────
//!
//!   BROKEN_EPOCH_PREFIX  – first 25 bytes of PersistedEpoch::Regular(epoch_39644)
//!                          up to and including the compact-encoded empty Vec<> length
//!   GOOD_AUTHORITIES     – SCALE-encoded Vec<(AuthorityId, Weight)> from epoch 39643
//! 

use std::{
	fs,
	path::{Path, PathBuf},
};

// ── Chain-specific constants ──────────────────────────────────────────────────

/// First 25 bytes of the broken epoch entry in the SCALE blob.
///
/// Layout:
///   0x01                            – PersistedEpoch::Regular variant
///   dc 9a 00 00 00 00 00 00         – epoch_index = 39644  (u64 LE)
///   99 ae 97 11 00 00 00 00         – start_slot  = 295_153_305 (u64 LE)
///   58 02 00 00 00 00 00 00         – duration    = 600  (u64 LE)
///   00                              – authorities Vec compact length = 0  ← replaced
const BROKEN_EPOCH_PREFIX: &[u8] = &[
	0x01, // PersistedEpoch::Regular
	0xdc, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // epoch_index = 39644
	0x99, 0xae, 0x97, 0x11, 0x00, 0x00, 0x00, 0x00, // start_slot  = 295_153_305
	0x58, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // duration    = 600
	0x00, // authorities: compact Vec len = 0  ← this single byte is replaced
];

/// SCALE-encoded Vec<(AuthorityId, BabeAuthorityWeight)> from epoch 39643.
///
/// Layout: 0x18 (compact len = 6) + 6 × (32-byte pubkey + 8-byte weight LE)
const GOOD_AUTHORITIES: &[u8] = &[
	0x18, // compact Vec length = 6
	// ── authority 1 ──────────────────────────────────────────────────────────
	0x72, 0x42, 0xe6, 0x36, 0x3d, 0xff, 0xc4, 0xe5,
	0xd6, 0xdb, 0x33, 0x94, 0xbc, 0x3a, 0xbd, 0x27,
	0xc8, 0xd1, 0x8c, 0xc2, 0x4b, 0x27, 0x13, 0x1c,
	0x28, 0x0d, 0xb9, 0x74, 0x93, 0x71, 0x71, 0x79,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
	// ── authority 2 ──────────────────────────────────────────────────────────
	0x80, 0x6c, 0xa0, 0x5e, 0x21, 0xf9, 0x8b, 0xf0,
	0x19, 0xc9, 0xb1, 0x17, 0x04, 0xd1, 0xf9, 0x58,
	0x30, 0xbf, 0x6c, 0x79, 0xf7, 0x57, 0x42, 0x2e,
	0xcd, 0x7c, 0x74, 0x1c, 0xc9, 0x00, 0x81, 0x3d,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
	// ── authority 3 ──────────────────────────────────────────────────────────
	0x02, 0xec, 0x4a, 0xc0, 0x9a, 0xa7, 0x4d, 0xe6,
	0x4a, 0x1f, 0x98, 0x1e, 0x1a, 0x26, 0xae, 0xa0,
	0xd0, 0x8b, 0xb8, 0x36, 0x24, 0x05, 0x54, 0xed,
	0x86, 0xf8, 0xf7, 0xa9, 0x32, 0x89, 0x13, 0x2e,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
	// ── authority 4 ──────────────────────────────────────────────────────────
	0x3c, 0x05, 0xb4, 0x45, 0x12, 0x57, 0x0e, 0x65,
	0x61, 0x7d, 0xbb, 0x39, 0xbe, 0x56, 0x39, 0x31,
	0x70, 0x8b, 0x20, 0x04, 0x60, 0x9d, 0x92, 0x0f,
	0x39, 0xe1, 0x58, 0xf7, 0x3e, 0x05, 0x4b, 0x4f,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
	// ── authority 5 ──────────────────────────────────────────────────────────
	0x96, 0x40, 0xb0, 0xfd, 0x54, 0xe0, 0x0c, 0xf4,
	0x73, 0xf3, 0x88, 0x82, 0x14, 0x91, 0x52, 0x3c,
	0xc1, 0x0f, 0xec, 0x90, 0xe7, 0x3a, 0x36, 0x97,
	0xc5, 0x36, 0x6a, 0x63, 0xac, 0x17, 0x6a, 0x64,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
	// ── authority 6 ──────────────────────────────────────────────────────────
	0xda, 0x83, 0x50, 0x57, 0x65, 0x85, 0x80, 0x7e,
	0x08, 0x3b, 0x4b, 0x0a, 0xc4, 0x58, 0x6d, 0x77,
	0x05, 0x1f, 0x18, 0x99, 0x97, 0x1e, 0xa8, 0xad,
	0x33, 0xd8, 0x68, 0x4b, 0x91, 0x0c, 0x31, 0x0e,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // weight = 1
];

// ── Database constants ────────────────────────────────────────────────────────

const NUM_COLUMNS: u8 = 13;
const AUX_COLUMN: u8 = 8;
const BABE_EPOCH_CHANGES_KEY: &[u8] = b"babe_epoch_changes";

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args: Vec<String> = std::env::args().collect();

	match args.get(1).map(String::as_str) {
		Some("patch") => cmd_patch(&args[2..]),
		Some("restore") => cmd_restore(&args[2..]),
		Some("info") => cmd_info(&args[2..]),
		_ => {
			print_usage(&args[0]);
			std::process::exit(1);
		},
	}
}

fn print_usage(prog: &str) {
	eprintln!("Usage:");
	eprintln!("  {prog} patch   <db-path> [--dry-run] [--backup <file>]");
	eprintln!("  {prog} restore <db-path> <backup-file>");
	eprintln!("  {prog} info    <db-path>");
	eprintln!();
	eprintln!("  patch    Fix the broken epoch 39644 (empty authorities) in the database.");
	eprintln!("           Always writes a backup before modifying the DB.");
	eprintln!("           Default backup path: <db-path>/babe_epoch_changes.bak");
	eprintln!();
	eprintln!("  restore  Write a previously saved backup file back into the database,");
	eprintln!("           undoing a patch.");
	eprintln!();
	eprintln!("  info     Show the current state of babe_epoch_changes without changes.");
	eprintln!();
	eprintln!("  <db-path> must be the ParityDB directory (contains the 'metadata' file).");
	eprintln!("  Typically: <base-path>/chains/<chain-name>/db/full");
	eprintln!();
	eprintln!("  IMPORTANT: Stop the node before running this tool.");
}

// ── Open DB ───────────────────────────────────────────────────────────────────

fn open_db(db_path: &Path) -> Result<parity_db::Db, Box<dyn std::error::Error>> {
	let mut config = parity_db::Options::with_columns(db_path, NUM_COLUMNS);

	// Match Substrate's exact column configuration (sc_client_db::parity_db::open).
	for col_idx in [1u8, 4, 5, 6, 11, 12] {
		config.columns[col_idx as usize].compression = parity_db::CompressionType::Lz4;
	}
	config.columns[1].ref_counted = true;
	config.columns[1].preimage = true;
	config.columns[1].uniform = true;
	config.columns[11].ref_counted = true;
	config.columns[11].preimage = true;
	config.columns[11].uniform = true;

	parity_db::Db::open(&config).map_err(|e| {
		format!(
			"Failed to open ParityDB at '{}': {}\n\
			 Ensure the node is stopped and the path points to the database \
			 directory (the one containing the 'metadata' file).",
			db_path.display(),
			e
		)
		.into()
	})
}

fn read_epoch_changes(db: &parity_db::Db) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	db.get(AUX_COLUMN, BABE_EPOCH_CHANGES_KEY)
		.map_err(|e| format!("DB read error: {e}").into())
		.and_then(|opt| {
			opt.ok_or_else(|| {
				"Key 'babe_epoch_changes' not found in AUX column (column 8). \
				 Is this a valid Substrate BABE node database?"
					.into()
			})
		})
}

fn write_epoch_changes(
	db: &parity_db::Db,
	data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
	db.commit(std::iter::once((
		AUX_COLUMN,
		BABE_EPOCH_CHANGES_KEY.to_vec(),
		Some(data),
	)))
	.map_err(|e| format!("DB write error: {e}").into())
}

// ── patch ─────────────────────────────────────────────────────────────────────

fn cmd_patch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
	// Parse args: patch <db-path> [--dry-run] [--backup <file>]
	if args.is_empty() {
		eprintln!("patch: missing <db-path>");
		std::process::exit(1);
	}
	let db_path = PathBuf::from(&args[0]);
	let dry_run = args.iter().any(|a| a == "--dry-run");
	let backup_path: PathBuf = {
		let pos = args.iter().position(|a| a == "--backup");
		match pos.and_then(|p| args.get(p + 1)) {
			Some(p) => PathBuf::from(p),
			None => db_path.join("babe_epoch_changes.bak"),
		}
	};

	if dry_run {
		println!("=== DRY-RUN mode: no changes will be written ===");
	}

	println!("Opening ParityDB at: {}", db_path.display());
	let db = open_db(&db_path)?;
	println!("Database opened successfully.");

	let raw = read_epoch_changes(&db)?;
	println!("Read {} bytes from 'babe_epoch_changes'.", raw.len());

	// ── Check current state ────────────────────────────────────────────────────
	let already_patched = is_patched(&raw);
	let needs_patch = raw
		.windows(BROKEN_EPOCH_PREFIX.len())
		.any(|w| w == BROKEN_EPOCH_PREFIX);

	if already_patched && !needs_patch {
		println!();
		println!(
			"The database appears to already be patched \
			 (epoch 39644 has authorities, broken pattern not found)."
		);
		println!("No changes needed.");
		return Ok(());
	}

	if !needs_patch {
		println!();
		println!(
			"WARNING: The broken epoch 39644 pattern was NOT found.\n\
			 This might mean:\n\
			   • The database is from a different chain, or\n\
			   • The chain-specific constants in this binary do not match your chain.\n\
			 No changes made."
		);
		return Ok(());
	}

	let match_pos = raw
		.windows(BROKEN_EPOCH_PREFIX.len())
		.position(|w| w == BROKEN_EPOCH_PREFIX)
		.unwrap();

	println!(
		"Found broken epoch 39644 (empty authorities) at byte offset {}.",
		match_pos
	);

	// ── Build patched blob ─────────────────────────────────────────────────────
	let auth_byte_pos = match_pos + BROKEN_EPOCH_PREFIX.len() - 1;
	let mut patched: Vec<u8> = Vec::with_capacity(raw.len() + GOOD_AUTHORITIES.len() - 1);
	patched.extend_from_slice(&raw[..auth_byte_pos]);
	patched.extend_from_slice(GOOD_AUTHORITIES);
	patched.extend_from_slice(&raw[auth_byte_pos + 1..]);

	println!(
		"Patch ready: {} bytes → {} bytes  (+{} bytes for 6 authorities).",
		raw.len(),
		patched.len(),
		patched.len() - raw.len(),
	);

	// Sanity: broken pattern must be gone, patched pattern must be present.
	if patched.windows(BROKEN_EPOCH_PREFIX.len()).any(|w| w == BROKEN_EPOCH_PREFIX) {
		return Err("BUG: broken pattern still present after patching. File a bug report.".into());
	}
	if !is_patched(&patched) {
		return Err("BUG: patched pattern not found after patching. File a bug report.".into());
	}

	if dry_run {
		println!();
		println!("=== DRY-RUN: no files written. Remove --dry-run to apply. ===");
		return Ok(());
	}

	// ── Write backup FIRST ─────────────────────────────────────────────────────
	println!();
	println!("Writing backup to: {}", backup_path.display());
	fs::write(&backup_path, &raw).map_err(|e| {
		format!("Could not write backup to '{}': {}", backup_path.display(), e)
	})?;
	println!(
		"Backup written ({} bytes).  Keep this file until the chain is confirmed healthy.",
		raw.len()
	);

	// ── Write patched data ─────────────────────────────────────────────────────
	println!();
	println!("Writing patched data to database...");
	write_epoch_changes(&db, patched)?;

	println!("✓ Database patched successfully.");
	println!();
	println!("NEXT STEPS:");
	println!("  1. Run this tool on every other validator node.");
	println!("  2. Restart the validators with --force-authoring.");
	println!("  3. Watch for 'Claimed slot N' in babe logs, then imported/finalized blocks.");
	println!(
		"  4. Once the chain is stable, remove --force-authoring and delete the backup."
	);
	println!();
	println!(
		"TO UNDO THIS PATCH (if something goes wrong):  \
		 babe-epoch-fix restore {} {}",
		db_path.display(),
		backup_path.display()
	);

	Ok(())
}

// ── restore ───────────────────────────────────────────────────────────────────

fn cmd_restore(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
	if args.len() < 2 {
		eprintln!("restore: usage: restore <db-path> <backup-file>");
		std::process::exit(1);
	}
	let db_path = PathBuf::from(&args[0]);
	let backup_path = PathBuf::from(&args[1]);

	println!("Restoring from backup: {}", backup_path.display());
	println!("Target database:       {}", db_path.display());

	let original = fs::read(&backup_path).map_err(|e| {
		format!("Could not read backup file '{}': {}", backup_path.display(), e)
	})?;
	println!("Read {} bytes from backup.", original.len());

	// Confirm the backup contains the broken pattern (sanity check).
	let has_broken = original
		.windows(BROKEN_EPOCH_PREFIX.len())
		.any(|w| w == BROKEN_EPOCH_PREFIX);
	if has_broken {
		println!(
			"Note: backup contains the broken epoch 39644 pattern — \
			 this is the original (pre-patch) data, as expected."
		);
	} else {
		println!(
			"Note: backup does NOT contain the broken epoch 39644 pattern. \
			 It may be from a different point in time — proceeding anyway."
		);
	}

	println!();
	println!("Opening ParityDB at: {}", db_path.display());
	let db = open_db(&db_path)?;
	println!("Database opened successfully.");

	write_epoch_changes(&db, original)?;

	println!("✓ Restore complete. The database now contains the original epoch changes.");
	println!("  Restart the node to use the restored data.");

	Ok(())
}

// ── info ──────────────────────────────────────────────────────────────────────

fn cmd_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
	if args.is_empty() {
		eprintln!("info: missing <db-path>");
		std::process::exit(1);
	}
	let db_path = PathBuf::from(&args[0]);

	println!("Opening ParityDB at: {}", db_path.display());
	let db = open_db(&db_path)?;
	println!("Database opened successfully.");

	let raw = read_epoch_changes(&db)?;
	println!();
	println!("babe_epoch_changes blob: {} bytes", raw.len());

	let has_broken = raw
		.windows(BROKEN_EPOCH_PREFIX.len())
		.any(|w| w == BROKEN_EPOCH_PREFIX);

	let patched = is_patched(&raw);

	println!();
	if has_broken {
		let pos = raw
			.windows(BROKEN_EPOCH_PREFIX.len())
			.position(|w| w == BROKEN_EPOCH_PREFIX)
			.unwrap();
		println!("  [✗] Broken epoch 39644 (0 authorities) found at byte offset {}.", pos);
		println!("      → Database needs patching.");
	} else {
		println!("  [✓] Broken epoch 39644 pattern NOT found.");
	}

	if patched {
		println!("  [✓] Patched epoch 39644 (with authorities) found.");
		println!("      → Database appears already patched.");
	} else {
		println!("  [?] Patched epoch 39644 pattern not found.");
		if !has_broken {
			println!(
				"      → Neither broken nor patched pattern present. \
				 Chain-specific constants may not match this database."
			);
		}
	}

	Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns true if the patched epoch 39644 (with the first authority byte present)
/// is found anywhere in the blob.  We check for the prefix up to (but not including)
/// the Vec length byte, then verify the next byte is NOT 0x00.
fn is_patched(data: &[u8]) -> bool {
	// Search for everything in BROKEN_EPOCH_PREFIX except the last 0x00 byte.
	let prefix_without_auth = &BROKEN_EPOCH_PREFIX[..BROKEN_EPOCH_PREFIX.len() - 1];
	data.windows(prefix_without_auth.len())
		.enumerate()
		.any(|(i, w)| {
			w == prefix_without_auth &&
				data.get(i + prefix_without_auth.len()).copied().unwrap_or(0) != 0x00
		})
}
