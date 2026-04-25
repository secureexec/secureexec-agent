/// Minimal BTF binary parser for kernel struct field offset validation.
///
/// Reads `/sys/kernel/btf/vmlinux` directly (BTF magic 0xeB9F) and resolves
/// struct member offsets, including:
///   - anonymous nested struct/union members (e.g. `skc_dport` lives inside
///     the anonymous `skc_portpair` union in `sock_common`);
///   - typedef / qualifier chains (e.g. `__be32` → `__u32` → INT, used for
///     `skc_daddr` / `skc_rcv_saddr` / `skc_dport`).
///
/// Does NOT depend on aya's internal (pub(crate)) BTF walking API.
///
/// BTF kind values follow `<linux/btf.h>`:
///   1=INT 2=PTR 3=ARRAY 4=STRUCT 5=UNION 6=ENUM 7=FWD 8=TYPEDEF 9=VOLATILE
///   10=CONST 11=RESTRICT 12=FUNC 13=FUNC_PROTO 14=VAR 15=DATASEC 16=FLOAT
///   17=DECL_TAG 18=TYPE_TAG 19=ENUM64
use std::collections::HashMap;

use crate::sensors::ebpf::tracefs::OffsetMismatch;
use crate::sensors::ebpf::tracefs::MismatchKind;

// ---------------------------------------------------------------------------
// BTF binary format constants
// ---------------------------------------------------------------------------

const BTF_MAGIC: u16 = 0xEB9F;

// Kinds whose payload after `struct btf_type` is fixed-size or vlen-scaled.
const BTF_KIND_INT:        u8 = 1;
const BTF_KIND_PTR:        u8 = 2;
const BTF_KIND_ARRAY:      u8 = 3;
const BTF_KIND_STRUCT:     u8 = 4;
const BTF_KIND_UNION:      u8 = 5;
const BTF_KIND_ENUM:       u8 = 6;
const BTF_KIND_FWD:        u8 = 7;
const BTF_KIND_TYPEDEF:    u8 = 8;
const BTF_KIND_VOLATILE:   u8 = 9;
const BTF_KIND_CONST:      u8 = 10;
const BTF_KIND_RESTRICT:   u8 = 11;
const BTF_KIND_FUNC:       u8 = 12;
const BTF_KIND_FUNC_PROTO: u8 = 13;
const BTF_KIND_VAR:        u8 = 14;
const BTF_KIND_DATASEC:    u8 = 15;
const BTF_KIND_FLOAT:      u8 = 16;
const BTF_KIND_DECL_TAG:   u8 = 17;
const BTF_KIND_TYPE_TAG:   u8 = 18;
const BTF_KIND_ENUM64:     u8 = 19;

// ---------------------------------------------------------------------------
// Expected kernel struct field spec
// ---------------------------------------------------------------------------

/// One struct field we expect at a given byte offset with an optional size.
/// `size: None` = pointer; size depends on kernel bitness (not validated).
pub struct ExpectedKernelField {
    pub struct_name: &'static str,
    pub field:       &'static str,
    pub offset:      usize,
    pub size:        Option<usize>,
}

// ---------------------------------------------------------------------------
// Resolved field info from BTF
// ---------------------------------------------------------------------------

struct FieldInfo {
    /// Byte offset within the struct.
    offset_bytes: usize,
    /// Size in bytes, derived from the member's type (and any typedef chain).
    /// `None` = pointer or unresolvable.
    size_bytes: Option<usize>,
}

// ---------------------------------------------------------------------------
// Parsed BTF representation
// ---------------------------------------------------------------------------

/// Internal view of a single struct/union member parsed from BTF.
struct Member {
    name:         String,
    bit_offset:   u32,
    type_id:      u32,
}

/// Internal view of a parsed struct or union type.
struct BtfComposite {
    members: Vec<Member>,
}

/// Minimal parsed BTF index.
struct BtfIndex {
    /// Named structs/unions: name → type_id.  We use the FIRST occurrence of
    /// each name (BTF deduplicates, but multiple anonymous-tagged forwards
    /// can technically share a name).
    named: HashMap<String, u32>,
    /// All composites (named and anonymous): type_id → definition.
    composites: HashMap<u32, BtfComposite>,
    /// type_id → size_bytes for scalars (INT, FLOAT, ENUM, ENUM64, STRUCT,
    /// UNION, DATASEC).  Pointers and qualifiers are resolved through
    /// `qualifier_chain`.
    type_sizes: HashMap<u32, usize>,
    /// type_id → underlying type_id for TYPEDEF / VOLATILE / CONST /
    /// RESTRICT / TYPE_TAG.  Allows `effective_size` to chase through
    /// qualifier chains down to the concrete scalar/struct.
    qualifier_chain: HashMap<u32, u32>,
}

// ---------------------------------------------------------------------------
// Little-endian primitive readers
// ---------------------------------------------------------------------------

fn parse_u16_le(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes(b.try_into().ok()?))
}

fn parse_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// BTF binary parser
// ---------------------------------------------------------------------------

/// Parse raw BTF bytes into a `BtfIndex`.
///
/// `data` is expected to start with the `btf_header` (24 bytes) followed by
/// the type and string sections at the offsets recorded in the header.
fn parse_btf(data: &[u8]) -> Result<BtfIndex, String> {
    // --- header (min 24 bytes) ---
    if data.len() < 24 {
        return Err("BTF data too short".into());
    }
    let magic = parse_u16_le(data, 0).ok_or("BTF header truncated")?;
    if magic != BTF_MAGIC {
        // Reading a big-endian BTF blob with a little-endian parser produces
        // a byte-swapped magic (0x9FEB).  Either way we can't decode it.
        return Err(format!("bad BTF magic: {magic:#06x} (need {BTF_MAGIC:#06x})"));
    }
    let hdr_len  = parse_u32_le(data, 4).unwrap()  as usize;
    let type_off = parse_u32_le(data, 8).unwrap()  as usize;
    let type_len = parse_u32_le(data, 12).unwrap() as usize;
    let str_off  = parse_u32_le(data, 16).unwrap() as usize;
    let str_len  = parse_u32_le(data, 20).unwrap() as usize;

    let type_base = hdr_len.checked_add(type_off).ok_or("type_off overflow")?;
    let str_base  = hdr_len.checked_add(str_off).ok_or("str_off overflow")?;
    let type_end  = type_base.checked_add(type_len).ok_or("type_len overflow")?;
    let str_end   = str_base.checked_add(str_len).ok_or("str_len overflow")?;
    if type_end > data.len() || str_end > data.len() {
        return Err("BTF section out of range".into());
    }

    let types_bytes  = &data[type_base..type_end];
    let strtab_bytes = &data[str_base..str_end];

    // String-table accessor.  Returns "" for any out-of-range or unterminated
    // offset; "" is also the canonical empty name (offset 0 in any valid BTF).
    let cstr = |off: u32| -> String {
        let off = off as usize;
        if off >= strtab_bytes.len() { return String::new(); }
        match strtab_bytes[off..].iter().position(|&b| b == 0) {
            Some(end) => String::from_utf8_lossy(&strtab_bytes[off..off + end]).into_owned(),
            None      => String::new(),
        }
    };

    let mut named:           HashMap<String, u32>       = HashMap::new();
    let mut composites:      HashMap<u32, BtfComposite> = HashMap::new();
    let mut type_sizes:      HashMap<u32, usize>        = HashMap::new();
    let mut qualifier_chain: HashMap<u32, u32>          = HashMap::new();

    // type_id 0 is reserved for void; the first parsed type gets type_id=1.
    let mut type_id: u32 = 1;
    let mut pos = 0usize;

    while pos + 12 <= types_bytes.len() {
        let name_off     = parse_u32_le(types_bytes, pos).unwrap();
        let info         = parse_u32_le(types_bytes, pos + 4).unwrap();
        let size_or_type = parse_u32_le(types_bytes, pos + 8).unwrap();
        pos += 12;

        let kind  = ((info >> 24) & 0x1f) as u8;
        let vlen  = (info & 0xFFFF) as usize;
        let kflag = (info >> 31) != 0;

        match kind {
            BTF_KIND_INT => {
                // INT: 4 extra bytes (encoding word); size_or_type = byte size.
                type_sizes.insert(type_id, size_or_type as usize);
                pos = pos.saturating_add(4);
            }
            BTF_KIND_PTR => {
                // No extra payload.  Size unknown (pointer width is kernel-
                // dependent); pointers are validated with size: None.
            }
            BTF_KIND_ARRAY => {
                // 12 extra bytes (struct btf_array).  We don't compute array
                // size because we don't validate any array fields by size.
                pos = pos.saturating_add(12);
            }
            BTF_KIND_STRUCT | BTF_KIND_UNION => {
                let byte_size = size_or_type as usize;
                type_sizes.insert(type_id, byte_size);
                let name = cstr(name_off);
                let mut members = Vec::with_capacity(vlen.min(1024));
                for _ in 0..vlen {
                    if pos + 12 > types_bytes.len() { break; }
                    let m_name_off = parse_u32_le(types_bytes, pos).unwrap();
                    let m_type     = parse_u32_le(types_bytes, pos + 4).unwrap();
                    let m_off_raw  = parse_u32_le(types_bytes, pos + 8).unwrap();
                    pos += 12;
                    // When kflag is set, the upper byte holds bitfield_size
                    // and the lower 24 bits hold the bit offset.  We never
                    // validate bitfield fields, so we drop bitfield_size.
                    let bit_offset = if kflag { m_off_raw & 0x00FF_FFFF } else { m_off_raw };
                    members.push(Member {
                        name: cstr(m_name_off),
                        bit_offset,
                        type_id: m_type,
                    });
                }
                if !name.is_empty() {
                    named.entry(name).or_insert(type_id);
                }
                composites.insert(type_id, BtfComposite { members });
            }
            BTF_KIND_ENUM => {
                // ENUM: vlen × struct btf_enum (8 bytes).  Size in size_or_type.
                type_sizes.insert(type_id, size_or_type as usize);
                pos = pos.saturating_add(vlen.saturating_mul(8));
            }
            BTF_KIND_FWD => {
                // No extra payload; no size.
            }
            BTF_KIND_TYPEDEF
            | BTF_KIND_VOLATILE
            | BTF_KIND_CONST
            | BTF_KIND_RESTRICT
            | BTF_KIND_TYPE_TAG => {
                // No extra payload; size_or_type = referenced type_id.
                qualifier_chain.insert(type_id, size_or_type);
            }
            BTF_KIND_FUNC => {
                // No extra payload.
            }
            BTF_KIND_FUNC_PROTO => {
                // vlen × struct btf_param (8 bytes).
                pos = pos.saturating_add(vlen.saturating_mul(8));
            }
            BTF_KIND_VAR => {
                // 4 extra bytes (struct btf_var).
                pos = pos.saturating_add(4);
            }
            BTF_KIND_DATASEC => {
                // vlen × struct btf_var_secinfo (12 bytes).
                pos = pos.saturating_add(vlen.saturating_mul(12));
            }
            BTF_KIND_FLOAT => {
                // No extra payload; size_or_type = byte size.
                type_sizes.insert(type_id, size_or_type as usize);
            }
            BTF_KIND_DECL_TAG => {
                // 4 extra bytes (struct btf_decl_tag).
                pos = pos.saturating_add(4);
            }
            BTF_KIND_ENUM64 => {
                // vlen × struct btf_enum64 (12 bytes).  Size in size_or_type.
                type_sizes.insert(type_id, size_or_type as usize);
                pos = pos.saturating_add(vlen.saturating_mul(12));
            }
            _ => {
                // Unknown kind from a future kernel: assume no extra payload.
                // If wrong, parsing of subsequent types will be misaligned;
                // unknown types are however expected to be rare and are
                // ignored by `validate_all` lookups (no name resolution).
            }
        }

        type_id += 1;
    }

    Ok(BtfIndex { named, composites, type_sizes, qualifier_chain })
}

impl BtfIndex {
    /// Resolve the byte size of `type_id`, chasing through TYPEDEF / VOLATILE
    /// / CONST / RESTRICT / TYPE_TAG to the underlying scalar/struct.
    /// Returns `None` for pointers, FWDs and unresolvable types.
    /// Bounded by a small depth limit to avoid pathological cycles in
    /// malformed BTF.
    fn effective_size(&self, mut type_id: u32) -> Option<usize> {
        for _ in 0..16 {
            if let Some(&sz) = self.type_sizes.get(&type_id) {
                return Some(sz);
            }
            match self.qualifier_chain.get(&type_id) {
                Some(&next) if next != type_id => type_id = next,
                _ => return None,
            }
        }
        None
    }

    /// Resolve a field `field_name` in `struct_name`, recursively descending
    /// into anonymous (name == "") nested struct/union members (used for e.g.
    /// `skc_dport` which lives inside the anonymous `skc_portpair` union in
    /// `sock_common`).
    ///
    /// Returns `(byte_offset_from_struct_start, size_bytes_if_known)`.
    fn resolve_field(
        &self,
        struct_name: &str,
        field_name: &str,
    ) -> Option<FieldInfo> {
        let type_id = *self.named.get(struct_name)?;
        let composite = self.composites.get(&type_id)?;
        self.resolve_in(composite, field_name, 0)
    }

    fn resolve_in(
        &self,
        composite: &BtfComposite,
        field_name: &str,
        base_bit_offset: u32,
    ) -> Option<FieldInfo> {
        for m in &composite.members {
            let member_bit_off = base_bit_offset.saturating_add(m.bit_offset);
            if m.name == field_name {
                return Some(FieldInfo {
                    offset_bytes: (member_bit_off / 8) as usize,
                    size_bytes:   self.effective_size(m.type_id),
                });
            }
            // Anonymous member (name == ""): descend into nested struct/union.
            if m.name.is_empty() {
                if let Some(nested) = self.composites.get(&m.type_id) {
                    if let Some(info) = self.resolve_in(nested, field_name, member_bit_off) {
                        return Some(info);
                    }
                }
            }
        }
        None
    }

    fn has_struct(&self, name: &str) -> bool {
        self.named.contains_key(name)
    }
}

// ---------------------------------------------------------------------------
// BtfStructValidator
// ---------------------------------------------------------------------------

/// Validates that the hard-coded kernel struct field offsets in the eBPF programs
/// match the layout reported by `/sys/kernel/btf/vmlinux`.
///
/// `new()` always succeeds. If BTF is unavailable, `validate_all` emits a
/// single `MismatchKind::Source { reason: "btf_unavailable" }` so the alert
/// counter still bumps.
pub struct BtfStructValidator {
    index: Result<BtfIndex, String>,
}

impl BtfStructValidator {
    pub fn new() -> Self {
        Self { index: Self::load() }
    }

    fn load() -> Result<BtfIndex, String> {
        let data = std::fs::read("/sys/kernel/btf/vmlinux")
            .map_err(|e| format!("/sys/kernel/btf/vmlinux: {e}"))?;
        parse_btf(&data)
    }

    pub fn validate_all(&self, fields: &[ExpectedKernelField]) -> Vec<OffsetMismatch> {
        let index = match &self.index {
            Ok(idx) => idx,
            Err(_) => {
                return vec![OffsetMismatch {
                    kind:            MismatchKind::Source,
                    label:           "btf".into(),
                    field:           String::new(),
                    expected_offset: None,
                    actual_offset:   None,
                    expected_size:   None,
                    actual_size:     None,
                    reason:          "btf_unavailable",
                }];
            }
        };

        let mut out = Vec::new();
        for ef in fields {
            if !index.has_struct(ef.struct_name) {
                out.push(OffsetMismatch {
                    kind:            MismatchKind::Struct,
                    label:           ef.struct_name.into(),
                    field:           ef.field.into(),
                    expected_offset: Some(ef.offset),
                    actual_offset:   None,
                    expected_size:   ef.size,
                    actual_size:     None,
                    reason:          "struct_missing",
                });
                continue;
            }

            match index.resolve_field(ef.struct_name, ef.field) {
                None => {
                    out.push(OffsetMismatch {
                        kind:            MismatchKind::Struct,
                        label:           ef.struct_name.into(),
                        field:           ef.field.into(),
                        expected_offset: Some(ef.offset),
                        actual_offset:   None,
                        expected_size:   ef.size,
                        actual_size:     None,
                        reason:          "field_missing",
                    });
                }
                Some(info) => {
                    if info.offset_bytes != ef.offset {
                        out.push(OffsetMismatch {
                            kind:            MismatchKind::Struct,
                            label:           ef.struct_name.into(),
                            field:           ef.field.into(),
                            expected_offset: Some(ef.offset),
                            actual_offset:   Some(info.offset_bytes),
                            expected_size:   ef.size,
                            actual_size:     info.size_bytes,
                            reason:          "offset_mismatch",
                        });
                    } else if let (Some(exp_sz), Some(act_sz)) = (ef.size, info.size_bytes) {
                        if act_sz != exp_sz {
                            out.push(OffsetMismatch {
                                kind:            MismatchKind::Struct,
                                label:           ef.struct_name.into(),
                                field:           ef.field.into(),
                                expected_offset: Some(ef.offset),
                                actual_offset:   Some(info.offset_bytes),
                                expected_size:   Some(exp_sz),
                                actual_size:     Some(act_sz),
                                reason:          "size_mismatch",
                            });
                        }
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Validated kernel struct fields (hard-coded offsets in network.rs eBPF)
// ---------------------------------------------------------------------------

/// Kernel struct field offsets hard-coded in `agent/linux/ebpf/src/network.rs`.
/// Validated at agent startup; any mismatch is reported as a critical anomaly.
pub const VALIDATED_KERNEL_FIELDS: &[ExpectedKernelField] = &[
    // sock_common — read_sock_v4_*/read_sock_v6_*/cache_udp_source
    ExpectedKernelField { struct_name: "sock_common", field: "skc_daddr",        offset: 0,  size: Some(4)  },
    ExpectedKernelField { struct_name: "sock_common", field: "skc_rcv_saddr",    offset: 4,  size: Some(4)  },
    // skc_dport and skc_num live inside anonymous union skc_portpair:
    ExpectedKernelField { struct_name: "sock_common", field: "skc_dport",        offset: 12, size: Some(2)  },
    ExpectedKernelField { struct_name: "sock_common", field: "skc_num",          offset: 14, size: Some(2)  },
    ExpectedKernelField { struct_name: "sock_common", field: "skc_family",       offset: 16, size: Some(2)  },
    ExpectedKernelField { struct_name: "sock_common", field: "skc_v6_daddr",     offset: 56, size: Some(16) },
    ExpectedKernelField { struct_name: "sock_common", field: "skc_v6_rcv_saddr", offset: 72, size: Some(16) },
    // socket — try_inet_bind / try_inet6_bind
    ExpectedKernelField { struct_name: "socket",      field: "sk",               offset: 24, size: None     },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny BTF blob builder used by the parser tests.  Mirrors the on-disk
    /// layout: `btf_header` (24 bytes) → type section → string section.
    struct BtfBuilder {
        types:  Vec<u8>,
        strtab: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            // The strtab always begins with a single NUL byte: offset 0 is
            // the canonical empty name.
            Self { types: Vec::new(), strtab: vec![0u8] }
        }

        fn add_string(&mut self, s: &str) -> u32 {
            if s.is_empty() {
                return 0;
            }
            let off = self.strtab.len() as u32;
            self.strtab.extend_from_slice(s.as_bytes());
            self.strtab.push(0);
            off
        }

        fn push_type_header(&mut self, name_off: u32, kind: u8, vlen: u32, kflag: bool, size_or_type: u32) {
            let info = (vlen & 0xFFFF) | ((kind as u32) << 24) | (if kflag { 1u32 << 31 } else { 0 });
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
        }

        fn add_int(&mut self, name: &str, byte_size: u32) -> u32 {
            let n = self.add_string(name);
            self.push_type_header(n, BTF_KIND_INT, 0, false, byte_size);
            // 4-byte encoding word (encoding=0, offset=0, bits=byte_size*8).
            let bits = byte_size * 8;
            self.types.extend_from_slice(&bits.to_le_bytes());
            self.next_id()
        }

        fn add_typedef(&mut self, name: &str, ref_type: u32) -> u32 {
            let n = self.add_string(name);
            self.push_type_header(n, BTF_KIND_TYPEDEF, 0, false, ref_type);
            self.next_id()
        }

        fn add_const(&mut self, ref_type: u32) -> u32 {
            self.push_type_header(0, BTF_KIND_CONST, 0, false, ref_type);
            self.next_id()
        }

        fn add_ptr(&mut self, ref_type: u32) -> u32 {
            self.push_type_header(0, BTF_KIND_PTR, 0, false, ref_type);
            self.next_id()
        }

        fn add_fwd(&mut self, name: &str) -> u32 {
            let n = self.add_string(name);
            self.push_type_header(n, BTF_KIND_FWD, 0, false, 0);
            self.next_id()
        }

        fn add_enum(&mut self, name: &str, byte_size: u32, values: &[(&str, i32)]) -> u32 {
            let n = self.add_string(name);
            let vlen = values.len() as u32;
            self.push_type_header(n, BTF_KIND_ENUM, vlen, false, byte_size);
            for (vn, vv) in values {
                let vn_off = self.add_string(vn);
                self.types.extend_from_slice(&vn_off.to_le_bytes());
                self.types.extend_from_slice(&vv.to_le_bytes());
            }
            self.next_id()
        }

        fn add_enum64(&mut self, name: &str, byte_size: u32, values: &[(&str, u64)]) -> u32 {
            let n = self.add_string(name);
            let vlen = values.len() as u32;
            self.push_type_header(n, BTF_KIND_ENUM64, vlen, false, byte_size);
            for (vn, vv) in values {
                let vn_off = self.add_string(vn);
                self.types.extend_from_slice(&vn_off.to_le_bytes());
                let lo = (*vv & 0xFFFF_FFFF) as u32;
                let hi = (*vv >> 32) as u32;
                self.types.extend_from_slice(&lo.to_le_bytes());
                self.types.extend_from_slice(&hi.to_le_bytes());
            }
            self.next_id()
        }

        fn add_float(&mut self, name: &str, byte_size: u32) -> u32 {
            let n = self.add_string(name);
            self.push_type_header(n, BTF_KIND_FLOAT, 0, false, byte_size);
            self.next_id()
        }

        fn add_struct(&mut self, name: &str, byte_size: u32, members: &[(&str, u32, u32)]) -> u32 {
            self.add_composite(name, byte_size, members, BTF_KIND_STRUCT)
        }

        fn add_union(&mut self, name: &str, byte_size: u32, members: &[(&str, u32, u32)]) -> u32 {
            self.add_composite(name, byte_size, members, BTF_KIND_UNION)
        }

        fn add_composite(&mut self, name: &str, byte_size: u32, members: &[(&str, u32, u32)], kind: u8) -> u32 {
            let n = self.add_string(name);
            let vlen = members.len() as u32;
            self.push_type_header(n, kind, vlen, false, byte_size);
            for (m_name, m_type, bit_off) in members {
                let m_name_off = self.add_string(m_name);
                self.types.extend_from_slice(&m_name_off.to_le_bytes());
                self.types.extend_from_slice(&m_type.to_le_bytes());
                self.types.extend_from_slice(&bit_off.to_le_bytes());
            }
            self.next_id()
        }

        fn next_id(&self) -> u32 {
            // type_id starts at 1 in BTF; this returns the id of the type
            // most recently appended to `types`.
            let mut count = 0u32;
            let mut pos = 0usize;
            while pos + 12 <= self.types.len() {
                let info = u32::from_le_bytes(self.types[pos + 4..pos + 8].try_into().unwrap());
                let kind = ((info >> 24) & 0x1f) as u8;
                let vlen = (info & 0xFFFF) as usize;
                pos += 12;
                let extra = match kind {
                    BTF_KIND_INT       => 4,
                    BTF_KIND_ARRAY     => 12,
                    BTF_KIND_STRUCT    | BTF_KIND_UNION => vlen * 12,
                    BTF_KIND_ENUM      => vlen * 8,
                    BTF_KIND_ENUM64    => vlen * 12,
                    BTF_KIND_FUNC_PROTO => vlen * 8,
                    BTF_KIND_VAR       => 4,
                    BTF_KIND_DATASEC   => vlen * 12,
                    BTF_KIND_DECL_TAG  => 4,
                    _ => 0,
                };
                pos += extra;
                count += 1;
            }
            count
        }

        fn finish(&self) -> Vec<u8> {
            // header: 24 bytes
            //   magic@0, version@2, flags@3, hdr_len@4,
            //   type_off@8, type_len@12, str_off@16, str_len@20.
            let hdr_len: u32 = 24;
            let type_off: u32 = 0;
            let type_len: u32 = self.types.len() as u32;
            let str_off: u32 = type_len;
            let str_len: u32 = self.strtab.len() as u32;
            let mut out = Vec::with_capacity(24 + self.types.len() + self.strtab.len());
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&hdr_len.to_le_bytes());
            out.extend_from_slice(&type_off.to_le_bytes());
            out.extend_from_slice(&type_len.to_le_bytes());
            out.extend_from_slice(&str_off.to_le_bytes());
            out.extend_from_slice(&str_len.to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strtab);
            out
        }
    }

    #[test]
    fn parses_simple_struct() {
        let mut b = BtfBuilder::new();
        let i32_id = b.add_int("int", 4);
        let i16_id = b.add_int("short", 2);
        // struct foo { int a; short b; } — a@0, b@4 (bit offsets 0, 32).
        b.add_struct("foo", 8, &[("a", i32_id, 0), ("b", i16_id, 32)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let a = idx.resolve_field("foo", "a").unwrap();
        assert_eq!(a.offset_bytes, 0);
        assert_eq!(a.size_bytes, Some(4));

        let bf = idx.resolve_field("foo", "b").unwrap();
        assert_eq!(bf.offset_bytes, 4);
        assert_eq!(bf.size_bytes, Some(2));
    }

    #[test]
    fn resolves_typedef_and_qualifier_chain() {
        // const __be32 → __be32 → __u32 (INT 4)
        let mut b = BtfBuilder::new();
        let u32_id   = b.add_int("__u32", 4);
        let be32_id  = b.add_typedef("__be32", u32_id);
        let cbe32_id = b.add_const(be32_id);
        b.add_struct("h", 4, &[("daddr", cbe32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("h", "daddr").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, Some(4), "typedef chain must resolve to INT size");
    }

    #[test]
    fn descends_into_anonymous_nested_union() {
        // Mirrors sock_common.skc_portpair: an anonymous nested union whose
        // members must be visible from the outer struct lookup.
        // struct outer {
        //   u16 family;             // @0
        //   union {                 // @2
        //     u32 portpair;
        //     struct { u16 dport; u16 num; };
        //   } skc_portpair;
        // };
        let mut b = BtfBuilder::new();
        let u16_id = b.add_int("u16", 2);
        let u32_id = b.add_int("u32", 4);
        // Inner anonymous struct {dport@0, num@16 bits}
        let inner_struct = b.add_struct("", 4, &[
            ("dport", u16_id, 0),
            ("num",   u16_id, 16),
        ]);
        // Anonymous union: portpair (full u32) + inner anonymous struct.
        let pair_union = b.add_union("", 4, &[
            ("portpair", u32_id,        0),
            ("",         inner_struct,  0),
        ]);
        // Outer struct: family@0 (16 bits), anonymous union @ bit 16.
        b.add_struct("outer", 8, &[
            ("family", u16_id,     0),
            ("",       pair_union, 16),
        ]);
        let idx = parse_btf(&b.finish()).unwrap();

        assert_eq!(idx.resolve_field("outer", "family").unwrap().offset_bytes, 0);
        let dport = idx.resolve_field("outer", "dport").unwrap();
        assert_eq!(dport.offset_bytes, 2, "dport must inherit anon union offset");
        assert_eq!(dport.size_bytes, Some(2));
        let num = idx.resolve_field("outer", "num").unwrap();
        assert_eq!(num.offset_bytes, 4);
    }

    #[test]
    fn pointer_field_has_no_size() {
        // struct s { int *p; }
        let mut b = BtfBuilder::new();
        let i32_id = b.add_int("int", 4);
        let ptr_id = b.add_ptr(i32_id);
        b.add_struct("s", 8, &[("p", ptr_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("s", "p").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, None, "pointers have no recorded BTF size");
    }

    #[test]
    fn enum_advances_position_correctly() {
        // Tests that an ENUM with N values doesn't misalign subsequent type
        // parsing — the original parser had ENUM at the wrong kind id and
        // would skip the wrong number of bytes.
        let mut b = BtfBuilder::new();
        let _enum_id = b.add_enum("color", 4, &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
        let i32_id   = b.add_int("int", 4);
        b.add_struct("after", 4, &[("v", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("after", "v").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, Some(4));
    }

    #[test]
    fn enum64_advances_position_correctly() {
        let mut b = BtfBuilder::new();
        let _e64 = b.add_enum64("big", 8, &[("X", 0xDEADBEEF), ("Y", 0xCAFEBABE_DEADBEEF)]);
        let i32_id = b.add_int("int", 4);
        b.add_struct("after", 4, &[("v", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("after", "v").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, Some(4));
    }

    #[test]
    fn fwd_does_not_misalign_subsequent_types() {
        let mut b = BtfBuilder::new();
        let _fwd  = b.add_fwd("forward_decl");
        let i32_id = b.add_int("int", 4);
        b.add_struct("after", 4, &[("v", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("after", "v").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, Some(4));
    }

    #[test]
    fn float_advances_position_correctly() {
        let mut b = BtfBuilder::new();
        let _f64 = b.add_float("double", 8);
        let i32_id = b.add_int("int", 4);
        b.add_struct("after", 4, &[("v", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        let f = idx.resolve_field("after", "v").unwrap();
        assert_eq!(f.offset_bytes, 0);
        assert_eq!(f.size_bytes, Some(4));
    }

    #[test]
    fn missing_struct_returns_none() {
        let mut b = BtfBuilder::new();
        let i32_id = b.add_int("int", 4);
        b.add_struct("known", 4, &[("v", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        assert!(idx.resolve_field("absent", "v").is_none());
        assert!(!idx.has_struct("absent"));
        assert!(idx.has_struct("known"));
    }

    #[test]
    fn missing_field_returns_none() {
        let mut b = BtfBuilder::new();
        let i32_id = b.add_int("int", 4);
        b.add_struct("foo", 4, &[("only", i32_id, 0)]);
        let idx = parse_btf(&b.finish()).unwrap();

        assert!(idx.resolve_field("foo", "missing").is_none());
    }

    fn expect_err(r: Result<BtfIndex, String>) -> String {
        match r { Ok(_) => panic!("expected parse error"), Err(e) => e }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = vec![0u8; 64];
        data[0] = 0x12;
        data[1] = 0x34;
        let err = expect_err(parse_btf(&data));
        assert!(err.contains("magic"));
    }

    #[test]
    fn rejects_truncated_header() {
        let data = vec![0u8; 10];
        let err = expect_err(parse_btf(&data));
        assert!(err.contains("too short"));
    }

    #[test]
    fn rejects_out_of_range_sections() {
        let mut b = BtfBuilder::new();
        let _ = b.add_int("int", 4);
        let mut data = b.finish();
        // Smash str_len so str_off + str_len exceeds data size.
        let bogus: u32 = 0xFFFF_FFFF;
        data[20..24].copy_from_slice(&bogus.to_le_bytes());
        assert!(parse_btf(&data).is_err());
    }

    #[test]
    fn validate_all_reports_btf_unavailable_when_load_failed() {
        let v = BtfStructValidator { index: Err("no btf".into()) };
        let r = v.validate_all(VALIDATED_KERNEL_FIELDS);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason, "btf_unavailable");
        assert!(matches!(r[0].kind, MismatchKind::Source));
    }

    #[test]
    fn validate_all_flags_offset_size_and_missing() {
        // Synthetic "sock_common"-like struct exercising every mismatch path.
        let mut b = BtfBuilder::new();
        let _u16_id = b.add_int("__u16", 2);
        let u32_id = b.add_int("__u32", 4);
        let u64_id = b.add_int("__u64", 8);
        b.add_struct(
            "sock_common", 80,
            &[
                ("skc_daddr",  u32_id, 32),  // bit 32 = byte 4 → offset_mismatch (expected 0)
                ("skc_family", u64_id, 128), // bit 128 = byte 16, but size 8 vs expected 2 → size_mismatch
                // skc_dport intentionally absent → field_missing
            ],
        );
        let idx = parse_btf(&b.finish()).unwrap();
        let v = BtfStructValidator { index: Ok(idx) };

        let r = v.validate_all(&[
            ExpectedKernelField { struct_name: "sock_common", field: "skc_daddr",  offset: 0,  size: Some(4) },
            ExpectedKernelField { struct_name: "sock_common", field: "skc_family", offset: 16, size: Some(2) },
            ExpectedKernelField { struct_name: "sock_common", field: "skc_dport",  offset: 12, size: Some(2) },
            // Whole struct missing:
            ExpectedKernelField { struct_name: "no_such_struct", field: "x",       offset: 0,  size: Some(1) },
        ]);

        assert_eq!(r.len(), 4);
        let by_field: std::collections::HashMap<&str, &OffsetMismatch> =
            r.iter().map(|m| (m.field.as_str(), m)).collect();

        assert_eq!(by_field["skc_daddr"].reason, "offset_mismatch");
        assert_eq!(by_field["skc_daddr"].actual_offset, Some(4));

        assert_eq!(by_field["skc_family"].reason, "size_mismatch");
        assert_eq!(by_field["skc_family"].actual_offset, Some(16));
        assert_eq!(by_field["skc_family"].actual_size,   Some(8));

        assert_eq!(by_field["skc_dport"].reason, "field_missing");
        assert_eq!(by_field["skc_dport"].actual_offset, None);

        assert_eq!(by_field["x"].reason, "struct_missing");
    }

    #[test]
    fn validate_all_passes_on_correct_layout() {
        // Synthesize a sock_common that exactly matches VALIDATED_KERNEL_FIELDS.
        let mut b = BtfBuilder::new();
        let u16_id = b.add_int("__u16", 2);
        let u32_id = b.add_int("__u32", 4);
        // typedef chain for __be32 → __u32, used by skc_daddr / skc_rcv_saddr
        let be32_id = b.add_typedef("__be32", u32_id);
        // typedef chain for __be16 → __u16, used by skc_dport
        let be16_id = b.add_typedef("__be16", u16_id);
        // struct in6_addr (16 bytes)
        // struct in6_addr — only its declared byte size matters for validation;
        // a single u8 member at bit 0 keeps the BTF blob compact.
        let u8_id = b.add_int("__u8", 1);
        let bytes16_id = b.add_struct("in6_addr", 16, &[("s6_addr", u8_id, 0)]);
        // skc_portpair anon union: portpair (u32) | { dport (__be16), num (u16) }
        let inner = b.add_struct("", 4, &[
            ("skc_dport", be16_id, 0),
            ("skc_num",   u16_id,  16),
        ]);
        let portpair = b.add_union("", 4, &[
            ("skc_portpair", u32_id, 0),
            ("",             inner,  0),
        ]);
        let _sock_common = b.add_struct(
            "sock_common", 88,
            &[
                ("skc_daddr",        be32_id,    0),
                ("skc_rcv_saddr",    be32_id,    32),
                ("",                 portpair,   96),  // bit offset 12*8
                ("skc_family",       u16_id,     128), // bit offset 16*8
                ("skc_v6_daddr",     bytes16_id, 448), // bit offset 56*8
                ("skc_v6_rcv_saddr", bytes16_id, 576), // bit offset 72*8
            ],
        );
        // struct socket { struct sock *sk @ offset 24 }
        let void_ptr = b.add_ptr(0); // void pointer is fine; PTR resolves to None size
        let _socket = b.add_struct("socket", 64, &[("sk", void_ptr, 24 * 8)]);

        let idx = parse_btf(&b.finish()).unwrap();
        let v = BtfStructValidator { index: Ok(idx) };
        let r = v.validate_all(VALIDATED_KERNEL_FIELDS);
        assert!(r.is_empty(), "expected no mismatches, got {:?}", r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }
}
