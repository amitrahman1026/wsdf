use super::{protocol::*, types::*};
use epan_sys;
use std::ffi::c_int;

/// A packet dissector implementation using the new TvbRange API.
///
/// Dissectors contain the logic for analyzing packet contents and building
/// the protocol tree. The new API matches Wireshark's Lua patterns for familiarity.
///
/// # Example
///
/// ```rust
/// let dissector = Dissector::new(|tree, tvb| {
///     // Create ranges for data access. Analogous to Lua API tvb(offset, length)
///     // Reference: wslua_tvb.c Tvb_range()
///     let version_range = tvb.range(0, 1)?;
///     let header_range = tvb.range(1, 8)?;
///
///     // Add to tree using ranges. Analogous to Lua API tree:add(field, range)
///     // Reference: wslua_tree.c TreeItem_add()
///     tree.add_item("version", version_range)?;
///     let mut header_tree = tree.add("header", header_range)?;
///
///     // Extract values from ranges. Analogous to Lua API range:uint()
///     // Reference: wslua_tvb.c TvbRange_uint()
///     let version = version_range.uint8()?;
///
///     Ok(tvb.reported_length()) // Return consumed bytes
/// });
/// ```
pub struct Dissector {
    inner: Box<dyn Fn(&mut Tree, Tvb) -> Result<i32, Box<dyn std::error::Error>>>,
}

impl Dissector {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&mut Tree, Tvb) -> Result<i32, Box<dyn std::error::Error>> + 'static,
    {
        Dissector { inner: Box::new(f) }
    }

    // This is where wireshark presents a packet to the ffi interface
    pub(crate) unsafe fn process_packet(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::packet_info,
        proto_tree: *mut epan_sys::proto_tree,
        protocol: &Protocol,
    ) -> c_int {
        // There's not a guarantee that the proto_tree that will be passed in by wireshark is
        // not NULL. In the case that it is null, it is used for other validation purposes in
        // wireshark so while you can still add expert info, it seems advisable to not build
        // a tree at all. More details can be found in 2.12 Optimizations in README.dissectors
        if proto_tree.is_null() {
            return epan_sys::tvb_captured_length(tvb) as i32;
        }

        let tree_result = Tree::new(protocol, pinfo, proto_tree, tvb, 0);
        match tree_result {
            Ok((mut tree, tvb_wrapper)) => {
                match (self.inner)(&mut tree, tvb_wrapper) {
                    Ok(consumed) => consumed,
                    Err(_) => 0, // Error in dissection
                }
            }
            Err(_) => 0, // Error creating tree
        }
    }
}

/// Immutable reference to packet data - matches C tvbuff_t*
/// This represents a view into packet data without any dissector state
#[derive(Clone, Copy)]
pub struct Tvb {
    ptr: *mut epan_sys::tvbuff,
}

impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self { ptr }
    }

    /// Get the total reported length of this TVB
    pub fn reported_length(&self) -> i32 {
        unsafe { epan_sys::tvb_reported_length(self.ptr) as i32 }
    }

    /// Get the captured length of this TVB
    pub fn captured_length(&self) -> i32 {
        unsafe { epan_sys::tvb_captured_length(self.ptr) as i32 }
    }

    /// Get remaining reported length from offset
    pub fn reported_length_remaining(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_reported_length_remaining(self.ptr, offset) }
    }

    /// Get remaining captured length from offset
    pub fn captured_length_remaining(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_captured_length_remaining(self.ptr, offset) }
    }

    /// Create a TvbRange from this TVB. Analogous to Lua API tvb(offset, length)
    /// Reference: wslua_tvb.c Tvb_range()
    pub fn range(&self, offset: i32, length: i32) -> Result<TvbRange, TvbError> {
        if offset < 0 {
            return Err(TvbError::InvalidRange);
        }

        let actual_length = if length == -1 {
            self.reported_length_remaining(offset)
        } else {
            if length < 0 {
                return Err(TvbError::InvalidRange);
            }
            length
        };

        if actual_length < 0 {
            return Err(TvbError::OutOfBounds);
        }

        if offset + actual_length > self.reported_length() {
            return Err(TvbError::OutOfBounds);
        }

        Ok(TvbRange {
            tvb: *self,
            offset,
            length: actual_length,
        })
    }

    /// Create a range covering the entire TVB
    pub fn range_all(&self) -> TvbRange {
        TvbRange {
            tvb: *self,
            offset: 0,
            length: self.reported_length(),
        }
    }

    /// Create subset TVB with specified length
    pub fn subset_length(&self, offset: i32, length: i32) -> Result<Tvb, TvbError> {
        unsafe {
            let tvb = epan_sys::tvb_new_subset_length(self.ptr, offset, length);
            if tvb.is_null() {
                Err(TvbError::SubsetFailed)
            } else {
                Ok(Tvb { ptr: tvb })
            }
        }
    }

    /// Create subset TVB from offset to end
    pub fn subset_remaining(&self, offset: i32) -> Result<Tvb, TvbError> {
        unsafe {
            let tvb = epan_sys::tvb_new_subset_remaining(self.ptr, offset);
            if tvb.is_null() {
                Err(TvbError::SubsetFailed)
            } else {
                Ok(Tvb { ptr: tvb })
            }
        }
    }

    /// Create child TVB with new data
    pub unsafe fn new_child_real_data(
        &self,
        data: *const u8,
        length: u32,
        reported_length: u32,
    ) -> Result<Tvb, TvbError> {
        let tvb = epan_sys::tvb_new_child_real_data(
            self.ptr,
            data as *mut u8,
            length,
            reported_length as i32,
        );

        if tvb.is_null() {
            Err(TvbError::SubsetFailed)
        } else {
            Ok(Tvb { ptr: tvb })
        }
    }

    /// Get raw pointer to data (unsafe)
    pub unsafe fn get_ptr(&self, offset: i32, length: i32) -> *const u8 {
        epan_sys::tvb_get_ptr(self.ptr, offset, length)
    }

    /// Internal getter for the raw pointer
    pub(crate) fn as_ptr(&self) -> *mut epan_sys::tvbuff {
        self.ptr
    }
}

/// Lightweight view into a TVB. Analogous to Lua API TvbRange concept
/// Reference: wslua_tvb.c TvbRange struct and methods
/// This is where the actual data extraction happens
#[derive(Clone, Copy)]
pub struct TvbRange {
    tvb: Tvb,
    offset: i32,
    length: i32,
}

impl TvbRange {
    /// Get the underlying TVB
    pub fn tvb(&self) -> Tvb {
        self.tvb
    }

    /// Get the offset within the TVB
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Get the length of this range
    pub fn length(&self) -> i32 {
        self.length
    }

    /// Create a sub-range within this range
    pub fn range(&self, offset: i32, length: i32) -> Result<TvbRange, TvbError> {
        if offset < 0 {
            return Err(TvbError::InvalidRange);
        }

        let actual_length = if length == -1 {
            self.length - offset
        } else {
            if length < 0 {
                return Err(TvbError::InvalidRange);
            }
            length
        };

        if actual_length < 0 || offset + actual_length > self.length {
            return Err(TvbError::OutOfBounds);
        }

        Ok(TvbRange {
            tvb: self.tvb,
            offset: self.offset + offset,
            length: actual_length,
        })
    }

    /// Extract uint8 from this range. Analogous to Lua API TvbRange:uint()
    /// Reference: wslua_tvb.c TvbRange_uint()
    pub fn uint8(&self) -> Result<u8, TvbError> {
        if self.length < 1 {
            return Err(TvbError::InvalidLength {
                expected: 1,
                actual: self.length,
            });
        }
        unsafe { Ok(epan_sys::tvb_get_uint8(self.tvb.ptr, self.offset)) }
    }

    /// Extract uint16 with endianness
    pub fn uint16(&self, encoding: Encoding) -> Result<u16, TvbError> {
        if self.length < 2 {
            return Err(TvbError::InvalidLength {
                expected: 2,
                actual: self.length,
            });
        }
        unsafe {
            let value = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohs(self.tvb.ptr, self.offset),
                Encoding::LittleEndian => epan_sys::tvb_get_letohs(self.tvb.ptr, self.offset),
                _ => return Err(TvbError::InvalidEncoding),
            };
            Ok(value)
        }
    }

    /// Extract uint32 with endianness
    pub fn uint32(&self, encoding: Encoding) -> Result<u32, TvbError> {
        if self.length < 4 {
            return Err(TvbError::InvalidLength {
                expected: 4,
                actual: self.length,
            });
        }
        unsafe {
            let value = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohl(self.tvb.ptr, self.offset),
                Encoding::LittleEndian => epan_sys::tvb_get_letohl(self.tvb.ptr, self.offset),
                _ => return Err(TvbError::InvalidEncoding),
            };
            Ok(value)
        }
    }

    /// Get raw bytes as Vec. Analogous to Lua API TvbRange:bytes()
    /// Reference: wslua_tvb.c TvbRange_bytes()
    pub fn bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = epan_sys::tvb_get_ptr(self.tvb.ptr, self.offset, self.length);
            std::slice::from_raw_parts(ptr, self.length as usize).to_vec()
        }
    }

    /// Create subset TVB from this range. Analogous to Lua API TvbRange:tvb()
    /// Reference: wslua_tvb.c TvbRange_tvb()
    pub fn to_tvb(&self) -> Result<Tvb, TvbError> {
        self.tvb.subset_length(self.offset, self.length)
    }

    /// Get string with encoding. Analogous to Lua API TvbRange:string()
    /// Reference: wslua_tvb.c TvbRange_string()
    pub fn string(&self, encoding: Encoding) -> Result<String, TvbError> {
        let bytes = self.bytes();
        match encoding {
            Encoding::UTF8 => String::from_utf8(bytes).map_err(|_| TvbError::InvalidEncoding),
            Encoding::ASCII7Bits => {
                // Convert ASCII bytes to string
                if bytes.iter().all(|&b| b <= 127) {
                    Ok(String::from_utf8_lossy(&bytes).to_string())
                } else {
                    Err(TvbError::InvalidEncoding)
                }
            }
            _ => Err(TvbError::InvalidEncoding), // TODO: Add more encoding support
        }
    }

    /// Check if bytes exist without throwing. Analogous to Lua API bounds checking
    /// Reference: wslua_tvb.c push_TvbRange() bounds validation
    pub fn bytes_exist(&self) -> bool {
        unsafe { epan_sys::tvb_bytes_exist(self.tvb.ptr, self.offset, self.length) }
    }
}

#[derive(Clone, Copy)]
pub struct PacketInfo {
    ptr: *mut epan_sys::_packet_info,
}
impl PacketInfo {
    pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
        Self { ptr }
    }
    // This raw pointer is managed by the block allocator of wmem
    pub unsafe fn alloc_string(&self, s: &str) -> *const i8 {
        let c_str = std::ffi::CString::new(s).expect("msg");
        unsafe {
            let size = s.len() + 1; // +1 for null terminator
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, size) as *mut i8;
            std::ptr::copy_nonoverlapping(c_str.as_ptr(), ptr, size);
            ptr
        }
    }
    pub unsafe fn alloc_bytes(&self, bytes: &[u8]) -> *mut u8 {
        unsafe {
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, bytes.len()) as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            ptr
        }
    }
    pub fn set_column_text(&self, col: Column, text: &str) {
        unsafe {
            let text = self.alloc_string(text);
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
            epan_sys::col_add_str((*self.ptr).cinfo, col as i32, text);
        }
    }
    pub fn clear_column(&self, col: Column) {
        unsafe {
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
        }
    }
    pub unsafe fn add_data_source(&self, tvb: &Tvb, name: &str) {
        let name = self.alloc_string(name);
        epan_sys::add_new_data_source(self.ptr, tvb.as_ptr(), name);
    }
}

/// Tree represents a protocol tree node that can have children added to it.
/// Analogous to Lua API TreeItem concept - it's both an item and potential container
/// Reference: wslua_tree.c TreeItem struct and methods
pub struct Tree<'a> {
    protocol: &'a Protocol,
    pub pinfo: PacketInfo,
    current_node: *mut epan_sys::proto_node, // The subtree for adding children to
    current_item: *mut epan_sys::proto_item, // The item itself
}

impl<'a> Tree<'a> {
    /// Create the root tree for a protocol dissector
    /// This should be called at the start of dissection
    pub(crate) unsafe fn new(
        protocol: &'a Protocol,
        pinfo: *mut epan_sys::packet_info,
        parent: *mut epan_sys::proto_node,
        tvb: *mut epan_sys::tvbuff,
        offset: i32,
    ) -> TreeResult<(Self, Tvb)> {
        let item = epan_sys::proto_tree_add_item(
            parent,
            protocol.get_proto_handle(),
            tvb,
            offset,
            -1,
            epan_sys::ENC_NA,
        );

        if item.is_null() {
            return Err(TreeError::AddItemFailed(
                "Failed to create root item".into(),
            ));
        }

        let ett_handle = protocol
            .get_ett_handle(ROOT_ETT_ID)
            .ok_or(TreeError::EttNotFound(format!(
                "Ett '{}' not found",
                ROOT_ETT_ID
            )))?;

        // The actual subtree for display
        let current = epan_sys::proto_item_add_subtree(item, ett_handle);

        if current.is_null() {
            return Err(TreeError::InvalidSubtreeOperation(
                "Failed to create root subtree".into(),
            ));
        }

        let tree = Self {
            protocol,
            pinfo: PacketInfo::new(pinfo),
            current_node: current,
            current_item: item,
        };

        let tvb_wrapper = Tvb::new(tvb);

        Ok((tree, tvb_wrapper))
    }
    /// Add child item to tree using TvbRange. Analogous to Lua API tree:add(field, range)
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add(&mut self, field_id: &str, range: TvbRange) -> TreeResult<Tree<'a>> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                epan_sys::ENC_NA,
            );

            if item.is_null() {
                return Err(TreeError::AddItemFailed(format!(
                    "Failed to create item for field '{}'",
                    field_id
                )));
            }

            // Get the field's ETT for creating subtree (or use a default)
            let ett_handle = self
                .protocol
                .get_ett_handle(&format!("{}_ett", field_id))
                .or_else(|| self.protocol.get_ett_handle(ROOT_ETT_ID))
                .ok_or(TreeError::EttNotFound("No suitable ETT found".into()))?;

            // Convert item to subtree (Lua pattern!)
            let subtree = epan_sys::proto_item_add_subtree(item, ett_handle);

            Ok(Tree {
                protocol: self.protocol,
                pinfo: self.pinfo,
                current_node: subtree,
                current_item: item,
            })
        }
    }

    /// Add child item with specific encoding. Analogous to Lua API tree:add(field, range, encoding)
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add_with_encoding(
        &mut self,
        field_id: &str,
        range: TvbRange,
        encoding: Encoding,
    ) -> TreeResult<Tree<'a>> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                encoding.to_u32(),
            );

            if item.is_null() {
                return Err(TreeError::AddItemFailed(format!(
                    "Failed to create item for field '{}'",
                    field_id
                )));
            }

            // Get the field's ETT for creating subtree
            let ett_handle = self
                .protocol
                .get_ett_handle(&format!("{}_ett", field_id))
                .or_else(|| self.protocol.get_ett_handle(ROOT_ETT_ID))
                .ok_or(TreeError::EttNotFound("No suitable ETT found".into()))?;

            // Convert item to subtree (Lua pattern!)
            let subtree = epan_sys::proto_item_add_subtree(item, ett_handle);

            Ok(Tree {
                protocol: self.protocol,
                pinfo: self.pinfo,
                current_node: subtree,
                current_item: item,
            })
        }
    }

    /// Add item and return TreeItem for expert info, text setting, etc.
    /// Analogous to Lua API tree:add() returning a TreeItem
    /// Reference: wslua_tree.c TreeItem_add()
    pub fn add_item(&mut self, field_id: &str, range: TvbRange) -> TreeResult<TreeItem> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                epan_sys::ENC_NA,
            );

            if item.is_null() {
                return Err(TreeError::AddItemFailed(format!(
                    "Failed to create item for field '{}'",
                    field_id
                )));
            }

            Ok(TreeItem::new(item, self.pinfo))
        }
    }

    /// Add item with encoding and return TreeItem
    pub fn add_item_with_encoding(
        &mut self,
        field_id: &str,
        range: TvbRange,
        encoding: Encoding,
    ) -> TreeResult<TreeItem> {
        let field_handle = self
            .protocol
            .get_field_handle(field_id)
            .ok_or_else(|| TreeError::AddItemFailed(format!("Field '{}' not found", field_id)))?;

        if !range.bytes_exist() {
            return Err(TreeError::AddItemFailed(
                "TvbRange extends beyond packet data".into(),
            ));
        }

        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                field_handle.handle,
                range.tvb.as_ptr(),
                range.offset,
                range.length,
                encoding.to_u32(),
            );

            if item.is_null() {
                return Err(TreeError::AddItemFailed(format!(
                    "Failed to create item for field '{}'",
                    field_id
                )));
            }

            Ok(TreeItem::new(item, self.pinfo))
        }
    }
    pub fn add_expert_info(
        &mut self,
        item: &mut TreeItem,
        expert_id: &str,
        text: Option<&str>,
    ) -> Result<(), ExpertError> {
        let handle = self
            .protocol
            .get_expert_field(expert_id)
            .ok_or_else(|| ExpertError::FieldNotFound(expert_id.to_string()))?;

        unsafe {
            let mut expert_field = epan_sys::expert_field {
                ei: handle.ei,
                hf: handle.hf,
            };
            if let Some(text) = text {
                // Custom text
                let text_ptr = self.pinfo.alloc_string(text);
                epan_sys::expert_add_info_format(
                    self.pinfo.ptr,
                    item.as_ptr(),
                    &mut expert_field as *mut epan_sys::expert_field,
                    text_ptr,
                );
            } else {
                // Default text from registration
                epan_sys::expert_add_info(
                    self.pinfo.ptr,
                    item.as_ptr(),
                    &mut expert_field as *mut epan_sys::expert_field,
                );
            }
        }
        Ok(())
    }
    /// Set custom text on tree item
    pub fn set_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_set_text(self.current_item, text_ptr);
        }
    }

    /// Append text to tree item
    pub fn append_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_append_text(self.current_item, text_ptr);
        }
    }

    /// Set the length of this tree item (rarely needed with TvbRange)
    pub fn set_length(&mut self, length: i32) {
        unsafe {
            epan_sys::proto_item_set_len(self.current_item, length);
        }
    }

    /// Transform data from TvbRange (for decompression, decoding, etc.)
    pub fn transform_data(
        &self,
        range: TvbRange,
        transform_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
        name: &str,
    ) -> Result<Tvb, Box<dyn std::error::Error>> {
        let src_data = range.bytes();
        let dst_data = transform_fn(&src_data)?;

        unsafe {
            // Allocate memory for the lifetime of the packet
            let dst_ptr = self.pinfo.alloc_bytes(&dst_data);
            let next_tvb = range.tvb.new_child_real_data(
                dst_ptr,
                dst_data.len() as u32,
                dst_data.len() as u32,
            )?;

            self.pinfo.add_data_source(&next_tvb, name);

            Ok(next_tvb)
        }
    }
}

/// TreeItem represents a single protocol item in the tree
/// Used for setting text, adding expert info, etc.
#[derive(Clone, Copy)]
pub struct TreeItem {
    ptr: *mut epan_sys::proto_item,
    pub pinfo: PacketInfo,
}

impl TreeItem {
    pub(crate) fn new(ptr: *mut epan_sys::proto_item, pinfo: PacketInfo) -> Self {
        Self { ptr, pinfo }
    }

    /// Set custom text on this item
    pub fn set_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_set_text(self.ptr, text_ptr);
        }
    }

    /// Append text to this item
    pub fn append_text(&mut self, text: &str) {
        unsafe {
            let text_ptr = self.pinfo.alloc_string(text);
            epan_sys::proto_item_append_text(self.ptr, text_ptr);
        }
    }

    /// Set the length of this item
    pub fn set_length(&mut self, length: i32) {
        unsafe {
            epan_sys::proto_item_set_len(self.ptr, length);
        }
    }

    /// Internal getter for FFI
    pub(crate) fn as_ptr(&self) -> *mut epan_sys::proto_item {
        self.ptr
    }
}
