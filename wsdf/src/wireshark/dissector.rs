use super::{protocol::*, types::*};
use epan_sys;
use std::ffi::c_int;

pub struct Dissector {
    inner: Box<dyn Fn(&mut Tree) -> i32>,
}

impl Dissector {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&mut Tree) -> i32 + 'static,
    {
        Dissector { inner: Box::new(f) }
    }

    // This is where wireshark presents a packet to the ffi interface
    pub unsafe fn dispatch(
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
        let mut tree = Tree::new(protocol, pinfo, proto_tree, tvb, 0);
        (self.inner)(&mut tree)
    }
}

// WIP: Data structures needed to support the object oriented API
#[derive(Clone, Copy)]
pub struct Tvb {
    ptr: *mut epan_sys::tvbuff,
    pub start: i32,
    pub offset: i32,
}
impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self {
            ptr,
            start: 0,
            offset: 0,
        }
    }
    pub unsafe fn get_ptr(&self, offset: i32, length: i32) -> *const u8 {
        epan_sys::tvb_get_ptr(self.ptr, offset, length)
    }

    // The get_DATA() type functions should do the book keeping required for the underlying managed buffer

    pub fn get_uint8(&mut self, _offset: i32) -> u8 {
        unsafe {
            let ret = epan_sys::tvb_get_uint8(self.ptr, self.offset);
            self.offset += 1;
            ret
        }
    }

    pub fn get_uint16(&mut self, _offset: i32, encoding: Encoding) -> u16 {
        unsafe {
            let ret = match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohs(self.ptr, self.offset),
                // everything that is not Big Endian (enc as 0) is Litte endian in wireshark
                _ => epan_sys::tvb_get_letohs(self.ptr, self.offset),
            };
            self.offset += 2;
            ret
        }
    }
    pub unsafe fn new_child_real_data(
        &self,
        data: *const u8,
        length: u32,
        reported_length: u32,
    ) -> Option<Tvb> {
        let tvb = epan_sys::tvb_new_child_real_data(
            self.ptr,
            data as *mut u8,
            length,
            reported_length as i32,
        );

        if !tvb.is_null() {
            Some(Tvb::new(tvb))
        } else {
            None
        }
    }
    pub unsafe fn new_subset_remaining(&self, offset: i32) -> Option<Tvb> {
        let tvb = epan_sys::tvb_new_subset_remaining(self.ptr, offset);
        if !tvb.is_null() {
            Some(Tvb::new(tvb))
        } else {
            None
        }
    }
    pub fn length(&self) -> i32 {
        unsafe { epan_sys::tvb_reported_length(self.ptr) as i32 }
    }
    pub fn remaining_length(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_captured_length_remaining(self.ptr, offset) }
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
    pub unsafe fn alloc_raw_string(&self, s: &str) -> *const i8 {
        let c_str = std::ffi::CString::new(s).unwrap();
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
            let text = self.alloc_raw_string(text);
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
        let name = self.alloc_raw_string(name);
        epan_sys::add_new_data_source(self.ptr, tvb.ptr, name);
    }
}

pub struct Tree<'a> {
    protocol: &'a Protocol,
    pub pinfo: PacketInfo,
    pub tvb: Tvb,
    current_node: *mut epan_sys::proto_node,
    current_item: *mut epan_sys::proto_item,
}

impl<'a> Tree<'a> {
    // This should be called before top level dissector function, when the whole packet is first dissected
    unsafe fn new(
        protocol: &'a Protocol,
        pinfo: *mut epan_sys::packet_info,
        parent: *mut epan_sys::proto_node,
        tvb: *mut epan_sys::tvbuff,
        offset: i32,
    ) -> Self {
        let item = epan_sys::proto_tree_add_item(
            parent,
            protocol.get_proto_handle(),
            tvb,
            offset,
            -1,
            epan_sys::ENC_NA,
        );
        // The actual subtree for display
        let current = epan_sys::proto_item_add_subtree(item, protocol.get_ett_handle(ROOT_ETT_ID));

        Self {
            protocol,
            pinfo: PacketInfo::new(pinfo),
            tvb: Tvb::new(tvb),
            current_node: current,
            current_item: item,
        }
    }
    pub fn get_reported_length(&self) -> i32 {
        unsafe { epan_sys::tvb_reported_length(self.tvb.ptr) as i32 }
    }
    pub fn add_subtree(&mut self, field_id: &str, ett_id: &str) -> Option<Tree<'a>> {
        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                self.protocol.get_field_handle(field_id)?.handle,
                self.tvb.ptr,
                self.tvb.offset, // New subtrees should be added at the current offset of the parent subtree's tvb
                0,               // Length will be set when sub tree is ended
                epan_sys::ENC_NA,
            );

            let subtree =
                epan_sys::proto_item_add_subtree(item, self.protocol.get_ett_handle(ett_id));

            Some(Tree {
                protocol: self.protocol,
                pinfo: self.pinfo,
                tvb: self.tvb,
                current_node: subtree,
                current_item: item,
            })
        }
    }

    pub fn end_subtree(&mut self, subtree: &Tree) {
        let length = subtree.tvb.offset - subtree.tvb.start;
        unsafe {
            epan_sys::proto_item_set_len(subtree.current_item, length);
        }
        self.tvb.offset = subtree.tvb.offset;
    }

    // Adds an item to the start offset of the tree, and increment the current offset by length
    // Returns a TreeItem that offers a view on the "section" the item looks at
    pub fn add_item(
        &mut self,
        field_id: &str,
        length: i32,
        encoding: Encoding,
    ) -> Option<TreeItem> {
        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                self.protocol.get_field_handle(field_id)?.handle,
                self.tvb.ptr,
                self.tvb.offset,
                length,
                encoding.to_u32(),
            );

            let item_tvb = Tvb {
                ptr: self.tvb.ptr,
                start: self.tvb.offset,
                offset: self.tvb.offset,
            }; // the item's tvb should be starting at the offset

            self.tvb.offset += length;

            if !item.is_null() {
                Some(TreeItem::new(item, self.pinfo, item_tvb))
            } else {
                None
            }
        }
    }
    pub fn add_expert_info(
        &mut self,
        item: &mut TreeItem,
        expert_id: &str,
        text: Option<&str>,
    ) -> Option<()> {
        let handle = self.protocol.get_expert_field(expert_id)?;

        unsafe {
            let mut expert_field = epan_sys::expert_field {
                ei: handle.ei,
                hf: handle.hf,
            };
            if let Some(text) = text {
                // Custom text
                let text_ptr = self.pinfo.alloc_raw_string(text);
                epan_sys::expert_add_info_format(
                    self.pinfo.ptr,
                    item.ptr,
                    &mut expert_field as *mut epan_sys::expert_field,
                    text_ptr,
                );
            } else {
                // Default text from registration
                epan_sys::expert_add_info(
                    self.pinfo.ptr,
                    item.ptr,
                    &mut expert_field as *mut epan_sys::expert_field,
                );
            }
        }
        Some(())
    }
    // New Tree with a different TVB buffer but within same protocol context
    pub unsafe fn with_tvb(&self, tvb: Tvb) -> Self {
        Self {
            protocol: self.protocol,
            pinfo: self.pinfo,
            tvb,
            current_node: self.current_node,
            current_item: self.current_item,
        }
    }
    // Provide users a way for users to be able to pass in a closure to transform data
    // e.g. Decompression, decryption etc.
    pub fn transform_data(
        &mut self,
        length: u32,
        transform_fn: impl FnOnce(&[u8], &mut [u8]) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Option<Tree<'a>> {
        unsafe {
            let src_ptr = self.tvb.get_ptr(self.tvb.offset, -1);
            let src_len = self.tvb.remaining_length(self.tvb.offset) as usize;
            let src_data = std::slice::from_raw_parts(src_ptr, src_len);

            // This allocates memory for the lifetime of the packet.
            let dst_ptr = self.pinfo.alloc_bytes(&vec![0; length as usize]);
            let dst_data = std::slice::from_raw_parts_mut(dst_ptr, length as usize);

            if transform_fn(src_data, dst_data).is_err() {
                return None;
            }

            let next_tvb = self.tvb.new_child_real_data(dst_ptr, length, length)?;

            self.pinfo.add_data_source(&next_tvb, "Transformed Data");

            Some(self.with_tvb(next_tvb))
        }
    }
}

#[derive(Clone, Copy)]
pub struct TreeItem {
    ptr: *mut epan_sys::proto_item,
    pub pinfo: PacketInfo,
    pub tvb: Tvb,
}

impl TreeItem {
    pub(crate) fn new(ptr: *mut epan_sys::proto_item, pinfo: PacketInfo, tvb: Tvb) -> Self {
        Self { ptr, pinfo, tvb }
    }
    pub fn set_text(&mut self, text: &str) {
        unsafe {
            let text = self.pinfo.alloc_raw_string(text);
            epan_sys::proto_item_set_text(self.ptr, text);
        }
    }

    pub fn append_text(&mut self, text: &str) {
        unsafe {
            let text = self.pinfo.alloc_raw_string(text);
            epan_sys::proto_item_append_text(self.ptr, text);
        }
    }
}
