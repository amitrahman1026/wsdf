use quote::{format_ident, quote};
use syn::{parse_quote, punctuated::Punctuated};

use crate::util::*;

/// Implement this for things which can extract options out of meta items.
pub(crate) trait OptionBuilder {
    fn add_option(&mut self, meta: &syn::Meta) -> syn::Result<()>;
}

/// Initializes some set of options from a list of attributes. Note that each attribute may contain
/// multiple meta items, but each meta item should map to exactly one option.
pub(crate) fn init_options<T>(attrs: &[syn::Attribute]) -> syn::Result<T>
where
    T: OptionBuilder + Default,
{
    let mut opts = T::default();
    // Not all attributes are wsdf attributes, so we need to filter them out first.
    let meta_items = get_meta_items(get_wsdf_attrs(attrs).as_slice())?;
    for meta in &meta_items {
        opts.add_option(meta)?;
    }
    Ok(opts)
}

/// Options for the top level protocol.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProtocolOptions {
    /// The dissector table(s) to register the protocol to.
    pub(crate) decode_from: Vec<DecodeFrom>,
    pub(crate) proto_desc: Option<String>,
    pub(crate) proto_name: Option<String>,
    pub(crate) proto_filter: Option<String>,
}

/// Options for anything which can derive ProtocolField.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProtocolFieldOptions {
    pub(crate) pre_dissect: Vec<syn::Path>,
    pub(crate) post_dissect: Vec<syn::Path>,
}

/// Options for a field. A field may be a named field or a unit tuple element, in a struct or an
/// enum variant.
#[derive(Debug, Clone, Default)]
pub(crate) struct FieldOptions {
    pub(crate) hidden: Option<bool>,
    /// An identifier for an integer field which is used to determine the size of this field. Only
    /// used by vector types to denote their number of elements.
    pub(crate) size_hint: Option<syn::Ident>,
    /// Wireshark type, e.g. "FT_UINT8".
    pub(crate) ws_type: Option<String>,
    /// Wireshark encoding option, e.g. "ENC_LITTLE_ENDIAN".
    pub(crate) ws_enc: Option<String>,
    /// Wireshark display hint, e.g. "BASE_HEX".
    pub(crate) ws_display: Option<FieldDisplayPair>,
    /// For enum fields only. An identifier for a previous field which is used to determine the
    /// variant to decode as.
    pub(crate) get_variant: Option<syn::Path>,
    pub(crate) taps: Vec<syn::Path>,
    /// Path to a custom function to decode this field.
    pub(crate) decode_with: Option<syn::Path>,
    /// Path to a custom function to consume (and decode) this field. The difference between
    /// `decode_with` and `consume_with` is that `decode_with` expects the size of the field to be
    /// known before we reach it, while `consume_with` will pass the entire packet to the function,
    /// and let it figure out the size.
    ///
    /// This is necessary for certain protocols, e.g. those which use TLV encoding.
    pub(crate) consume_with: Option<syn::Path>,
    pub(crate) subdissector: Option<Subdissector>,
    /// Custom name for the field.
    pub(crate) rename: Option<String>,
    pub(crate) save: Option<bool>,
    pub(crate) bytes: Option<bool>,
}

/// Options for an enum variant.
#[derive(Debug, Clone, Default)]
pub(crate) struct VariantOptions {
    /// Custom name for the variant.
    pub(crate) rename: Option<String>,
    pub(crate) pre_dissect: Vec<syn::Path>,
    pub(crate) post_dissect: Vec<syn::Path>,
}

/// We differentiate between "regular" subdissector tables (those which have a name and a pattern,
/// e.g "udp.port" 1234) and "decode as" subdissectors, which only have a name.
///
/// This is not an actual dichotomy in Wireshark. For example, "regular" dissectors can also be
/// used in a "decode as" way. We may want to support this in the future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Subdissector {
    DecodeAs(String),
    Table {
        table_name: String,
        /// A list of fields to try, in order, when finding the subdissector to use.
        fields: Vec<syn::Ident>,
        typ: SubdissectorTableType,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubdissectorTableType {
    Uint {
        ws_type: Box<syn::Path>,
        ws_display: Box<syn::Expr>,
    },
    Str,
    /// This is meant to be used as a temporary state while we're parsing the attributes and don't
    /// have enough information to determine the type yet.
    Unknown,
}

/// The subdissector table to register with.
#[derive(Debug, Clone)]
pub(crate) enum DecodeFrom {
    DecodeAs(String),
    Uint(String, Vec<u32>),
}

impl DecodeFrom {
    pub(crate) fn to_tokens(&self) -> proc_macro2::TokenStream {
        match self {
            DecodeFrom::DecodeAs(value) => {
                let value_cstr: syn::Expr = cstr!(value);
                quote! {
                    wsdf::epan_sys::dissector_add_for_decode_as(#value_cstr, handle);
                }
            }
            DecodeFrom::Uint(name, pattern) => {
                let name_cstr: syn::Expr = cstr!(name);
                quote! {#(
                    wsdf::epan_sys::dissector_add_uint(
                        #name_cstr,
                        #pattern as std::ffi::c_uint,
                        handle,
                    );
                )*}
            }
        }
    }
}

impl OptionBuilder for ProtocolOptions {
    fn add_option(&mut self, meta: &syn::Meta) -> syn::Result<()> {
        match meta {
            syn::Meta::NameValue(nv) => match nv.path.get_ident() {
                None => return make_err(meta, "expected identifier"),
                Some(ident) => match ident.to_string().as_str() {
                    META_DECODE_FROM => self.extract_decode_from(nv, meta)?,
                    META_PROTO_DESC => {
                        let proto_desc = get_lit_str(&nv.value)?.value();
                        self.proto_desc = Some(proto_desc);
                    }
                    META_PROTO_NAME => {
                        let proto_name = get_lit_str(&nv.value)?.value();
                        self.proto_name = Some(proto_name);
                    }
                    META_PROTO_FILTER => {
                        let proto_filter = get_lit_str(&nv.value)?.value();
                        self.proto_filter = Some(proto_filter);
                    }
                    // These meta items belong to ProtocolFieldOptions. But they may appear in
                    // the same list of attributes, e.g.
                    //
                    // #[derive(Protocol)]
                    // #[wsdf(decode_from = "udp.port", pre_dissect = "f")]
                    // struct SomeProto {
                    //   x: u16,
                    // }
                    //
                    // Because we have Protocol : ProtocolField and they all share the same
                    // #[wsdf(...)] look.
                    META_PRE_DISSECT | META_POST_DISSECT => (),
                    _ => return make_err(meta, "unrecognized attribute"),
                },
            },
            _ => return make_err(meta, "unexpected meta item"),
        };
        Ok(())
    }
}

impl OptionBuilder for ProtocolFieldOptions {
    fn add_option(&mut self, meta: &syn::Meta) -> syn::Result<()> {
        match meta {
            syn::Meta::NameValue(nv) => match nv.path.get_ident() {
                None => return make_err(meta, "expected identifier"),
                Some(ident) => match ident.to_string().as_str() {
                    META_PRE_DISSECT => self.pre_dissect = parse_strings(&nv.value)?,
                    META_POST_DISSECT => self.post_dissect = parse_strings(&nv.value)?,
                    // These meta items belong to ProtocolOptions. But they may appear in the same
                    // list of attributes.
                    META_PROTO_DESC | META_PROTO_NAME | META_PROTO_FILTER | META_DECODE_FROM => (),
                    _ => return make_err(meta, "unrecognized attribute"),
                },
            },
            _ => return make_err(meta, "unexpected meta item"),
        }
        Ok(())
    }
}

impl ProtocolOptions {
    fn extract_decode_from(
        &mut self,
        nv: &syn::MetaNameValue,
        meta: &syn::Meta,
    ) -> Result<(), syn::Error> {
        let items = unpack_expr(&nv.value);
        for item in items {
            match unpack_expr(item).as_slice() {
                [] => return make_err(meta, "expected at least one item"),
                [name] => {
                    let decode_from = get_lit_str(name)?.value();
                    self.decode_from.push(DecodeFrom::DecodeAs(decode_from));
                }
                [name, xs @ ..] => {
                    let name = get_lit_str(name)?.value();
                    let mut patterns: Vec<u32> = Vec::with_capacity(xs.len());
                    for x in xs {
                        let pattern = get_lit_int(x)?.base10_parse()?;
                        patterns.push(pattern);
                    }
                    self.decode_from.push(DecodeFrom::Uint(name, patterns));
                }
            }
        }
        Ok(())
    }
}

impl OptionBuilder for FieldOptions {
    fn add_option(&mut self, meta: &syn::Meta) -> syn::Result<()> {
        match meta {
            syn::Meta::Path(path) => match path.get_ident() {
                None => return make_err(meta, "expected identifier"),
                Some(ident) => match ident.to_string().as_str() {
                    META_HIDE => self.hidden = Some(true),
                    META_SAVE => self.save = Some(true),
                    META_BYTES => self.bytes = Some(true),
                    _ => return make_err(meta, "unrecognized attribute"),
                },
            },
            syn::Meta::NameValue(nv) => match nv.path.get_ident() {
                None => return make_err(meta, "expected identifier"),
                Some(ident) => match ident.to_string().as_str() {
                    META_HIDE => {
                        let hidden = get_lit_bool(&nv.value)?.value;
                        self.hidden = Some(hidden);
                    }
                    META_SAVE => {
                        let save = get_lit_bool(&nv.value)?.value;
                        self.save = Some(save);
                    }
                    META_LEN => {
                        let len = get_lit_str(&nv.value)?.value();
                        self.size_hint = Some(format_ident!("{}", len));
                    }
                    META_WS_TYPE => {
                        let ws_type = get_lit_str(&nv.value)?.value();
                        self.ws_type = Some(ws_type);
                    }
                    META_WS_ENC => {
                        let ws_enc = get_lit_str(&nv.value)?.value();
                        self.ws_enc = Some(ws_enc);
                    }
                    META_WS_DISPLAY => self.extract_ws_display(nv)?,
                    META_GET_VARIANT => {
                        let get_variant = get_lit_str(&nv.value)?.value();
                        let path = syn::parse_str::<syn::Path>(&get_variant)?;
                        self.get_variant = Some(path);
                    }
                    META_DECODE_WITH => {
                        let decode_with = get_lit_str(&nv.value)?.value();
                        self.decode_with = Some(syn::parse_str::<syn::Path>(&decode_with)?);
                    }
                    META_TAP => self.taps = parse_strings(&nv.value)?,
                    META_CONSUME_WITH => {
                        let consume_with = get_lit_str(&nv.value)?.value();
                        let path = syn::parse_str::<syn::Path>(&consume_with)?;
                        self.consume_with = Some(path);
                    }
                    META_SUBDISSECTOR => self.extract_subdissector(nv, meta)?,
                    META_RENAME => {
                        let rename = get_lit_str(&nv.value)?.value();
                        self.rename = Some(rename);
                    }
                    META_BYTES => {
                        let bytes = get_lit_bool(&nv.value)?.value;
                        self.bytes = Some(bytes);
                    }
                    _ => return make_err(meta, "unrecognized attribute"),
                },
            },
            syn::Meta::List(_) => return make_err(meta, "unexpected meta item"),
        };
        Ok(())
    }
}

impl FieldOptions {
    fn extract_ws_display(&mut self, nv: &syn::MetaNameValue) -> Result<(), syn::Error> {
        // Wireshark display is either a single string, or a "bitwise-OR" or two strings.
        if let syn::Expr::Binary(syn::ExprBinary {
            op: syn::BinOp::BitOr(..),
            left,
            right,
            ..
        }) = &nv.value
        {
            let display = get_lit_str(left)?.value();
            let ext = get_lit_str(right)?.value();

            let display = FieldDisplay::new(&display);
            let ext = FieldDisplay::new(&ext);

            self.ws_display = Some(FieldDisplayPair {
                display,
                ext: Some(ext),
            });
        } else {
            let display = get_lit_str(&nv.value)?.value();
            let display = FieldDisplay::new(&display);
            self.ws_display = Some(FieldDisplayPair { display, ext: None });
        }
        Ok(())
    }

    fn extract_subdissector(
        &mut self,
        nv: &syn::MetaNameValue,
        meta: &syn::Meta,
    ) -> Result<(), syn::Error> {
        match unpack_expr(&nv.value).as_slice() {
            [] => return make_err(meta, "expected at least one item"),
            [decode_as] => {
                let decode_as = get_lit_str(decode_as)?.value();
                self.subdissector = Some(Subdissector::DecodeAs(decode_as));
            }
            [table_name, items @ ..] => {
                let table_name = get_lit_str(table_name)?.value();

                let mut fields = Vec::with_capacity(items.len());
                for item in items {
                    let field = get_lit_str(item)?.value();
                    fields.push(format_ident!("{}", field));
                }

                self.subdissector = Some(Subdissector::Table {
                    table_name,
                    fields,
                    typ: SubdissectorTableType::Unknown,
                });
            }
        }
        Ok(())
    }
}

impl OptionBuilder for VariantOptions {
    fn add_option(&mut self, meta: &syn::Meta) -> syn::Result<()> {
        match meta {
            syn::Meta::NameValue(nv) => match nv.path.get_ident() {
                None => return make_err(meta, "expected identifier"),
                Some(ident) => match ident.to_string().as_str() {
                    META_RENAME => {
                        let rename = get_lit_str(&nv.value)?.value();
                        self.rename = Some(rename);
                    }
                    META_PRE_DISSECT => self.pre_dissect = parse_strings(&nv.value)?,
                    META_POST_DISSECT => self.post_dissect = parse_strings(&nv.value)?,
                    _ => return make_err(meta, "unrecognized attribute"),
                },
            },
            _ => return make_err(meta, "unexpected meta item"),
        };
        Ok(())
    }
}

pub(crate) const META_DECODE_FROM: &str = "decode_from";
pub(crate) const META_PROTO_DESC: &str = "proto_desc";
pub(crate) const META_PROTO_NAME: &str = "proto_name";
pub(crate) const META_PROTO_FILTER: &str = "proto_filter";
pub(crate) const META_HIDE: &str = "hide";
pub(crate) const META_SAVE: &str = "save";
pub(crate) const META_LEN: &str = "len_field";
pub(crate) const META_WS_TYPE: &str = "typ";
pub(crate) const META_WS_ENC: &str = "enc";
pub(crate) const META_WS_DISPLAY: &str = "display";
pub(crate) const META_GET_VARIANT: &str = "get_variant";
pub(crate) const META_DECODE_WITH: &str = "decode_with";
pub(crate) const META_TAP: &str = "tap";
pub(crate) const META_CONSUME_WITH: &str = "consume_with";
pub(crate) const META_SUBDISSECTOR: &str = "subdissector";
pub(crate) const META_RENAME: &str = "rename";
pub(crate) const META_PRE_DISSECT: &str = "pre_dissect";
pub(crate) const META_POST_DISSECT: &str = "post_dissect";
pub(crate) const META_BYTES: &str = "bytes";

/// Extracts all the meta items from a list of attributes.
pub(crate) fn get_meta_items(attrs: &[&syn::Attribute]) -> syn::Result<Vec<syn::Meta>> {
    let mut xs = Vec::new();
    for attr in attrs {
        let pairs: Punctuated<syn::Meta, syn::Token![,]> =
            attr.parse_args_with(Punctuated::parse_terminated)?;
        xs.extend(pairs);
    }
    Ok(xs)
}

/// Extracts the attributes which start with some identifier.
pub(crate) fn get_attrs<'a>(attrs: &'a [syn::Attribute], ident: &str) -> Vec<&'a syn::Attribute> {
    attrs
        .iter()
        .filter(|attr| match attr.meta {
            syn::Meta::List(ref lst) => lst
                .path
                .segments
                .first()
                .filter(|s| s.ident == ident)
                .is_some(),
            _ => false,
        })
        .collect()
}

pub(crate) fn get_wsdf_attrs(attrs: &[syn::Attribute]) -> Vec<&syn::Attribute> {
    get_attrs(attrs, "wsdf")
}

pub(crate) fn get_docs(attrs: &[syn::Attribute]) -> Option<String> {
    let docs = attrs.iter().filter_map(get_doc).collect::<String>();
    if docs.is_empty() {
        None
    } else {
        Some(docs)
    }
}

/// Extracts the doc comment contents from an attribute, if any.
fn get_doc(attr: &syn::Attribute) -> Option<String> {
    match attr.meta {
        syn::Meta::NameValue(ref nv) => {
            if nv.path.segments.len() == 1 && nv.path.segments.last().unwrap().ident == *"doc" {
                get_lit_str(&nv.value)
                    .ok()
                    .map(|lit| lit.value().trim().to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Given a list of attributes, checks the name = value meta items and takes all the values which
/// match the provided meta name.
pub(crate) fn filter_for_meta_value(
    attrs: &[syn::Attribute],
    meta_name: &str,
) -> syn::Result<Vec<syn::Expr>> {
    let meta_items = get_meta_items(get_wsdf_attrs(attrs).as_slice())?;
    let ret = meta_items.into_iter().filter_map(|meta| {
        if let syn::Meta::NameValue(nv) = meta {
            if let Some(ident) = nv.path.get_ident() {
                if ident.to_string().as_str() == meta_name {
                    return Some(nv.value);
                }
            }
        }
        None
    });
    Ok(ret.collect())
}

#[cfg(test)]
mod test_attribute_parsing {
    use super::*;

    #[test]
    fn get_attrs_works() {
        let foo: syn::Attribute = parse_quote! { #[foo(bar, baz = "qux")] };
        let bar: syn::Attribute = parse_quote! { #[bar(foo, baz = "qux")] };
        let attrs = vec![foo.clone(), bar.clone()];
        assert_eq!(get_attrs(&attrs, "foo"), vec![&foo]);
        assert_eq!(get_attrs(&attrs, "bar"), vec![&bar]);
        assert_eq!(get_attrs(&attrs, "baz").len(), 0);
    }

    #[test]
    fn get_docs_works() {
        let attr: syn::Attribute = parse_quote! { #[doc = "foo"] };
        assert_eq!(get_docs(&[attr]), Some("foo".to_string()));
    }
}

/// Represents the value of a wireshark display option. It is a pair where the second item is
/// optional, as per Wireshark's API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldDisplayPair {
    display: FieldDisplay,
    ext: Option<FieldDisplay>,
}

impl FieldDisplayPair {
    pub(crate) fn new((display, ext): (&str, Option<&str>)) -> Self {
        Self {
            display: FieldDisplay::new(display),
            ext: ext.map(FieldDisplay::new),
        }
    }

    pub(crate) fn to_expr(&self) -> syn::Expr {
        let left = format_ident!("{}", self.display);
        let left = quote! { wsdf::epan_sys::#left };
        let right = match &self.ext {
            // If there is nothing, we can use 0, since it does not change the result of
            // bitwise-OR.
            None => quote! { 0 },
            Some(ext) => {
                let right = format_ident!("{}", ext);
                quote! { wsdf::epan_sys::#right }
            }
        };
        parse_quote! { #left as std::ffi::c_int | #right as std::ffi::c_int }
    }
}

impl quote::ToTokens for FieldDisplayPair {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.to_expr().to_tokens(tokens)
    }
}

#[cfg(test)]
mod test_field_display_pair {
    use super::*;

    #[test]
    fn without_ext() {
        let pair = super::FieldDisplayPair::new(("BASE_NONE", None));
        assert_eq!(
            pair.to_expr(),
            parse_quote! {
                wsdf::epan_sys::field_display_e_BASE_NONE as std::ffi::c_int | 0 as std::ffi::c_int
            }
        );
    }

    #[test]
    fn with_ext() {
        let pair = super::FieldDisplayPair::new(("BASE_NONE", Some("BASE_SHOW_ASCII_PRINTABLE")));
        assert_eq!(
            pair.to_expr(),
            parse_quote! {
                wsdf::epan_sys::field_display_e_BASE_NONE as std::ffi::c_int |
                wsdf::epan_sys::BASE_SHOW_ASCII_PRINTABLE as std::ffi::c_int
            }
        );
    }
}
