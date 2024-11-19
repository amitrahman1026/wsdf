use std::collections::{HashMap, HashSet};

use quote::{format_ident, quote};
use syn::{parse_quote, punctuated::Punctuated, spanned::Spanned};

use crate::{attributes::*, types::*, util::*};

/// The "innards" of a struct-like object we care about. This is either a unit tuple or a regular
/// thing with named fields.
///
/// This applies to structs of course, but also enum variants.
pub(crate) enum StructInnards {
    UnitTuple(UnitTuple),
    NamedFields { fields: Vec<NamedField> },
}

pub(crate) struct UnitTuple(pub(crate) FieldMeta);

#[derive(Clone)]
pub(crate) struct NamedField {
    ident: syn::Ident,
    meta: FieldMeta,
}

/// Field metadata.
#[derive(Clone)]
pub(crate) struct FieldMeta {
    ty: syn::Type,
    docs: Option<String>,
    options: FieldOptions,

    /// For fields which are given to subdissectors, what the key type is. For Decode As
    /// dissectors, this would be `()`, otherwise it could be, e.g. a u16 for "udp.port".
    ///
    /// If the field is not to be subdissected, should be None.
    subdissector_key_type: Option<syn::Type>,
}

impl StructInnards {
    pub(crate) fn from_fields(fields: &syn::Fields) -> syn::Result<Self> {
        match fields {
            syn::Fields::Named(fields) => Self::from_fields_named(fields),
            syn::Fields::Unnamed(fields) => Self::from_fields_unnamed(fields),
            syn::Fields::Unit => Ok(StructInnards::UnitTuple(UnitTuple(FieldMeta {
                ty: parse_quote! { () },
                docs: None,
                options: FieldOptions::default(),
                subdissector_key_type: None,
            }))),
        }
    }

    fn from_fields_named(fields: &syn::FieldsNamed) -> syn::Result<Self> {
        let mut named_fields = Vec::new();
        for field in &fields.named {
            let ident = field.ident.clone().unwrap(); // safe since the fields are named
            let options = init_options::<FieldOptions>(&field.attrs)?;
            let docs = get_docs(&field.attrs);
            let meta = FieldMeta {
                ty: field.ty.clone(),
                docs,
                options,
                subdissector_key_type: None,
            };
            named_fields.push(NamedField { ident, meta });
        }
        Ok(StructInnards::NamedFields {
            fields: named_fields,
        })
    }

    fn from_fields_unnamed(fields: &syn::FieldsUnnamed) -> syn::Result<Self> {
        if fields.unnamed.len() != 1 {
            return make_err(fields, "expected only one field in tuple");
        }
        let field = fields.unnamed.last().unwrap(); // safe since we checked there's exactly one
        let options = init_options::<FieldOptions>(&field.attrs)?;
        let docs = get_docs(&field.attrs);
        Ok(StructInnards::UnitTuple(UnitTuple(FieldMeta {
            ty: field.ty.clone(),
            docs,
            options,
            subdissector_key_type: None,
        })))
    }

    fn register_fields(&self) -> Vec<syn::Stmt> {
        match self {
            StructInnards::UnitTuple(unit) => {
                let decl_args = unit.decl_register_args();
                let call_register_func = unit.call_inner_register_func();
                parse_quote! {
                    #decl_args
                    #call_register_func
                }
            }
            StructInnards::NamedFields { fields } => {
                let fields = assign_subdissector_key_types(fields);
                fields
                    .iter()
                    .flat_map(NamedField::registration_steps)
                    .collect()
            }
        }
    }

    fn dissect_fields(&self) -> Vec<syn::Stmt> {
        match self {
            StructInnards::UnitTuple(unit) => unit.dissect_field(),
            StructInnards::NamedFields { fields } => {
                let plans = get_field_dissection_plans(fields);
                fields
                    .iter()
                    .zip(plans)
                    .flat_map(|(field, plan)| field.dissection_steps(&plan))
                    .collect()
            }
        }
    }

    pub(crate) fn add_to_tree_fn(&self, dissect_options: &ProtocolFieldOptions) -> syn::ItemFn {
        let dissect_fields = self.dissect_fields();
        let fn_contents: Vec<syn::Stmt> = match self {
            StructInnards::UnitTuple(_) => parse_quote! {
                #(#dissect_fields)*
            },
            StructInnards::NamedFields { .. } => parse_quote! {
                let parent = args.add_subtree();
                #(#dissect_fields)*

                // When the subtree was created above, its size should have been uninitialized. We
                // set it manually here, now that all fields have been dissected and we know its
                // size.
                unsafe {
                    wsdf::epan_sys::proto_item_set_len(parent, (offset - args.offset) as _);
                }
            },
        };
        let pre_dissect = pre_post_dissect(&dissect_options.pre_dissect);
        let post_dissect = pre_post_dissect(&dissect_options.post_dissect);
        parse_quote! {
            fn add_to_tree(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                // Some type-wide declarations.
                let mut fields_local = wsdf::FieldsStore::default();
                let offset = args.offset;
                #(#pre_dissect)* // this should appear after offset is declared
                #(#fn_contents)*
                #(#post_dissect)*
                offset - args.offset // return the number of bytes dissected
            }
        }
    }

    pub(crate) fn size_fn(&self) -> syn::ItemFn {
        let fn_contents: Vec<syn::Stmt> = match self {
            // We use a trick here. We create the field dissection plan as per usual, but then
            // modify its add_strategy to be hidden. This has the same effect as simply querying
            // the field's size.
            StructInnards::UnitTuple(unit) => {
                let mut plan = FieldDissectionPlan::from_unit_tuple(unit);
                plan.add_strategy = AddStrategy::Hidden;
                unit.dissect_field_with_plan(&plan)
            }
            StructInnards::NamedFields { fields } => {
                let mut plans = get_field_dissection_plans(fields);
                for plan in &mut plans {
                    plan.add_strategy = AddStrategy::Hidden;
                }
                fields
                    .iter()
                    .zip(plans)
                    .flat_map(|(field, plan)| field.dissection_steps(&plan))
                    .collect()
            }
        };
        parse_quote! {
            fn size(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                let offset = args.offset;
                let parent = args.parent; // doesn't matter where it points to since we're not
                                          // adding to the tree
                #(#fn_contents)*
                offset - args.offset
            }
        }
    }

    pub(crate) fn register_fn(&self) -> syn::ItemFn {
        let register_fields = self.register_fields();
        let fn_contents: Vec<syn::Stmt> = match self {
            StructInnards::UnitTuple(_) => register_fields,
            StructInnards::NamedFields { .. } => parse_quote! {
                // A group of named fields must be hung together under a new subtree. So we'll need
                // to create it here (both the ETT and HF).
                let _ = ws_indices.ett.get_or_create_ett(args);
                let _ = ws_indices.hf.get_or_create_text_node(args);

                #(#register_fields)*
            },
        };
        parse_quote! {
            fn register(args: &wsdf::RegisterArgs, ws_indices: &mut wsdf::WsIndices) {
                #(#fn_contents)*
            }
        }
    }
}

impl UnitTuple {
    fn decl_register_args(&self) -> syn::Stmt {
        let blurb = self.blurb_expr();
        let ws_type = self.0.ws_type_as_expr();
        let ws_display = self.0.ws_display_as_expr();

        parse_quote! {
            let args_next = wsdf::RegisterArgs {
                proto_id: args.proto_id,
                name: args.name,
                prefix: args.prefix,
                blurb: #blurb,
                ws_type: #ws_type,
                ws_display: #ws_display,
            };
        }
    }

    fn decl_dissector_args(&self) -> syn::Stmt {
        let ws_enc = self.0.ws_enc_as_expr();
        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: args.prefix,
                prefix_local: args.prefix_local,
                offset: args.offset,
                parent: args.parent,
                variant: std::option::Option::None,
                list_len: std::option::Option::None,
                ws_enc: #ws_enc,
            };
        }
    }

    fn blurb_expr(&self) -> syn::Expr {
        // For unit tuples, we would like to take the blurb from its "parent" field.
        let blurb_cstr = self.0.blurb_cstr();
        parse_quote! {
            if !args.blurb.is_null() { args.blurb }
            else { #blurb_cstr }
        }
    }

    fn call_inner_register_func(&self) -> syn::Stmt {
        self.0.call_register_func()
    }

    fn dissect_field(&self) -> Vec<syn::Stmt> {
        let plan = FieldDissectionPlan::from_unit_tuple(self);
        self.dissect_field_with_plan(&plan)
    }

    fn dissect_field_with_plan(&self, plan: &FieldDissectionPlan) -> Vec<syn::Stmt> {
        let decl_args_next = self.decl_dissector_args();
        let var_name = format_ident!("__inner_value"); // just a random symbol to store the inner
                                                       // field's value, if it is emitted
        plan.dissection_steps(&decl_args_next, &var_name)
    }
}

impl NamedField {
    fn registration_steps(&self) -> Vec<syn::Stmt> {
        let ident_str = self.ident.to_string();
        let decl_prefix: syn::Stmt = parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #ident_str;
        };

        let name = self
            .meta
            .options
            .rename
            .clone()
            .unwrap_or(self.ident.to_wsdf_title_case());
        let name: syn::Expr = cstr!(name);
        let decl_args = self
            .meta
            .decl_register_args(&name, &parse_quote!(&prefix_next));

        let call_register_func = self.meta.call_register_func();

        parse_quote! {
            #decl_prefix
            #decl_args
            #call_register_func
        }
    }

    fn dissection_steps(&self, plan: &FieldDissectionPlan) -> Vec<syn::Stmt> {
        let decl_prefix_next = self.decl_prefix_next();
        let decl_args_next = self.decl_dissector_args();

        // By convention, when a field is emitted, we'll store it in a variable named like so -
        // just prepend two underscores.
        let var_name = format_ident!("__{}", self.ident);

        let steps = plan.dissection_steps(&decl_args_next, &var_name);

        parse_quote! {
            #decl_prefix_next
            #(#steps)*
        }
    }

    fn decl_prefix_next(&self) -> syn::Stmt {
        let field_name = self.ident.to_string();
        parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #field_name;
        }
    }

    fn decl_dissector_args(&self) -> syn::Stmt {
        let variant = self.meta.get_variant_as_expr();
        let list_len = self.meta.size_hint_as_expr();
        let ws_enc = self.meta.ws_enc_as_expr();
        let field_ident = self.ident.to_string();

        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: &prefix_next,
                prefix_local: #field_ident,
                offset,
                parent,
                variant: #variant,
                list_len: #list_len,
                ws_enc: #ws_enc,
            };
        }
    }
}

impl FieldMeta {
    fn blurb_cstr(&self) -> syn::Expr {
        match &self.docs {
            Some(docs) => cstr!(docs),
            None => parse_quote! { std::ptr::null() },
        }
    }

    fn ws_type_as_expr(&self) -> syn::Expr {
        self.options.ws_type_as_expr()
    }

    fn ws_display_as_expr(&self) -> syn::Expr {
        self.options.ws_display_as_expr()
    }

    fn ws_enc_as_expr(&self) -> syn::Expr {
        self.options.ws_enc_as_expr()
    }

    fn size_hint_as_expr(&self) -> syn::Expr {
        self.options.size_hint_as_expr()
    }

    fn get_variant_as_expr(&self) -> syn::Expr {
        self.options.get_variant_as_expr()
    }

    fn maybe_bytes(&self) -> syn::Type {
        self.options.maybe_bytes()
    }

    fn call_register_func(&self) -> syn::Stmt {
        let field_ty = &self.ty;
        // Most fields will just be registered as per normal (recursively via ::register). But some
        // fields are to be subdissected.
        //
        // In which case we'll have to register the subdissector instead.
        match &self.options.subdissector {
            None => {
                let maybe_bytes = self.maybe_bytes();
                parse_quote! {
                    <#field_ty as wsdf::Dissect<'tvb, #maybe_bytes>>::register(&args_next, ws_indices);
                }
            }
            Some(Subdissector::DecodeAs(table_name)) => parse_quote! {
                <() as wsdf::SubdissectorKey>::create_table(args_next.proto_id, #table_name, ws_indices.dtable);
            },
            Some(Subdissector::Table { table_name, .. }) => {
                debug_assert!(self.subdissector_key_type.is_some());
                let key_type = self.subdissector_key_type.as_ref().unwrap();
                parse_quote! {
                    <#key_type as wsdf::SubdissectorKey>::create_table(args.proto_id, #table_name, ws_indices.dtable);
                }
            }
        }
    }

    fn decl_register_args(&self, name: &syn::Expr, prefix: &syn::Expr) -> syn::Stmt {
        let blurb = self.blurb_cstr();
        let ws_type = self.ws_type_as_expr();
        let ws_display = self.ws_display_as_expr();
        parse_quote! {
            let args_next = wsdf::RegisterArgs {
                proto_id: args.proto_id,
                name: #name,
                prefix: #prefix,
                blurb: #blurb,
                ws_type: #ws_type,
                ws_display: #ws_display,
            };
        }
    }
}

impl FieldOptions {
    fn ws_type_as_expr(&self) -> syn::Expr {
        match &self.ws_type {
            Some(ty) => {
                let ws_type = format_ws_type(ty);
                parse_quote! { std::option::Option::Some(#ws_type) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn ws_display_as_expr(&self) -> syn::Expr {
        match &self.ws_display {
            Some(display) => parse_quote! { std::option::Option::Some(#display) },
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn ws_enc_as_expr(&self) -> syn::Expr {
        match &self.ws_enc {
            Some(enc) => {
                let ws_enc = format_ws_enc(enc);
                parse_quote! { std::option::Option::Some(#ws_enc) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn size_hint_as_expr(&self) -> syn::Expr {
        match &self.size_hint {
            Some(size_hint) => {
                let field_name = format_ident!("__{size_hint}");
                parse_quote! { std::option::Option::Some(#field_name as usize) }
            }
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn get_variant_as_expr(&self) -> syn::Expr {
        match &self.get_variant {
            Some(get_variant) => parse_quote! {
                // This ugly bit is just to get around some lifetime issues in the final code. We
                // create a temporary context holding a field of `()` and pass that into context
                // handler.
                std::option::Option::Some(
                    wsdf::tap::handle_get_variant(&wsdf::tap::Context {
                        field: (),
                        fields,
                        fields_local: &fields_local,
                        pinfo: args.pinfo,
                        packet: args.data,
                        offset,
                    },
                    #get_variant,
                ))
            },
            None => parse_quote! { std::option::Option::None },
        }
    }

    fn maybe_bytes(&self) -> syn::Type {
        match self.bytes {
            Some(true) => parse_quote! { [u8] },
            Some(false) | None => parse_quote! { () },
        }
    }

    fn requires_ctx(&self) -> bool {
        !self.taps.is_empty()
            || self.consume_with.is_some()
            || self.decode_with.is_some()
            || self.get_variant.is_some()
    }
}

/// Contains all the information we need to generate the steps to dissect a field.
struct FieldDissectionPlan<'a> {
    emit: bool,
    save: bool,
    build_ctx: bool,
    taps: &'a [syn::Path],
    add_strategy: AddStrategy,

    meta: &'a FieldMeta,
}

/// How a field should be added to the protocol tree.
enum AddStrategy {
    Subdissect(Subdissector),
    DecodeWith(syn::Path),
    ConsumeWith(syn::Path),
    Hidden,

    /// Just add it plainly.
    Default,
}

impl AddStrategy {
    fn from_field_options(options: &FieldOptions) -> Self {
        // @todo: this should be validated earlier, or perhaps we should return an error here
        // instead of failing the assert.
        //
        // The idea is that at most one of these three should have been set.
        debug_assert!(matches!(
            (
                &options.decode_with,
                &options.consume_with,
                &options.subdissector
            ),
            (Some(_), None, None)
                | (None, Some(_), None)
                | (None, None, Some(_))
                | (None, None, None)
        ));

        if let Some(subd) = &options.subdissector {
            AddStrategy::Subdissect(subd.clone())
        } else if let Some(consume_fn) = &options.consume_with {
            AddStrategy::ConsumeWith(consume_fn.clone())
        } else if let Some(decode_fn) = &options.decode_with {
            AddStrategy::DecodeWith(decode_fn.clone())
        } else if let Some(true) = options.hidden {
            AddStrategy::Hidden
        } else {
            AddStrategy::Default
        }
    }
}

impl<'a> FieldDissectionPlan<'a> {
    fn from_unit_tuple(unit: &'a UnitTuple) -> Self {
        let options = &unit.0.options;
        let save = options.save == Some(true);
        let build_ctx = options.requires_ctx();
        let emit = build_ctx;
        let add_strategy = AddStrategy::from_field_options(options);

        Self {
            emit,
            save,
            build_ctx,
            taps: &options.taps,
            add_strategy,
            meta: &unit.0,
        }
    }
}

impl FieldDissectionPlan<'_> {
    fn dissection_steps(
        &self,
        decl_args_next: impl quote::ToTokens,
        field_var_name: &syn::Ident,
    ) -> Vec<syn::Stmt> {
        let emit_and_assign = self.emit_and_assign(field_var_name);
        let save_field = self.save_field();
        let build_tap_ctx = self.build_tap_ctx(field_var_name);
        let call_taps = self.call_taps();
        let exec_add_strategy = self.exec_add_strategy();

        parse_quote! {
            #decl_args_next
            #emit_and_assign
            #save_field
            #build_tap_ctx
            #(#call_taps)*
            #(#exec_add_strategy)*
        }
    }

    fn emit_and_assign(&self, var_name: &syn::Ident) -> Option<syn::Stmt> {
        if !self.emit {
            return None;
        }
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();
        Some(parse_quote! {
            let #var_name = <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::emit(&args_next);

        })
    }

    fn save_field(&self) -> Option<syn::Stmt> {
        if !self.save {
            return None;
        }
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();
        Some(parse_quote! {
            <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::save(&args_next, fields, &mut fields_local);
        })
    }

    fn build_tap_ctx(&self, field_value: impl quote::ToTokens) -> Option<syn::Stmt> {
        if !self.build_ctx {
            return None;
        }
        Some(parse_quote! {
            let ctx = wsdf::tap::Context {
                field: #field_value,
                fields,
                fields_local: &fields_local,
                pinfo: args.pinfo,
                packet: args.data,
                offset,
            };
        })
    }

    fn call_taps(&self) -> Vec<syn::Stmt> {
        self.taps
            .iter()
            .map(|tap_fn| {
                parse_quote! {
                    wsdf::tap::handle_tap(&ctx, #tap_fn);
                }
            })
            .collect()
    }

    fn exec_add_strategy(&self) -> Vec<syn::Stmt> {
        let ty = &self.meta.ty;
        let maybe_bytes = self.meta.maybe_bytes();

        match &self.add_strategy {
            AddStrategy::Subdissect(subd) => self.try_subdissector(subd),
            AddStrategy::ConsumeWith(consume_fn) => {
                parse_quote! {
                    let (n, s) = wsdf::tap::handle_consume_with(&ctx, #consume_fn);
                    <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::add_to_tree_format_value(&args_next, &s, n);
                    let offset = offset + n;
                }
            }
            AddStrategy::DecodeWith(decode_fn) => {
                parse_quote! {
                    let s = wsdf::tap::handle_decode_with(&ctx, #decode_fn);
                    let n = <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::size(&args_next, fields);
                    <#ty as wsdf::Primitive<'tvb, #maybe_bytes>>::add_to_tree_format_value(&args_next, &s, n);
                    let offset = offset + n;
                }
            }
            AddStrategy::Hidden => self.handle_hidden(),
            AddStrategy::Default => vec![parse_quote! {
                let offset = offset + <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::add_to_tree(&args_next, fields);
            }],
        }
    }

    fn handle_hidden(&self) -> Vec<syn::Stmt> {
        let maybe_bytes = self.meta.maybe_bytes();
        let ty = &self.meta.ty;

        if let Some(consume_fn) = &self.meta.options.consume_with {
            parse_quote! {
                // Assume that the context is already created.
                let (n, _) = wsdf::tap::handle_consume_with(&ctx, #consume_fn);
                let offset = offset + n;
            }
        } else if let Some(subd) = &self.meta.options.subdissector {
            self.try_subdissector_null_proto_root(subd)
        } else {
            parse_quote! {
                let offset = offset + <#ty as wsdf::Dissect<'tvb, #maybe_bytes>>::size(&args_next, fields);
            }
        }
    }

    fn try_subdissector(&self, subd: &Subdissector) -> Vec<syn::Stmt> {
        self.try_subdissector_with_proto_root(subd, &parse_quote!(args.proto_root))
    }

    fn try_subdissector_null_proto_root(&self, subd: &Subdissector) -> Vec<syn::Stmt> {
        self.try_subdissector_with_proto_root(subd, &parse_quote! { std::ptr::null_mut() })
    }

    fn try_subdissector_with_proto_root(
        &self,
        subd: &Subdissector,
        proto_root: &syn::Expr,
    ) -> Vec<syn::Stmt> {
        let ty = &self.meta.ty;

        let setup_tvb_next: syn::Stmt = parse_quote! {
            let tvb_next = <#ty as wsdf::Subdissect<'tvb>>::setup_tvb_next(&args_next);
        };
        let update_args_next: syn::Stmt = parse_quote! {
            let args_next = wsdf::DissectorArgs {
                tvb: tvb_next,
                proto_root: #proto_root,
                ..args_next
            };
        };
        let try_subdissector: Vec<syn::Stmt> = match subd {
            Subdissector::DecodeAs(table_name) => parse_quote! {
                let offset = offset + <#ty as wsdf::Subdissect<'tvb>>::try_subdissector(&args_next, #table_name, &());
            },
            Subdissector::Table {
                table_name, fields, ..
            } => {
                // Each field will be tried in sequence, and called only if none of the previous
                // one successfully dissected > 0 bytes.
                let try_fields = fields.iter().map(|field| -> syn::ExprIf {
                    let field_var_name = format_ident!("__{field}");
                    parse_quote! {
                        if nr_bytes_subdissected == 0 {
                            nr_bytes_subdissected
                                = <#ty as wsdf::Subdissect<'tvb>>::try_subdissector(
                                    &args_next,
                                    #table_name,
                                    &#field_var_name,
                                );
                        }
                    }
                });
                parse_quote! {
                    let mut nr_bytes_subdissected = 0;
                    #(#try_fields)*
                    if nr_bytes_subdissected == 0 {
                        nr_bytes_subdissected = args_next.call_data_dissector();
                    }
                    let offset = offset + nr_bytes_subdissected;
                }
            }
        };

        parse_quote! {
            #setup_tvb_next
            #update_args_next
            #(#try_subdissector)*
        }
    }
}

/// Scans a list of named fields and sets the `subdissector_key_type` on each.
fn assign_subdissector_key_types(fields: &[NamedField]) -> Vec<NamedField> {
    fields
        .iter()
        .map(|field| {
            let new_meta = match &field.meta.options.subdissector {
                Some(Subdissector::DecodeAs(_)) | None => FieldMeta {
                    subdissector_key_type: None,
                    ..field.meta.clone()
                },
                Some(Subdissector::Table { fields: keys, .. }) => {
                    // The idea here is to scan through the provided list of fields until the first
                    // one which matches one of the keys.
                    //
                    // @todo: ensure that all the keys can be found, and that their types match.
                    // This should be relatively easy once we remove the old code and use a better
                    // abstraction for Subdissector.
                    let mut new_meta = field.meta.clone();
                    for field in fields {
                        for key in keys {
                            if &field.ident == key {
                                new_meta.subdissector_key_type = Some(field.meta.ty.clone());
                            }
                        }
                    }
                    debug_assert!(new_meta.subdissector_key_type.is_some());
                    new_meta
                }
            };
            NamedField {
                meta: new_meta,
                ..field.clone()
            }
        })
        .collect()
}

fn get_field_dissection_plans(fields: &[NamedField]) -> Vec<FieldDissectionPlan> {
    let mut fields_to_emit = HashSet::new();
    for field in fields {
        let options = &field.meta.options;
        if options.requires_ctx() {
            fields_to_emit.insert(&field.ident);
        }
        if let Some(Subdissector::Table { fields, .. }) = &options.subdissector {
            for field in fields {
                fields_to_emit.insert(field);
            }
        }
        if let Some(dispatch_field) = &options.dispatch {
            fields_to_emit.insert(dispatch_field);
        }
        if let Some(len_field) = &options.size_hint {
            fields_to_emit.insert(len_field);
        }
    }

    fields
        .iter()
        .map(|field| {
            let options = &field.meta.options;

            let save = options.save == Some(true);
            let build_ctx = options.requires_ctx();
            let add_strategy = AddStrategy::from_field_options(options);

            FieldDissectionPlan {
                emit: fields_to_emit.contains(&field.ident),
                save,
                build_ctx,
                taps: &options.taps,
                add_strategy,
                meta: &field.meta,
            }
        })
        .collect()
}

pub(crate) struct Enum<'a> {
    ident: &'a syn::Ident,
    variants: Vec<Variant<'a>>,
}

struct Variant<'a> {
    data: &'a syn::Variant,
    options: VariantOptions,
}

impl Variant<'_> {
    fn ident(&self) -> &syn::Ident {
        &self.data.ident
    }

    fn ui_name(&self) -> String {
        self.options
            .rename
            .clone()
            .unwrap_or(self.ident().to_wsdf_title_case())
    }

    fn blurb_expr(&self) -> syn::Expr {
        let docs = get_docs(&self.data.attrs);
        match docs {
            Some(docs) => cstr!(docs),
            None => parse_quote! { std::ptr::null() },
        }
    }
}

impl<'a> Enum<'a> {
    pub(crate) fn new(
        ident: &'a syn::Ident,
        variants: &'a Punctuated<syn::Variant, syn::Token![,]>,
    ) -> syn::Result<Self> {
        let mut xs = Vec::with_capacity(variants.len());

        for variant in variants {
            let options = init_options::<VariantOptions>(&variant.attrs)?;
            xs.push(Variant {
                data: variant,
                options,
            });
        }

        Ok(Self {
            ident,
            variants: xs,
        })
    }

    pub(crate) fn ident(&self) -> &syn::Ident {
        self.ident
    }

    fn decl_prefix_next(&self, variant: &syn::Variant) -> syn::Stmt {
        let name_snake_case = variant.ident.to_wsdf_snake_case();

        parse_quote! {
            let prefix_next = args.prefix.to_owned() + "." + #name_snake_case;
        }
    }

    fn decl_dissector_args(variant: &syn::Variant) -> syn::Stmt {
        let variant_snake_case = variant.ident.to_wsdf_snake_case();
        parse_quote! {
            let args_next = wsdf::DissectorArgs {
                hf_indices: args.hf_indices,
                etts: args.etts,
                dtables: args.dtables,
                tvb: args.tvb,
                pinfo: args.pinfo,
                proto_root: args.proto_root,
                data: args.data,

                prefix: &prefix_next,
                prefix_local: #variant_snake_case,
                offset: args.offset,
                parent: args.parent,
                variant: std::option::Option::None,
                list_len: std::option::Option::None,
                ws_enc: std::option::Option::None,
            };
        }
    }

    pub(crate) fn add_to_tree_fn(&self) -> syn::ItemFn {
        let inner = self.match_and_call_on_variant(&parse_quote!(add_to_tree));
        parse_quote! {
            fn add_to_tree(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                #(#inner)*
            }
        }
    }

    pub(crate) fn size_fn(&self) -> syn::ItemFn {
        let inner = self.match_and_call_on_variant(&parse_quote!(size));
        parse_quote! {
            fn size(args: &wsdf::DissectorArgs<'_, 'tvb>, fields: &mut wsdf::FieldsStore<'tvb>) -> usize {
                let mut fields_local = wsdf::FieldsStore::default();
                #(#inner)*
            }
        }
    }

    pub(crate) fn register_fn(&self) -> syn::ItemFn {
        let register_stmts = self.variants.iter().flat_map(|variant| -> Vec<syn::Stmt> {
            let name = variant.ui_name();
            let name_cstr: syn::Expr = cstr!(name);
            let blurb = variant.blurb_expr();
            let struct_name = format_ident!("__{}", variant.ident());

            let decl_prefix_next = self.decl_prefix_next(variant.data);
            let decl_args_next: syn::Stmt = parse_quote! {
                let args_next = wsdf::RegisterArgs {
                    proto_id: args.proto_id,
                    name: #name_cstr,
                    prefix: &prefix_next,
                    blurb: #blurb,
                    ws_type: std::option::Option::None,
                    ws_display: std::option::Option::None,
                };
            };

            parse_quote! {
                #decl_prefix_next
                #decl_args_next
                #struct_name::register(&args_next, ws_indices);
            }
        });
        parse_quote! {
            fn register(args: &wsdf::RegisterArgs, ws_indices: &mut wsdf::WsIndices) {
                #(#register_stmts)*
            }
        }
    }

    fn match_and_call_on_variant(&self, call: &syn::Path) -> Vec<syn::Stmt> {
        let arms = self.variants.iter().map(|variant| -> syn::Arm {
            let name = variant.ident().to_string();
            let decl_prefix_next = self.decl_prefix_next(variant.data);
            let setup_args_next = Self::decl_dissector_args(variant.data);
            let struct_name = format_ident!("__{}", variant.ident());

            parse_quote! {
                Some(#name) => {
                    #decl_prefix_next
                    #setup_args_next
                    #struct_name::#call(&args_next, fields)
                }
            }
        });
        let enum_ident_str = self.ident.to_string();
        parse_quote! {
            match args.variant {
                #(#arms)*
                Some(v) => panic!("unexpected variant {} of {}", v, #enum_ident_str),
                None => panic!("unable to determine variant of {}", #enum_ident_str),
            }
        }
    }
}

/// Generates the code for pre/post dissect hooks.
fn pre_post_dissect(funcs: &[syn::Path]) -> Vec<syn::Stmt> {
    if funcs.is_empty() {
        return Vec::new();
    }
    let decl_ctx: syn::Stmt = parse_quote! {
        let ctx = wsdf::tap::Context {
            field: (),
            fields,
            fields_local: &fields_local,
            pinfo: args.pinfo,
            packet: args.data,
            offset,
        };
    };
    let calls = funcs.iter().map(|func| -> syn::Stmt {
        parse_quote! {
            wsdf::tap::handle_tap(&ctx, #func);
        }
    });
    parse_quote! {
        #decl_ctx
        #(#calls)*
    }
}
