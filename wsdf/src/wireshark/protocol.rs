use super::{dissector::*, types::*};
use epan_sys;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void},
};

pub struct Protocol {
    _name: String,
    pub abbrev: String,
    filter: String,
    // Static data for this protocol
    pub proto_handle: c_int,

    ett_defs: Vec<Ett>,
    // Holds the collapse state of the subtree
    ett_handles: HashMap<String, EttHandle>,

    // The actual dissector implementation
    pub dissector_fn: Dissector,

    field_defs: Vec<Field>,
    // All registered fields for this protocol
    field_handles: HashMap<String, FieldHandle>,

    // Encapsulates expert fields management under Expert Module
    expert_module: ExpertModule,

    // Pending match conditions for this protocol that have not yet been registered
    pub match_definitions: Option<Vec<DissectorDecodeFrom>>,
}

impl Protocol {
    unsafe fn register_field(&mut self, field: &Field) -> Result<(), RegistrationError> {
        let mut handle: c_int = -1;

        // Convert strings for value_string if present
        let values_ptr = if let Some(strings) = &field.strings {
            let mut values: Vec<epan_sys::_value_string> = strings
                .iter()
                .map(|(val, str)| epan_sys::_value_string {
                    value: *val,
                    strptr: to_c_str(str),
                })
                .collect();

            // The last entry in the array must have a NULL 'strptr' value, to
            // indicate the end of the array
            values.push(epan_sys::_value_string {
                value: 0,
                strptr: std::ptr::null(),
            });
            Box::into_raw(values.into_boxed_slice()) as *const epan_sys::_value_string
        } else {
            std::ptr::null()
        };

        let hf_info = epan_sys::hf_register_info {
            p_id: &mut handle,
            hfinfo: epan_sys::header_field_info {
                name: to_c_str(&field.name),
                abbrev: to_c_str(&field.abbrev),
                type_: field.field_type.to_u32(),
                display: field.display.to_u32() as i32,
                strings: values_ptr as *const c_void,
                bitmask: field.bitmask,
                blurb: field
                    .blurb
                    .as_ref()
                    .map_or(std::ptr::null(), |s| to_c_str(s)),
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        };

        let hf_ptr: *mut epan_sys::hf_register_info = Box::into_raw(Box::new(hf_info)); // Header fields need to persist and wireshark takes ownership
        debug_assert!(handle == -1);
        epan_sys::proto_register_field_array(self.get_proto_handle(), hf_ptr, 1);

        if handle != -1 {
            self.field_handles
                .insert(field.id.clone(), FieldHandle { handle });

            // Don't free on success -> wireshark took ownership
            Ok(())
        } else {
            let _ = Box::from_raw(hf_ptr); // Clean up
            Err(RegistrationError::RegistrationFailed)
        }
    }
    pub(crate) fn get_ett_handle(&self, id: &str) -> c_int {
        // self.ett_handles.get(idx as usize).expect("ETT handle index out of bounds, use set_num_ett during protocol creation to set the number of ETT fields").clone()
        self.ett_handles
            .get(id)
            .expect(&format!("ETT '{}' not registered", id))
            .handle
    }
    // This should be called by the Protocol.register routine unless you know what you're doing
    unsafe fn register_ett(&mut self) {
        // Initialize ett handles with -1
        let mut ett_handles = vec![-1; self.ett_defs.len()];

        // Create array of pointers to ett handles
        let ett_ptrs: Vec<*mut c_int> = ett_handles.iter_mut().map(|h| h as *mut c_int).collect();

        // Register the ETT array with Wireshark
        epan_sys::proto_register_subtree_array(ett_ptrs.as_ptr(), ett_handles.len() as c_int);

        // Store handles mapped to their IDs
        for (i, ett) in self.ett_defs.iter().enumerate() {
            self.ett_handles.insert(
                ett.id.clone(),
                EttHandle {
                    handle: ett_handles[i],
                },
            );
        }
    }

    // Get the handle to the protocol's ETT
    pub(crate) fn get_proto_handle(&self) -> c_int {
        self.proto_handle
    }
    // Get the handle to a field that has already been registered
    pub(crate) fn get_field_handle(&self, abbrev: &str) -> Option<&FieldHandle> {
        self.field_handles.get(abbrev)
    }

    unsafe fn register_expert_info(
        &mut self,
        expert_module: *mut epan_sys::expert_module_t,
        info: &ExpertFieldInfo,
    ) -> Result<(), RegistrationError> {
        let expert_field: epan_sys::expert_field = epan_sys::expert_field { ei: -1, hf: -1 };
        let expert_field_ptr = Box::into_raw(Box::new(expert_field));

        // These resources just need to be alive for the registration
        let name = to_c_str(&format!("{}.{}", self.filter, info.id));
        let summary = to_c_str(&info.summary);

        let ei_info = epan_sys::ei_register_info {
            ids: expert_field_ptr as *mut epan_sys::expert_field,
            eiinfo: epan_sys::expert_field_info {
                name,
                group: info.group.to_u32() as i32,
                severity: info.severity.to_u32() as i32,
                summary,
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: epan_sys::hf_register_info {
                    p_id: std::ptr::null_mut(), // overwrite with address of expert_field's hf
                    hfinfo: epan_sys::header_field_info {
                        name: std::ptr::null_mut(),
                        abbrev: std::ptr::null_mut(),
                        type_: epan_sys::ftenum_FT_NONE,
                        display: epan_sys::field_display_e_BASE_NONE as i32,
                        strings: std::ptr::null(),
                        bitmask: 0,
                        blurb: std::ptr::null(),
                        id: -1,
                        parent: 0,
                        ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                        same_name_prev_id: -1,
                        same_name_next: std::ptr::null_mut(),
                    },
                },
            },
        };

        let ei_ptr = Box::into_raw(Box::new(ei_info));

        epan_sys::expert_register_field_array(expert_module, ei_ptr, 1);

        if (*(*ei_ptr).ids).ei != -1 && (*(*ei_ptr).ids).hf != -1 {
            self.expert_module.expert_fields_handles.insert(
                info.id.clone(),
                ExpertFieldHandle {
                    ei: (*(*ei_ptr).ids).ei,
                    hf: (*(*ei_ptr).ids).hf,
                },
            );
            Ok(())
        } else {
            let _ = Box::from_raw(expert_field_ptr);
            let _ = Box::from_raw(ei_ptr);
            Err(RegistrationError::RegistrationFailed)
        }
    }
    pub fn get_expert_field(&self, id: &str) -> Option<&ExpertFieldHandle> {
        self.expert_module.expert_fields_handles.get(id)
    }
    // Routine to be called to register all header fields, ETT types, expert fields
    pub fn register(&mut self) {
        let fields_to_register = self.field_defs.clone();
        let expert_infos_to_register = self.expert_module.expert_info_defs.clone();

        unsafe {
            for field in fields_to_register {
                self.register_field(&field)
                    .expect("Failed to register field");
            }
            // Registering ETT is basically saying how many types of trees you have
            self.register_ett();

            // Registering Expert Info and just retaining the expert field handles
            if !expert_infos_to_register.is_empty() {
                let expert_module = epan_sys::expert_register_protocol(self.proto_handle);
                self.expert_module.ptr = expert_module;
                for expert_info in expert_infos_to_register {
                    self.register_expert_info(expert_module, &expert_info)
                        .expect("Failed to register expert info");
                }
            }
        }
    }
}

pub struct FieldBuilder {
    id: String,
    name: String,
    abbrev: String,
    field_type: Option<FieldType>,
    display: Option<FieldDisplay>,
    strings: Option<Vec<(u32, String)>>,
    bitmask: u64,
    blurb: Option<String>,
}
impl FieldBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>, abbrev: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            abbrev: abbrev.into(),
            field_type: None,
            display: None,
            strings: None,
            bitmask: 0,
            blurb: None,
        }
    }

    pub fn field_type(mut self, field_type: FieldType) -> Self {
        self.field_type = Some(field_type);
        self
    }

    pub fn display(mut self, display: FieldDisplay) -> Self {
        self.display = Some(display);
        self
    }

    pub fn strings(mut self, strings: Vec<(u32, String)>) -> Self {
        self.strings = Some(strings);
        self
    }

    pub fn bitmask(mut self, bitmask: u64) -> Self {
        self.bitmask = bitmask;
        self
    }

    pub fn blurb(mut self, blurb: impl Into<String>) -> Self {
        self.blurb = Some(blurb.into());
        self
    }

    pub fn build(self) -> Result<Field, RegistrationError> {
        Ok(Field {
            id: self.id,
            name: self.name,
            abbrev: self.abbrev,
            field_type: self.field_type.ok_or(RegistrationError::MissingFieldType)?,
            display: self.display.unwrap_or_default(),
            strings: self.strings,
            bitmask: self.bitmask,
            blurb: self.blurb,
        })
    }
}

pub struct FieldHandle {
    pub(crate) handle: c_int,
}

#[derive(Clone)]
pub struct Ett {
    id: String,
    _name: String,
}

pub struct EttHandle {
    handle: c_int,
}

pub const ROOT_ETT_ID: &str = "_root";

pub struct ExpertModule {
    expert_info_defs: Vec<ExpertFieldInfo>,
    // Lookup for expert field handles
    expert_fields_handles: HashMap<String, ExpertFieldHandle>,
    // Innter ptr to expert field modules
    ptr: *mut epan_sys::expert_module_t,
}

pub struct ExpertFieldHandle {
    pub(crate) ei: c_int,
    pub(crate) hf: c_int,
}

#[derive(Clone)]
pub struct ExpertFieldInfo {
    id: String,
    group: ExpertGroup,
    severity: ExpertSeverity,
    summary: String,
}

pub struct ProtocolBuilder {
    name: String,
    abbrev: String,
    filter: String,
    dissector_fn: Option<Dissector>,
    fields: Vec<Field>,
    ett: Vec<Ett>,
    expert_infos: Vec<ExpertFieldInfo>,
    match_definitions: Vec<DissectorDecodeFrom>,
}

impl ProtocolBuilder {
    pub fn new(
        name: impl Into<String>,
        abbrev: impl Into<String>,
        filter: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            abbrev: abbrev.into(),
            filter: filter.into(),
            dissector_fn: None,
            fields: Vec::new(),
            ett: Vec::new(),
            expert_infos: Vec::new(),
            match_definitions: Vec::new(),
        }
    }

    pub fn dissector(mut self, dissector: Dissector) -> Self {
        self.dissector_fn = Some(dissector);
        self
    }

    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    pub fn ett(mut self, id: impl Into<String>, name: impl Into<String>) -> Self {
        self.ett.push(Ett {
            id: id.into(),
            _name: name.into(),
        });
        self
    }

    pub fn expert_info(
        mut self,
        id: impl Into<String>,
        group: ExpertGroup,
        severity: ExpertSeverity,
        summary: impl Into<String>,
    ) -> Self {
        self.expert_infos.push(ExpertFieldInfo {
            id: id.into(),
            group,
            severity,
            summary: summary.into(),
        });
        self
    }

    pub fn decode_from(mut self, decode_from: DissectorDecodeFrom) -> Self {
        self.match_definitions.push(decode_from);
        self
    }
    pub fn build(self) -> Result<Protocol, RegistrationError> {
        let dissector = self
            .dissector_fn
            .ok_or(RegistrationError::MissingDissector)?;

        unsafe {
            let proto_handle = epan_sys::proto_register_protocol(
                to_c_str(&self.name),
                to_c_str(&self.abbrev),
                to_c_str(&self.filter),
            );
            debug_assert!(proto_handle != -1);

            // Ett def list should include root ETT type
            let mut ett_defs = vec![Ett {
                id: ROOT_ETT_ID.to_string(),
                _name: format!("{} Protocol Tree", self.name),
            }];
            ett_defs.extend(self.ett);

            Ok(Protocol {
                _name: self.name,
                abbrev: self.abbrev,
                filter: self.filter,
                proto_handle,
                ett_defs,
                ett_handles: HashMap::new(),
                dissector_fn: dissector,
                field_defs: self.fields,       // Store the field definitions
                field_handles: HashMap::new(), // Will be populated during registration
                expert_module: ExpertModule {
                    expert_info_defs: self.expert_infos,
                    expert_fields_handles: HashMap::new(),
                    ptr: std::ptr::null_mut(), // Will be populated during registration
                },
                match_definitions: Some(self.match_definitions),
            })
        }
    }
}

#[derive(Clone)]
pub struct Field {
    pub id: String,
    pub name: String,
    pub abbrev: String,
    pub field_type: FieldType,
    pub display: FieldDisplay,
    pub strings: Option<Vec<(u32, String)>>,
    pub bitmask: u64,
    pub blurb: Option<String>,
}
