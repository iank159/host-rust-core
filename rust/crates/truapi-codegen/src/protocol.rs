//! Semantic protocol model, resolved once between rustdoc extraction and emission.
use crate::RESERVED_PROTOCOL_ERROR_ID;
use crate::rustdoc::{self as raw, *};
use anyhow::{Result, bail};
use convert_case::{Case, Casing};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;

#[derive(Debug)]
pub struct ApiDefinition {
    raw: raw::ApiDefinition,
    pub traits: Vec<TraitDef>,
    pub wrappers: HashMap<String, VersionedWrapper>,
}
impl Deref for ApiDefinition {
    type Target = raw::ApiDefinition;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

#[derive(Debug)]
pub struct TraitDef {
    raw: raw::TraitDef,
    pub methods: Vec<MethodDef>,
    required_execution: Option<String>,
}
impl Deref for TraitDef {
    type Target = raw::TraitDef;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}
impl TraitDef {
    pub fn required_execution(&self) -> Option<&str> {
        self.required_execution.as_deref()
    }
}

#[derive(Debug)]
pub struct MethodDef {
    raw: raw::MethodDef,
    pub wire_ids: ExpandedWireIds,
    pub sensitive: bool,
    pub host_initiated: bool,
    pub wire_name: String,
    pub wire_constant: String,
    pub supported_versions: Option<Vec<u32>>,
    pub referenced_types: BTreeSet<String>,
}
impl MethodDef {
    pub fn is_included(&self, target_version: u32) -> bool {
        self.supported_versions
            .as_ref()
            .is_none_or(|versions| versions.iter().any(|version| *version <= target_version))
    }

    /// Highest version shared by all wrappers, up to the target version.
    pub fn wire_version(&self, target_version: u32) -> Option<u32> {
        self.supported_versions.as_ref().and_then(|versions| {
            versions
                .iter()
                .copied()
                .filter(|version| *version <= target_version)
                .max()
        })
    }
}

impl Deref for MethodDef {
    type Target = raw::MethodDef;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl ApiDefinition {
    pub fn new(raw: &raw::ApiDefinition) -> Result<Self> {
        validate_versioned_wrapper_shapes(raw)?;
        let wrappers = collect_versioned_wrappers(raw);
        let mut ids = BTreeMap::from([(
            RESERVED_PROTOCOL_ERROR_ID,
            "reserved for protocol errors".to_owned(),
        )]);
        let mut names = BTreeSet::new();
        let mut traits = Vec::new();
        for trait_def in &raw.traits {
            let mut methods = Vec::new();
            for method in &trait_def.methods {
                let wire_ids = wire_ids_for_method(trait_def, method)?;
                let wire_name = wire_method_name(&trait_def.name, &method.name);
                if !names.insert(wire_name.clone()) {
                    bail!("wire method name `{wire_name}` reused: registered twice");
                }
                for (id, tag) in wire_ids.entries(&wire_name) {
                    if let Some(existing) = ids.insert(id, tag.clone()) {
                        bail!("wire id {id} reused: `{existing}` and `{tag}` collide");
                    }
                }
                let mut referenced_types = BTreeSet::new();
                for param in &method.params {
                    collect_names(&param.type_ref, &mut referenced_types);
                }
                match &method.return_type {
                    ReturnType::Result { ok, err } => {
                        collect_names(ok, &mut referenced_types);
                        collect_names(err, &mut referenced_types);
                    }
                    ReturnType::Subscription(item) => collect_names(item, &mut referenced_types),
                    ReturnType::ResultSubscription { item, err } => {
                        collect_names(item, &mut referenced_types);
                        collect_names(err, &mut referenced_types);
                    }
                }
                let mut supported_versions: Option<Vec<u32>> = None;
                for wrapper in referenced_types
                    .iter()
                    .filter_map(|name| wrappers.get(name))
                {
                    let versions: Vec<_> = wrapper.variants.keys().copied().collect();
                    supported_versions = Some(match supported_versions {
                        None => versions,
                        Some(current) => current
                            .into_iter()
                            .filter(|v| versions.contains(v))
                            .collect(),
                    });
                }
                methods.push(MethodDef {
                    raw: method.clone(),
                    sensitive: method.wire.sensitive,
                    host_initiated: method.wire.host_initiated,
                    wire_ids,
                    wire_constant: wire_const_name(&trait_def.name, &method.name),
                    wire_name,
                    supported_versions,
                    referenced_types,
                });
            }
            traits.push(TraitDef {
                raw: trait_def.clone(),
                methods,
                required_execution: trait_def.required_execution().map(str::to_owned),
            });
        }
        Ok(Self {
            raw: raw.clone(),
            traits,
            wrappers,
        })
    }
}

fn collect_names(ty: &TypeRef, out: &mut BTreeSet<String>) {
    match ty {
        TypeRef::Named { name, args } => {
            out.insert(name.clone());
            for arg in args {
                collect_names(arg, out);
            }
        }
        TypeRef::Vec(inner) | TypeRef::Option(inner) | TypeRef::Array(inner, _) => {
            collect_names(inner, out)
        }
        TypeRef::Tuple(items) => {
            for item in items {
                collect_names(item, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn wire_method_name(trait_name: &str, method_name: &str) -> String {
    format!("{}_{}", trait_name.to_case(Case::Snake), method_name)
}
pub(crate) fn const_name(wire_method: &str) -> String {
    wire_method.to_case(Case::UpperSnake)
}
pub(crate) fn wire_const_name(trait_name: &str, method_name: &str) -> String {
    const_name(&wire_method_name(trait_name, method_name))
}

/// A versioned enum wrapper like `enum HostSignPayloadRequest { V2(Inner) }`,
/// `enum HostCreateTransactionRequest { V2(CreateTransactionRequest) }`,
/// or a multi-version enum `enum HostDevicePermissionRequest { V1(_), V2(_) }`.
///
/// The client generator selects the latest wrapper variant up to its target
/// protocol version, so a V2 package emits V2 wire payloads when available and
/// falls back to V1 for wrappers whose shape did not change.
#[derive(Debug, Clone)]
pub(crate) struct VersionedWrapper {
    pub(crate) variants: BTreeMap<u32, VersionedWrapperVariant>,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionedWrapperVariant {
    pub(crate) version: u32,
    pub(crate) kind: VersionedKind,
}

#[derive(Debug, Clone)]
pub(crate) enum VersionedKind {
    Unit,
    Tuple(TypeRef),
}

pub(crate) fn detect_versioned_wrapper(ty: &TypeDef) -> Option<VersionedWrapper> {
    if !ty.generic_params.is_empty() {
        return None;
    }
    let TypeDefKind::Enum(variants) = &ty.kind else {
        return None;
    };
    if variants.is_empty() || !variants.iter().all(|v| is_versioned_variant_name(&v.name)) {
        return None;
    }
    let mut version_variants = BTreeMap::new();
    for variant in variants {
        let version = version_number(&variant.name)?;
        let kind = match &variant.fields {
            VariantFields::Unit => VersionedKind::Unit,
            VariantFields::Unnamed(types) if types.len() == 1 => {
                VersionedKind::Tuple(types[0].clone())
            }
            _ => return None,
        };
        version_variants.insert(version, VersionedWrapperVariant { version, kind });
    }

    Some(VersionedWrapper {
        variants: version_variants,
    })
}

pub(crate) fn is_versioned_variant_name(name: &str) -> bool {
    version_number(name).is_some()
}

pub(crate) fn version_number(name: &str) -> Option<u32> {
    let rest = name.strip_prefix('V')?;
    if rest.is_empty() {
        return None;
    }
    rest.parse().ok()
}

pub(crate) fn collect_versioned_wrappers(
    api: &raw::ApiDefinition,
) -> HashMap<String, VersionedWrapper> {
    api.types
        .iter()
        .filter_map(|ty| detect_versioned_wrapper(ty).map(|w| (ty.name.clone(), w)))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpandedWireIds {
    Request {
        request_id: u8,
        response_id: u8,
    },
    Subscription {
        start_id: u8,
        stop_id: u8,
        interrupt_id: u8,
        receive_id: u8,
    },
}

impl ExpandedWireIds {
    pub(crate) fn sort_id(self) -> u8 {
        match self {
            ExpandedWireIds::Request { request_id, .. } => request_id,
            ExpandedWireIds::Subscription { start_id, .. } => start_id,
        }
    }

    pub(crate) fn entries(self, method_name: &str) -> Vec<(u8, String)> {
        match self {
            ExpandedWireIds::Request {
                request_id,
                response_id,
            } => vec![
                (request_id, format!("{method_name}_request")),
                (response_id, format!("{method_name}_response")),
            ],
            ExpandedWireIds::Subscription {
                start_id,
                stop_id,
                interrupt_id,
                receive_id,
            } => vec![
                (start_id, format!("{method_name}_start")),
                (stop_id, format!("{method_name}_stop")),
                (interrupt_id, format!("{method_name}_interrupt")),
                (receive_id, format!("{method_name}_receive")),
            ],
        }
    }
}

fn wire_ids_for_method(
    trait_def: &raw::TraitDef,
    method: &raw::MethodDef,
) -> Result<ExpandedWireIds> {
    let wire = &method.wire;
    match method.kind {
        MethodKind::Request => {
            if wire.start_id.is_some()
                || wire.stop_id.is_some()
                || wire.interrupt_id.is_some()
                || wire.receive_id.is_some()
            {
                bail!(
                    "method `{}::{}` is a request and must not use subscription wire ids",
                    trait_def.name,
                    method.name
                );
            }
            let request_id = wire.request_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "method `{}::{}` is missing #[wire(request_id = N)] annotation",
                    trait_def.name,
                    method.name
                )
            })?;
            let response_id =
                infer_wire_id(wire.response_id, request_id, 1, &method.name, "response_id")?;
            Ok(ExpandedWireIds::Request {
                request_id,
                response_id,
            })
        }
        MethodKind::Subscription | MethodKind::ResultSubscription => {
            if wire.request_id.is_some() || wire.response_id.is_some() {
                bail!(
                    "method `{}::{}` is a subscription and must not use request wire ids",
                    trait_def.name,
                    method.name
                );
            }
            let start_id = wire.start_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "method `{}::{}` is missing #[wire(start_id = N)] annotation",
                    trait_def.name,
                    method.name
                )
            })?;
            let stop_id = infer_wire_id(wire.stop_id, start_id, 1, &method.name, "stop_id")?;
            let interrupt_id =
                infer_wire_id(wire.interrupt_id, start_id, 2, &method.name, "interrupt_id")?;
            let receive_id =
                infer_wire_id(wire.receive_id, start_id, 3, &method.name, "receive_id")?;
            Ok(ExpandedWireIds::Subscription {
                start_id,
                stop_id,
                interrupt_id,
                receive_id,
            })
        }
    }
}

fn infer_wire_id(
    explicit: Option<u8>,
    anchor_id: u8,
    offset: u8,
    method_name: &str,
    field_name: &str,
) -> Result<u8> {
    explicit.map_or_else(
        || {
            anchor_id.checked_add(offset).ok_or_else(|| {
                anyhow::anyhow!(
                    "wire id overflow on `{method_name}` while inferring `{field_name}` from {anchor_id}"
                )
            })
        },
        Ok,
    )
}

fn validate_versioned_wrapper_shapes(api: &raw::ApiDefinition) -> Result<()> {
    for ty in &api.types {
        let TypeDefKind::Enum(variants) = &ty.kind else {
            continue;
        };
        if variants.is_empty() || !variants.iter().all(|v| is_versioned_variant_name(&v.name)) {
            continue;
        }
        for variant in variants {
            if matches!(variant.fields, VariantFields::Named(_)) {
                bail!(
                    "versioned wrapper `{}` variant `{}` uses named fields; define a request/response struct in the v0x module and wrap it as `{}`(v0x::MyStruct)",
                    ty.name,
                    variant.name,
                    variant.name
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_ids_flags_and_shared_versions_before_emission() {
        let wrapper = |name: &str, versions: &[u32]| TypeDef {
            name: name.into(),
            module_path: vec![],
            generic_params: vec![],
            docs: None,
            kind: TypeDefKind::Enum(
                versions
                    .iter()
                    .map(|version| VariantDef {
                        name: format!("V{version}"),
                        fields: VariantFields::Unit,
                        docs: None,
                        codec_index: None,
                    })
                    .collect(),
            ),
        };
        let named = |name: &str| TypeRef::Named {
            name: name.into(),
            args: vec![],
        };
        let raw = raw::ApiDefinition {
            public_trait_order: vec!["HTTPServer".into()],
            framework_types: vec![],
            types: vec![wrapper("Request", &[1, 3]), wrapper("Response", &[2, 3])],
            traits: vec![raw::TraitDef {
                name: "HTTPServer".into(),
                module_path: vec![],
                docs: None,
                methods: vec![raw::MethodDef {
                    name: "read".into(),
                    kind: MethodKind::Request,
                    params: vec![ParamDef {
                        name: "request".into(),
                        type_ref: named("Request"),
                    }],
                    return_type: ReturnType::Result {
                        ok: named("Response"),
                        err: TypeRef::Unit,
                    },
                    wire: WireAttrs {
                        request_id: Some(40),
                        sensitive: true,
                        ..WireAttrs::default()
                    },
                    docs: None,
                }],
            }],
        };
        let protocol = ApiDefinition::new(&raw).unwrap();
        let method = &protocol.traits[0].methods[0];
        assert_eq!(method.wire_name, "http_server_read");
        assert_eq!(method.wire_constant, "HTTP_SERVER_READ");
        assert_eq!(
            method.wire_ids,
            ExpandedWireIds::Request {
                request_id: 40,
                response_id: 41
            }
        );
        assert_eq!(method.supported_versions, Some(vec![3]));
        assert!(method.sensitive);
        assert!(!method.host_initiated);
        assert_eq!(
            method.referenced_types,
            BTreeSet::from(["Request".into(), "Response".into()])
        );
        assert_eq!(raw.traits[0].methods[0].wire.response_id, None);
    }
}
