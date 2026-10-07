// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use crate::build_info::{
    BUILD_INFO_BINARY, BUILD_INFO_FIELDS, DATATYPE_BUILD_INFO, DATATYPE_STRUCTURE,
    NODEID_BUILD_INFO, NODEID_BUILD_INFO_TYPE, NODEID_DATA_TYPE_ENCODING_TYPE, NODEID_HAS_ENCODING,
    NODEID_HAS_MODELLING_RULE, NODEID_MANDATORY, NODEID_MODELLING_RULE_TYPE,
};
use opta_gateway_contracts::opcua_status;
use opta_runtime::{lookup_default_namespace_node, DEFAULT_NAMESPACE_NODES};

use crate::{
    product_object, status, BrowseDescription, BrowseReference, Encoder, NodeId, Result,
    DATATYPE_BASE_DATA_TYPE, DATATYPE_BOOLEAN, DATATYPE_BYTE, DATATYPE_DATETIME, DATATYPE_FLOAT,
    DATATYPE_INT32, DATATYPE_SERVER_STATUS, DATATYPE_STRING, DATATYPE_UINT32,
    MAX_BROWSE_REFERENCES_PER_RESULT, NODECLASS_DATA_TYPE, NODECLASS_OBJECT, NODECLASS_OBJECT_TYPE,
    NODECLASS_REFERENCE_TYPE, NODECLASS_VARIABLE, NODECLASS_VARIABLE_TYPE, NODEID_AGGREGATES,
    NODEID_BASE_DATA_VARIABLE_TYPE, NODEID_BASE_OBJECT_TYPE, NODEID_BASE_VARIABLE_TYPE,
    NODEID_FOLDER_TYPE, NODEID_HAS_CHILD, NODEID_HAS_COMPONENT, NODEID_HAS_PROPERTY,
    NODEID_HAS_SUBTYPE, NODEID_HAS_TYPE_DEFINITION, NODEID_HIERARCHICAL_REFERENCES,
    NODEID_NAMESPACE_ARRAY, NODEID_NON_HIERARCHICAL_REFERENCES, NODEID_OBJECTS_FOLDER,
    NODEID_ORGANIZES, NODEID_REFERENCES, NODEID_ROOT_FOLDER, NODEID_SERVER, NODEID_SERVER_ARRAY,
    NODEID_SERVER_SERVICE_LEVEL, NODEID_SERVER_STATUS, NODEID_SERVER_STATUS_CURRENT_TIME,
    NODEID_SERVER_STATUS_STATE, NODEID_TYPES_FOLDER, NODEID_VIEWS_FOLDER, PRODUCT_NAMESPACE_INDEX,
    PRODUCT_OBJECT_BUCHI, PRODUCT_OBJECT_HEALTH, PRODUCT_OBJECT_INFO, PRODUCT_OBJECT_PROCESS,
    PRODUCT_OBJECT_SETTINGS,
};

const RESULT_MASK_REFERENCE_TYPE: u32 = 0x01;
const RESULT_MASK_IS_FORWARD: u32 = 0x02;
const RESULT_MASK_NODE_CLASS: u32 = 0x04;
pub(crate) const RESULT_MASK_BROWSE_NAME: u32 = 0x08;
pub(crate) const RESULT_MASK_DISPLAY_NAME: u32 = 0x10;
const RESULT_MASK_TYPE_DEFINITION: u32 = 0x20;

pub(crate) fn write_browse_result(
    e: &mut Encoder<'_>,
    browse: BrowseDescription,
    requested_max: u32,
) -> Result<()> {
    if !node_exists(browse.node_id) {
        return write_browse_result_status(e, status::BAD_NODE_ID_UNKNOWN);
    }
    if !matches!(browse.browse_direction, 0..=2) {
        return write_browse_result_status(e, status::BAD_BROWSE_DIRECTION_INVALID);
    }
    if !reference_type_id_supported(browse.reference_type_id) {
        return write_browse_result_status(e, status::BAD_REFERENCE_TYPE_ID_INVALID);
    }

    let mut refs = [None; MAX_BROWSE_REFERENCES_PER_RESULT];
    let refs_len = collect_browse_references(browse.node_id, &mut refs);
    let mut matching = 0usize;
    for reference in refs.iter().take(refs_len).flatten() {
        if browse_reference_matches(browse, *reference) {
            matching += 1;
        }
    }
    if requested_max != 0 && matching > requested_max as usize {
        return write_browse_result_status(e, status::BAD_NO_CONTINUATION_POINTS);
    }

    e.write_u32(opcua_status::GOOD)?;
    e.write_null_byte_string()?;
    e.write_array_len(matching)?;
    for reference in refs.iter().take(refs_len).flatten() {
        if browse_reference_matches(browse, *reference) {
            write_reference(e, *reference, browse.result_mask)?;
        }
    }
    Ok(())
}

fn write_browse_result_status(e: &mut Encoder<'_>, status_code: u32) -> Result<()> {
    e.write_u32(status_code)?;
    e.write_null_byte_string()?;
    e.write_array_len(0)
}

fn node_exists(node: NodeId) -> bool {
    if node.namespace == 0 {
        (2260..=2266).contains(&node.identifier)
            || (3052..=3057).contains(&node.identifier)
            || matches!(
                node.identifier,
                DATATYPE_BUILD_INFO
                    | DATATYPE_STRUCTURE
                    | BUILD_INFO_BINARY
                    | NODEID_BUILD_INFO_TYPE
                    | NODEID_HAS_ENCODING
                    | NODEID_HAS_MODELLING_RULE
                    | NODEID_DATA_TYPE_ENCODING_TYPE
                    | NODEID_MODELLING_RULE_TYPE
                    | NODEID_MANDATORY
                    | NODEID_ROOT_FOLDER
                    | NODEID_OBJECTS_FOLDER
                    | NODEID_TYPES_FOLDER
                    | NODEID_VIEWS_FOLDER
                    | NODEID_SERVER
                    | NODEID_REFERENCES
                    | NODEID_NON_HIERARCHICAL_REFERENCES
                    | NODEID_HIERARCHICAL_REFERENCES
                    | NODEID_HAS_CHILD
                    | NODEID_ORGANIZES
                    | NODEID_AGGREGATES
                    | NODEID_HAS_SUBTYPE
                    | NODEID_HAS_TYPE_DEFINITION
                    | NODEID_HAS_PROPERTY
                    | NODEID_HAS_COMPONENT
                    | NODEID_BASE_OBJECT_TYPE
                    | NODEID_FOLDER_TYPE
                    | NODEID_BASE_VARIABLE_TYPE
                    | NODEID_BASE_DATA_VARIABLE_TYPE
                    | DATATYPE_BASE_DATA_TYPE
                    | DATATYPE_BOOLEAN
                    | DATATYPE_BYTE
                    | DATATYPE_INT32
                    | DATATYPE_UINT32
                    | DATATYPE_FLOAT
                    | DATATYPE_STRING
                    | DATATYPE_DATETIME
                    | DATATYPE_SERVER_STATUS
                    | NODEID_SERVER_ARRAY
                    | NODEID_NAMESPACE_ARRAY
                    | NODEID_SERVER_STATUS
                    | NODEID_SERVER_STATUS_CURRENT_TIME
                    | NODEID_SERVER_STATUS_STATE
                    | NODEID_SERVER_SERVICE_LEVEL
            )
    } else if node.namespace == PRODUCT_NAMESPACE_INDEX {
        let Ok(node_id) = u16::try_from(node.identifier) else {
            return false;
        };
        product_object(node_id).is_some() || lookup_default_namespace_node(node_id).is_some()
    } else {
        false
    }
}

fn reference_type_id_supported(reference_type: NodeId) -> bool {
    reference_type == NodeId::numeric(0, 0)
        || (reference_type.namespace == 0
            && matches!(
                reference_type.identifier,
                NODEID_REFERENCES
                    | NODEID_NON_HIERARCHICAL_REFERENCES
                    | NODEID_HIERARCHICAL_REFERENCES
                    | NODEID_HAS_CHILD
                    | NODEID_ORGANIZES
                    | NODEID_AGGREGATES
                    | NODEID_HAS_SUBTYPE
                    | NODEID_HAS_PROPERTY
                    | NODEID_HAS_COMPONENT
                    | NODEID_HAS_TYPE_DEFINITION
                    | NODEID_HAS_ENCODING
                    | NODEID_HAS_MODELLING_RULE
            ))
}

fn browse_reference_matches(browse: BrowseDescription, reference: BrowseReference) -> bool {
    if browse.browse_direction == 0 && !reference.is_forward {
        return false;
    }
    if browse.browse_direction == 1 && reference.is_forward {
        return false;
    }
    if browse.node_class_mask != 0 && (browse.node_class_mask & reference.node_class as u32) == 0 {
        return false;
    }
    if browse.reference_type_id == NodeId::numeric(0, 0) {
        return true;
    }
    if browse.reference_type_id.namespace != 0 {
        return false;
    }
    let requested = browse.reference_type_id.identifier;
    requested == reference.reference_type_id
        || (browse.include_subtypes
            && reference_is_subtype_of(reference.reference_type_id, requested))
}

fn reference_is_subtype_of(reference_type_id: u32, requested: u32) -> bool {
    match requested {
        NODEID_REFERENCES => true,
        NODEID_NON_HIERARCHICAL_REFERENCES => {
            matches!(
                reference_type_id,
                NODEID_HAS_TYPE_DEFINITION | NODEID_HAS_ENCODING | NODEID_HAS_MODELLING_RULE
            )
        }
        NODEID_HIERARCHICAL_REFERENCES => matches!(
            reference_type_id,
            NODEID_HAS_CHILD
                | NODEID_ORGANIZES
                | NODEID_AGGREGATES
                | NODEID_HAS_SUBTYPE
                | NODEID_HAS_PROPERTY
                | NODEID_HAS_COMPONENT
        ),
        NODEID_HAS_CHILD => matches!(
            reference_type_id,
            NODEID_AGGREGATES | NODEID_HAS_SUBTYPE | NODEID_HAS_PROPERTY | NODEID_HAS_COMPONENT
        ),
        NODEID_AGGREGATES => matches!(
            reference_type_id,
            NODEID_HAS_PROPERTY | NODEID_HAS_COMPONENT
        ),
        _ => false,
    }
}

fn collect_browse_references(
    node: NodeId,
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
) -> usize {
    let mut len = 0usize;
    if node.namespace == 0 {
        match node.identifier {
            NODEID_BUILD_INFO | NODEID_BUILD_INFO_TYPE => {
                for (index, (id, name)) in BUILD_INFO_FIELDS.iter().enumerate() {
                    let id = if node.identifier == NODEID_BUILD_INFO_TYPE {
                        3052 + index as u32
                    } else {
                        *id
                    };
                    push_variable_ref(
                        refs,
                        &mut len,
                        NODEID_HAS_COMPONENT,
                        NodeId::numeric(0, id),
                        name,
                        0,
                        NODEID_BASE_DATA_VARIABLE_TYPE,
                    );
                }
                if node.identifier == NODEID_BUILD_INFO {
                    push_type_definition_ref(refs, &mut len, NODEID_BUILD_INFO_TYPE);
                }
            }
            2261..=2266 | 3052..=3057 => {
                push_type_definition_ref(refs, &mut len, NODEID_BASE_DATA_VARIABLE_TYPE);
                if (3052..=3057).contains(&node.identifier) {
                    push_object_ref(
                        refs,
                        &mut len,
                        NODEID_HAS_MODELLING_RULE,
                        NodeId::numeric(0, NODEID_MANDATORY),
                        "Mandatory",
                        0,
                        NODEID_MODELLING_RULE_TYPE,
                    );
                }
                push_reference(
                    refs,
                    &mut len,
                    BrowseReference {
                        reference_type_id: NODEID_HAS_COMPONENT,
                        is_forward: false,
                        target_node_id: NodeId::numeric(
                            0,
                            if node.identifier < 3000 {
                                NODEID_BUILD_INFO
                            } else {
                                NODEID_BUILD_INFO_TYPE
                            },
                        ),
                        browse_name: if node.identifier < 3000 {
                            "BuildInfo"
                        } else {
                            "BuildInfoType"
                        },
                        browse_namespace: 0,
                        node_class: if node.identifier < 3000 {
                            NODECLASS_VARIABLE
                        } else {
                            NODECLASS_VARIABLE_TYPE
                        },
                        type_definition: if node.identifier < 3000 {
                            NODEID_BUILD_INFO_TYPE
                        } else {
                            0
                        },
                    },
                );
            }
            NODEID_MANDATORY => {
                push_type_definition_ref(refs, &mut len, NODEID_MODELLING_RULE_TYPE);
            }
            DATATYPE_BUILD_INFO => {
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_ENCODING,
                    NodeId::numeric(0, BUILD_INFO_BINARY),
                    "Default Binary",
                    0,
                    NODEID_DATA_TYPE_ENCODING_TYPE,
                );
            }
            BUILD_INFO_BINARY => {
                push_type_definition_ref(refs, &mut len, NODEID_DATA_TYPE_ENCODING_TYPE);
                push_reference(
                    refs,
                    &mut len,
                    BrowseReference {
                        reference_type_id: NODEID_HAS_ENCODING,
                        is_forward: false,
                        target_node_id: NodeId::numeric(0, DATATYPE_BUILD_INFO),
                        browse_name: "BuildInfo",
                        browse_namespace: 0,
                        node_class: NODECLASS_DATA_TYPE,
                        type_definition: 0,
                    },
                );
            }
            NODEID_ROOT_FOLDER => {
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_ORGANIZES,
                    NodeId::numeric(0, NODEID_OBJECTS_FOLDER),
                    "Objects",
                    0,
                    NODEID_FOLDER_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_ORGANIZES,
                    NodeId::numeric(0, NODEID_TYPES_FOLDER),
                    "Types",
                    0,
                    NODEID_FOLDER_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_ORGANIZES,
                    NodeId::numeric(0, NODEID_VIEWS_FOLDER),
                    "Views",
                    0,
                    NODEID_FOLDER_TYPE,
                );
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            NODEID_OBJECTS_FOLDER => {
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_ORGANIZES,
                    NodeId::numeric(0, NODEID_SERVER),
                    "Server",
                    0,
                    NODEID_BASE_OBJECT_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_ORGANIZES,
                    NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_BUCHI as u32),
                    "Buchi",
                    PRODUCT_NAMESPACE_INDEX,
                    NODEID_FOLDER_TYPE,
                );
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            NODEID_TYPES_FOLDER | NODEID_VIEWS_FOLDER => {
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            NODEID_SERVER => {
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_SERVER_ARRAY),
                    "ServerArray",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_NAMESPACE_ARRAY),
                    "NamespaceArray",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_SERVER_STATUS),
                    "ServerStatus",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_PROPERTY,
                    NodeId::numeric(0, NODEID_SERVER_SERVICE_LEVEL),
                    "ServiceLevel",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_type_definition_ref(refs, &mut len, NODEID_BASE_OBJECT_TYPE);
            }
            NODEID_SERVER_ARRAY
            | NODEID_NAMESPACE_ARRAY
            | NODEID_SERVER_STATUS_CURRENT_TIME
            | NODEID_SERVER_STATUS_STATE
            | NODEID_SERVER_SERVICE_LEVEL => {
                push_type_definition_ref(refs, &mut len, NODEID_BASE_DATA_VARIABLE_TYPE);
            }
            NODEID_SERVER_STATUS => {
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_BUILD_INFO),
                    "BuildInfo",
                    0,
                    NODEID_BUILD_INFO_TYPE,
                );
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_SERVER_STATUS_CURRENT_TIME),
                    "CurrentTime",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_variable_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(0, NODEID_SERVER_STATUS_STATE),
                    "State",
                    0,
                    NODEID_BASE_DATA_VARIABLE_TYPE,
                );
                push_type_definition_ref(refs, &mut len, NODEID_BASE_DATA_VARIABLE_TYPE);
            }
            _ => {}
        }
    } else if node.namespace == PRODUCT_NAMESPACE_INDEX {
        match u16::try_from(node.identifier).ok() {
            Some(PRODUCT_OBJECT_BUCHI) => {
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_INFO as u32),
                    "Info",
                    PRODUCT_NAMESPACE_INDEX,
                    NODEID_FOLDER_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_PROCESS as u32),
                    "Process",
                    PRODUCT_NAMESPACE_INDEX,
                    NODEID_FOLDER_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_SETTINGS as u32),
                    "Settings",
                    PRODUCT_NAMESPACE_INDEX,
                    NODEID_FOLDER_TYPE,
                );
                push_object_ref(
                    refs,
                    &mut len,
                    NODEID_HAS_COMPONENT,
                    NodeId::numeric(PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_HEALTH as u32),
                    "Health",
                    PRODUCT_NAMESPACE_INDEX,
                    NODEID_FOLDER_TYPE,
                );
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            Some(PRODUCT_OBJECT_INFO) => {
                collect_namespace_range_references(refs, &mut len, 1001, 1999);
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            Some(PRODUCT_OBJECT_PROCESS) => {
                collect_namespace_range_references(refs, &mut len, 2001, 2999);
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            Some(PRODUCT_OBJECT_SETTINGS) => {
                collect_namespace_range_references(refs, &mut len, 3001, 3999);
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            Some(PRODUCT_OBJECT_HEALTH) => {
                collect_namespace_range_references(refs, &mut len, 4001, 4999);
                push_type_definition_ref(refs, &mut len, NODEID_FOLDER_TYPE);
            }
            Some(node_id) if lookup_default_namespace_node(node_id).is_some() => {
                push_type_definition_ref(refs, &mut len, NODEID_BASE_DATA_VARIABLE_TYPE);
            }
            _ => {}
        }
    }
    if node.namespace == 0 {
        if node.identifier == NODEID_BUILD_INFO {
            push_reference(
                refs,
                &mut len,
                BrowseReference {
                    reference_type_id: NODEID_HAS_COMPONENT,
                    is_forward: false,
                    target_node_id: NodeId::numeric(0, NODEID_SERVER_STATUS),
                    browse_name: "ServerStatus",
                    browse_namespace: 0,
                    node_class: NODECLASS_VARIABLE,
                    type_definition: NODEID_BASE_DATA_VARIABLE_TYPE,
                },
            );
        }
        if let Some(parent) = standard_subtype_parent(node.identifier) {
            push_inverse_subtype_ref(refs, &mut len, parent);
        }
    }
    len
}

fn standard_subtype_parent(node_id: u32) -> Option<u32> {
    match node_id {
        NODEID_NON_HIERARCHICAL_REFERENCES | NODEID_HIERARCHICAL_REFERENCES => {
            Some(NODEID_REFERENCES)
        }
        NODEID_HAS_CHILD | NODEID_ORGANIZES => Some(NODEID_HIERARCHICAL_REFERENCES),
        NODEID_AGGREGATES | NODEID_HAS_SUBTYPE => Some(NODEID_HAS_CHILD),
        NODEID_HAS_PROPERTY | NODEID_HAS_COMPONENT => Some(NODEID_AGGREGATES),
        NODEID_HAS_TYPE_DEFINITION | NODEID_HAS_ENCODING | NODEID_HAS_MODELLING_RULE => {
            Some(NODEID_NON_HIERARCHICAL_REFERENCES)
        }
        NODEID_BUILD_INFO_TYPE => Some(NODEID_BASE_DATA_VARIABLE_TYPE),
        NODEID_DATA_TYPE_ENCODING_TYPE | NODEID_MODELLING_RULE_TYPE => {
            Some(NODEID_BASE_OBJECT_TYPE)
        }
        DATATYPE_BUILD_INFO => Some(DATATYPE_STRUCTURE),
        DATATYPE_STRUCTURE => Some(DATATYPE_BASE_DATA_TYPE),
        NODEID_FOLDER_TYPE => Some(NODEID_BASE_OBJECT_TYPE),
        NODEID_BASE_DATA_VARIABLE_TYPE => Some(NODEID_BASE_VARIABLE_TYPE),
        DATATYPE_BOOLEAN
        | DATATYPE_BYTE
        | DATATYPE_INT32
        | DATATYPE_UINT32
        | DATATYPE_FLOAT
        | DATATYPE_STRING
        | DATATYPE_DATETIME
        | DATATYPE_SERVER_STATUS => Some(DATATYPE_BASE_DATA_TYPE),
        _ => None,
    }
}

fn standard_node_browse_info(node_id: u32) -> Option<(&'static str, i32)> {
    match node_id {
        DATATYPE_STRUCTURE => Some(("Structure", NODECLASS_DATA_TYPE)),
        DATATYPE_BUILD_INFO => Some(("BuildInfo", NODECLASS_DATA_TYPE)),
        NODEID_BUILD_INFO_TYPE => Some(("BuildInfoType", NODECLASS_VARIABLE_TYPE)),
        NODEID_HAS_MODELLING_RULE => Some(("HasModellingRule", NODECLASS_REFERENCE_TYPE)),
        NODEID_MODELLING_RULE_TYPE => Some(("ModellingRuleType", NODECLASS_OBJECT_TYPE)),
        NODEID_HAS_ENCODING => Some(("HasEncoding", NODECLASS_REFERENCE_TYPE)),
        NODEID_DATA_TYPE_ENCODING_TYPE => Some(("DataTypeEncodingType", NODECLASS_OBJECT_TYPE)),
        NODEID_REFERENCES => Some(("References", NODECLASS_REFERENCE_TYPE)),
        NODEID_NON_HIERARCHICAL_REFERENCES => {
            Some(("NonHierarchicalReferences", NODECLASS_REFERENCE_TYPE))
        }
        NODEID_HIERARCHICAL_REFERENCES => {
            Some(("HierarchicalReferences", NODECLASS_REFERENCE_TYPE))
        }
        NODEID_HAS_CHILD => Some(("HasChild", NODECLASS_REFERENCE_TYPE)),
        NODEID_ORGANIZES => Some(("Organizes", NODECLASS_REFERENCE_TYPE)),
        NODEID_AGGREGATES => Some(("Aggregates", NODECLASS_REFERENCE_TYPE)),
        NODEID_HAS_SUBTYPE => Some(("HasSubtype", NODECLASS_REFERENCE_TYPE)),
        NODEID_HAS_TYPE_DEFINITION => Some(("HasTypeDefinition", NODECLASS_REFERENCE_TYPE)),
        NODEID_HAS_PROPERTY => Some(("HasProperty", NODECLASS_REFERENCE_TYPE)),
        NODEID_HAS_COMPONENT => Some(("HasComponent", NODECLASS_REFERENCE_TYPE)),
        NODEID_BASE_OBJECT_TYPE => Some(("BaseObjectType", NODECLASS_OBJECT_TYPE)),
        NODEID_FOLDER_TYPE => Some(("FolderType", NODECLASS_OBJECT_TYPE)),
        NODEID_BASE_VARIABLE_TYPE => Some(("BaseVariableType", NODECLASS_VARIABLE_TYPE)),
        NODEID_BASE_DATA_VARIABLE_TYPE => Some(("BaseDataVariableType", NODECLASS_VARIABLE_TYPE)),
        DATATYPE_BASE_DATA_TYPE => Some(("BaseDataType", NODECLASS_DATA_TYPE)),
        DATATYPE_BOOLEAN => Some(("Boolean", NODECLASS_DATA_TYPE)),
        DATATYPE_BYTE => Some(("Byte", NODECLASS_DATA_TYPE)),
        DATATYPE_INT32 => Some(("Int32", NODECLASS_DATA_TYPE)),
        DATATYPE_UINT32 => Some(("UInt32", NODECLASS_DATA_TYPE)),
        DATATYPE_FLOAT => Some(("Float", NODECLASS_DATA_TYPE)),
        DATATYPE_STRING => Some(("String", NODECLASS_DATA_TYPE)),
        DATATYPE_DATETIME => Some(("DateTime", NODECLASS_DATA_TYPE)),
        DATATYPE_SERVER_STATUS => Some(("ServerStatusDataType", NODECLASS_DATA_TYPE)),
        _ => None,
    }
}

fn collect_namespace_range_references(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    start: u16,
    end: u16,
) {
    for node in DEFAULT_NAMESPACE_NODES
        .iter()
        .filter(|node| node.node_id >= start && node.node_id <= end)
    {
        push_variable_ref(
            refs,
            len,
            NODEID_HAS_COMPONENT,
            NodeId::numeric(PRODUCT_NAMESPACE_INDEX, u32::from(node.node_id)),
            node.browse_name,
            PRODUCT_NAMESPACE_INDEX,
            NODEID_BASE_DATA_VARIABLE_TYPE,
        );
    }
}

fn push_object_ref(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    reference_type_id: u32,
    node_id: NodeId,
    browse_name: &'static str,
    browse_namespace: u16,
    type_definition: u32,
) {
    push_reference(
        refs,
        len,
        BrowseReference {
            reference_type_id,
            is_forward: true,
            target_node_id: node_id,
            browse_name,
            browse_namespace,
            node_class: NODECLASS_OBJECT,
            type_definition,
        },
    );
}

fn push_variable_ref(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    reference_type_id: u32,
    node_id: NodeId,
    browse_name: &'static str,
    browse_namespace: u16,
    type_definition: u32,
) {
    push_reference(
        refs,
        len,
        BrowseReference {
            reference_type_id,
            is_forward: true,
            target_node_id: node_id,
            browse_name,
            browse_namespace,
            node_class: NODECLASS_VARIABLE,
            type_definition,
        },
    );
}

fn push_type_definition_ref(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    type_definition: u32,
) {
    let (browse_name, node_class) = match type_definition {
        NODEID_MODELLING_RULE_TYPE => ("ModellingRuleType", NODECLASS_OBJECT_TYPE),
        NODEID_BUILD_INFO_TYPE => ("BuildInfoType", NODECLASS_VARIABLE_TYPE),
        NODEID_DATA_TYPE_ENCODING_TYPE => ("DataTypeEncodingType", NODECLASS_OBJECT_TYPE),
        NODEID_BASE_DATA_VARIABLE_TYPE => ("BaseDataVariableType", NODECLASS_VARIABLE_TYPE),
        NODEID_BASE_VARIABLE_TYPE => ("BaseVariableType", NODECLASS_VARIABLE_TYPE),
        NODEID_BASE_OBJECT_TYPE => ("BaseObjectType", NODECLASS_OBJECT_TYPE),
        NODEID_FOLDER_TYPE => ("FolderType", NODECLASS_OBJECT_TYPE),
        _ => ("BaseObjectType", NODECLASS_OBJECT_TYPE),
    };
    push_reference(
        refs,
        len,
        BrowseReference {
            reference_type_id: NODEID_HAS_TYPE_DEFINITION,
            is_forward: true,
            target_node_id: NodeId::numeric(0, type_definition),
            browse_name,
            browse_namespace: 0,
            node_class,
            type_definition: 0,
        },
    );
}

fn push_inverse_subtype_ref(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    parent_node_id: u32,
) {
    let Some((browse_name, node_class)) = standard_node_browse_info(parent_node_id) else {
        return;
    };
    push_reference(
        refs,
        len,
        BrowseReference {
            reference_type_id: NODEID_HAS_SUBTYPE,
            is_forward: false,
            target_node_id: NodeId::numeric(0, parent_node_id),
            browse_name,
            browse_namespace: 0,
            node_class,
            type_definition: 0,
        },
    );
}

fn push_reference(
    refs: &mut [Option<BrowseReference>; MAX_BROWSE_REFERENCES_PER_RESULT],
    len: &mut usize,
    reference: BrowseReference,
) {
    if *len < refs.len() {
        refs[*len] = Some(reference);
        *len += 1;
    }
}

fn write_reference(
    e: &mut Encoder<'_>,
    reference: BrowseReference,
    result_mask: u32,
) -> Result<()> {
    if result_mask & RESULT_MASK_REFERENCE_TYPE != 0 {
        e.write_node_id(NodeId::numeric(0, reference.reference_type_id))?;
    } else {
        e.write_node_id(NodeId::numeric(0, 0))?;
    }
    e.write_bool(result_mask & RESULT_MASK_IS_FORWARD != 0 && reference.is_forward)?;
    e.write_expanded_node_id(reference.target_node_id)?;
    if result_mask & RESULT_MASK_BROWSE_NAME != 0 {
        e.write_qualified_name(reference.browse_namespace, reference.browse_name)?;
    } else {
        e.write_qualified_name(0, "")?;
    }
    if result_mask & RESULT_MASK_DISPLAY_NAME != 0 {
        e.write_localized_text(reference.browse_name)?;
    } else {
        e.write_u8(0)?;
    }
    if result_mask & RESULT_MASK_NODE_CLASS != 0 {
        e.write_i32(reference.node_class)?;
    } else {
        e.write_i32(0)?;
    }
    if result_mask & RESULT_MASK_TYPE_DEFINITION != 0 {
        e.write_expanded_node_id(NodeId::numeric(0, reference.type_definition))
    } else {
        e.write_expanded_node_id(NodeId::numeric(0, 0))
    }
}
