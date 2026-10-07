// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use crate::build_info::{
    BuildInfo, BUILD_INFO_BINARY, BUILD_INFO_FIELDS, DATATYPE_BUILD_INFO, DATATYPE_STRUCTURE,
    NODEID_BUILD_INFO, NODEID_BUILD_INFO_TYPE, NODEID_DATA_TYPE_ENCODING_TYPE, NODEID_HAS_ENCODING,
    NODEID_HAS_MODELLING_RULE, NODEID_MANDATORY, NODEID_MODELLING_RULE_TYPE,
};
use core::convert::TryFrom;

use opta_gateway_contracts::freshness::ScalarValue;
use opta_gateway_contracts::namespace::{Access, ValueKind};
use opta_gateway_contracts::opcua_status;
use opta_runtime::{lookup_default_namespace_node, RuntimeDataAccess};

use crate::{
    status, DecodedScalar, DecodedWriteValue, Encoder, NodeId, ReadValueId, Result,
    ATTR_ACCESSLEVEL, ATTR_BROWSENAME, ATTR_DATATYPE, ATTR_DISPLAYNAME, ATTR_EVENTNOTIFIER,
    ATTR_HISTORIZING, ATTR_NODECLASS, ATTR_NODEID, ATTR_USERACCESSLEVEL, ATTR_VALUE,
    ATTR_VALUERANK, DATATYPE_BASE_DATA_TYPE, DATATYPE_BOOLEAN, DATATYPE_BYTE, DATATYPE_DATETIME,
    DATATYPE_FLOAT, DATATYPE_INT32, DATATYPE_SERVER_STATUS, DATATYPE_STRING, DATATYPE_UINT32,
    NODECLASS_DATA_TYPE, NODECLASS_OBJECT, NODECLASS_OBJECT_TYPE, NODECLASS_REFERENCE_TYPE,
    NODECLASS_VARIABLE, NODECLASS_VARIABLE_TYPE, NODEID_AGGREGATES, NODEID_BASE_DATA_VARIABLE_TYPE,
    NODEID_BASE_OBJECT_TYPE, NODEID_BASE_VARIABLE_TYPE, NODEID_FOLDER_TYPE, NODEID_HAS_CHILD,
    NODEID_HAS_COMPONENT, NODEID_HAS_PROPERTY, NODEID_HAS_SUBTYPE, NODEID_HAS_TYPE_DEFINITION,
    NODEID_HIERARCHICAL_REFERENCES, NODEID_NAMESPACE_ARRAY, NODEID_NON_HIERARCHICAL_REFERENCES,
    NODEID_OBJECTS_FOLDER, NODEID_ORGANIZES, NODEID_REFERENCES, NODEID_ROOT_FOLDER, NODEID_SERVER,
    NODEID_SERVER_ARRAY, NODEID_SERVER_SERVICE_LEVEL, NODEID_SERVER_STATUS,
    NODEID_SERVER_STATUS_CURRENT_TIME, NODEID_SERVER_STATUS_STATE, NODEID_TYPES_FOLDER,
    NODEID_VIEWS_FOLDER, PRODUCT_NAMESPACE_INDEX, PRODUCT_OBJECT_BUCHI, PRODUCT_OBJECT_HEALTH,
    PRODUCT_OBJECT_INFO, PRODUCT_OBJECT_PROCESS, PRODUCT_OBJECT_SETTINGS,
};

pub(crate) fn namespace_node_id_for_product_node(node: NodeId) -> Option<u16> {
    if node.namespace != PRODUCT_NAMESPACE_INDEX {
        return None;
    }
    let id = u16::try_from(node.identifier).ok()?;
    lookup_default_namespace_node(id)?;
    Some(id)
}

pub(crate) fn write_node_value<const WRITE_CAPACITY: usize>(
    node: NodeId,
    attr: u32,
    index_range_present: bool,
    value: DecodedWriteValue,
    data_access: &mut RuntimeDataAccess<WRITE_CAPACITY>,
) -> u32 {
    if attr != ATTR_VALUE {
        return status::BAD_ATTRIBUTE_ID_INVALID;
    }
    if node.namespace == 0 && (NODEID_BUILD_INFO..=2266).contains(&node.identifier) {
        return opcua_status::BAD_NOT_WRITABLE;
    }
    if !data_access.writes_allowed()
        && node.namespace == PRODUCT_NAMESPACE_INDEX
        && u16::try_from(node.identifier)
            .ok()
            .and_then(lookup_default_namespace_node)
            .is_some_and(|contract| contract.access == Access::WritableNumericBoolean)
    {
        return opcua_status::BAD_NOT_WRITABLE;
    }
    if index_range_present || !value.is_supported_product_value_write() {
        return opcua_status::BAD_WRITE_NOT_SUPPORTED;
    }
    if node.namespace != PRODUCT_NAMESPACE_INDEX {
        return status::BAD_NODE_ID_UNKNOWN;
    }
    let Some(node_id) = u16::try_from(node.identifier).ok() else {
        return status::BAD_NODE_ID_UNKNOWN;
    };
    let Some(ns) = lookup_default_namespace_node(node_id) else {
        return status::BAD_NODE_ID_UNKNOWN;
    };
    if ns.access != Access::WritableNumericBoolean {
        return opcua_status::BAD_NOT_WRITABLE;
    }
    if !value.value_supported {
        return opcua_status::BAD_TYPE_MISMATCH;
    }
    let Some(value) = value.value else {
        return opcua_status::BAD_TYPE_MISMATCH;
    };
    let Some(scalar) = scalar_for_write(ns.value_kind, value) else {
        return opcua_status::BAD_TYPE_MISMATCH;
    };
    data_access
        .enqueue_write_node_id(node_id, scalar)
        .opcua_status
}

fn scalar_for_write(kind: ValueKind, value: DecodedScalar) -> Option<ScalarValue> {
    match (kind, value) {
        (ValueKind::Boolean, DecodedScalar::Boolean(value)) => Some(ScalarValue::Boolean(value)),
        (ValueKind::Int32, DecodedScalar::Int32(value)) => Some(ScalarValue::Int32(value)),
        (ValueKind::UInt32, DecodedScalar::UInt32(value)) => Some(ScalarValue::UInt32(value)),
        (ValueKind::Float, DecodedScalar::Float(value)) => {
            Some(ScalarValue::FloatMilli((value * 1000.0) as i32))
        }
        (ValueKind::Float, DecodedScalar::Int32(value)) => {
            Some(ScalarValue::FloatMilli(value.saturating_mul(1000)))
        }
        _ => None,
    }
}

pub(crate) fn write_read_data_value<const WRITE_CAPACITY: usize>(
    e: &mut Encoder<'_>,
    rv: ReadValueId,
    data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
    freshness_now_ms: u64,
    build_info: &'static BuildInfo,
    namespace_array: &[&str; 3],
    server_array: &[&str; 1],
) -> Result<()> {
    if rv.index_range_present {
        return e.write_data_value_status(opcua_status::BAD_INDEX_RANGE_INVALID);
    }
    if rv.data_encoding_present {
        return e.write_data_value_status(status::BAD_DATA_ENCODING_UNSUPPORTED);
    }
    match read_attribute_value(
        rv,
        data_access,
        freshness_now_ms,
        build_info,
        namespace_array,
        server_array,
    ) {
        AttributeValue::Scalar(status, Some(value)) if status == opcua_status::GOOD => {
            e.write_data_value_scalar(status, value)
        }
        AttributeValue::Scalar(status, _) => e.write_data_value_status(status),
        AttributeValue::Variant(status, variant) if status == opcua_status::GOOD => {
            e.write_u8(0x03)?;
            write_variant(e, variant)?;
            e.write_u32(status)
        }
        AttributeValue::Variant(status, _) => e.write_data_value_status(status),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AttributeValue<'a> {
    Scalar(u32, Option<ScalarValue>),
    Variant(u32, AttributeVariant<'a>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AttributeVariant<'a> {
    Boolean(bool),
    I32(i32),
    Byte(u8),
    NodeId(NodeId),
    QualifiedName(u16, &'a str),
    LocalizedText(&'a str),
    DateTime(i64),
    String(&'a str),
    BuildInfo(&'static BuildInfo),
    StringArray(&'a [&'a str]),
}

fn write_variant(e: &mut Encoder<'_>, variant: AttributeVariant<'_>) -> Result<()> {
    match variant {
        AttributeVariant::Boolean(value) => e.write_scalar_variant(ScalarValue::Boolean(value)),
        AttributeVariant::I32(value) => e.write_variant_i32(value),
        AttributeVariant::Byte(value) => e.write_variant_byte(value),
        AttributeVariant::NodeId(value) => e.write_variant_node_id(value),
        AttributeVariant::QualifiedName(ns, name) => e.write_variant_qualified_name(ns, name),
        AttributeVariant::LocalizedText(text) => e.write_variant_localized_text(text),
        AttributeVariant::String(value) => {
            e.write_u8(12)?;
            e.write_string(value)
        }
        AttributeVariant::BuildInfo(value) => value.write_variant(e),
        AttributeVariant::DateTime(value) => e.write_variant_datetime(value),
        AttributeVariant::StringArray(values) => e.write_variant_string_array(values),
    }
}

fn read_attribute_value<'a, const WRITE_CAPACITY: usize>(
    rv: ReadValueId,
    data_access: &'a RuntimeDataAccess<WRITE_CAPACITY>,
    freshness_now_ms: u64,
    build_info: &'static BuildInfo,
    namespace_array: &'a [&'a str; 3],
    server_array: &'a [&'a str; 1],
) -> AttributeValue<'a> {
    if rv.node_id.namespace == 0 {
        return read_standard_attribute(rv, build_info, namespace_array, server_array);
    }
    if rv.node_id.namespace != PRODUCT_NAMESPACE_INDEX {
        return AttributeValue::Scalar(status::BAD_NODE_ID_UNKNOWN, None);
    }
    let Ok(node_id) = u16::try_from(rv.node_id.identifier) else {
        return AttributeValue::Scalar(status::BAD_NODE_ID_UNKNOWN, None);
    };
    if let Some(object) = product_object(node_id) {
        return read_object_attribute(rv.attribute_id, rv.node_id, object);
    }
    let Some(ns) = lookup_default_namespace_node(node_id) else {
        return AttributeValue::Scalar(status::BAD_NODE_ID_UNKNOWN, None);
    };
    match rv.attribute_id {
        ATTR_NODEID => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::NodeId(rv.node_id))
        }
        ATTR_NODECLASS => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::I32(NODECLASS_VARIABLE),
        ),
        ATTR_BROWSENAME => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::QualifiedName(PRODUCT_NAMESPACE_INDEX, ns.browse_name),
        ),
        ATTR_DISPLAYNAME => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::LocalizedText(ns.browse_name),
        ),
        ATTR_DATATYPE => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::NodeId(NodeId::numeric(0, datatype_for_value_kind(ns.value_kind))),
        ),
        ATTR_VALUERANK => AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::I32(-1)),
        ATTR_ACCESSLEVEL | ATTR_USERACCESSLEVEL => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::Byte(access_level(ns.access)),
        ),
        ATTR_HISTORIZING => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::Boolean(false))
        }
        ATTR_VALUE => {
            let read = data_access.read_namespace_node_id(node_id, freshness_now_ms);
            AttributeValue::Scalar(read.opcua_status, read.value)
        }
        _ => AttributeValue::Scalar(status::BAD_ATTRIBUTE_ID_INVALID, None),
    }
}

fn read_standard_attribute<'a>(
    rv: ReadValueId,
    build_info: &'static BuildInfo,
    namespace_array: &'a [&'a str; 3],
    server_array: &'a [&'a str; 1],
) -> AttributeValue<'a> {
    if let Some(index) = BUILD_INFO_FIELDS
        .iter()
        .position(|(id, _)| *id == rv.node_id.identifier)
    {
        let value = if index == 5 {
            AttributeVariant::DateTime(build_info.date())
        } else {
            AttributeVariant::String(build_info.strings()[index])
        };
        return read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            BUILD_INFO_FIELDS[index].1,
            if index == 5 {
                DATATYPE_DATETIME
            } else {
                DATATYPE_STRING
            },
            Some(value),
        );
    }

    if (3052..=3057).contains(&rv.node_id.identifier) {
        let index = (rv.node_id.identifier - 3052) as usize;
        return read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            BUILD_INFO_FIELDS[index].1,
            if index == 5 {
                DATATYPE_DATETIME
            } else {
                DATATYPE_STRING
            },
            None,
        );
    }
    // IsAbstract (Part 3 AttributeId 8) on the types introduced with BuildInfo.
    if rv.attribute_id == 8
        && matches!(
            rv.node_id.identifier,
            DATATYPE_STRUCTURE
                | DATATYPE_BUILD_INFO
                | NODEID_BUILD_INFO_TYPE
                | NODEID_DATA_TYPE_ENCODING_TYPE
                | NODEID_HAS_ENCODING
                | NODEID_HAS_MODELLING_RULE
                | NODEID_MODELLING_RULE_TYPE
        )
    {
        return AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::Boolean(rv.node_id.identifier == DATATYPE_STRUCTURE),
        );
    }
    if rv.node_id.identifier == NODEID_BUILD_INFO_TYPE {
        let value = match rv.attribute_id {
            ATTR_DATATYPE => Some(AttributeVariant::NodeId(NodeId::numeric(
                0,
                DATATYPE_BUILD_INFO,
            ))),
            ATTR_VALUERANK => Some(AttributeVariant::I32(-1)),
            _ => None,
        };
        if let Some(value) = value {
            return AttributeValue::Variant(opcua_status::GOOD, value);
        }
    }
    match rv.node_id.identifier {
        NODEID_MANDATORY => read_object_attribute(rv.attribute_id, rv.node_id, "Mandatory"),
        NODEID_HAS_MODELLING_RULE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasModellingRule",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_MODELLING_RULE_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "ModellingRuleType",
            NODECLASS_OBJECT_TYPE,
        ),
        DATATYPE_STRUCTURE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "Structure",
            NODECLASS_DATA_TYPE,
        ),
        NODEID_HAS_ENCODING => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasEncoding",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_DATA_TYPE_ENCODING_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "DataTypeEncodingType",
            NODECLASS_OBJECT_TYPE,
        ),
        BUILD_INFO_BINARY => read_object_attribute(rv.attribute_id, rv.node_id, "Default Binary"),
        NODEID_ROOT_FOLDER => read_object_attribute(rv.attribute_id, rv.node_id, "Root"),
        NODEID_OBJECTS_FOLDER => read_object_attribute(rv.attribute_id, rv.node_id, "Objects"),
        NODEID_TYPES_FOLDER => read_object_attribute(rv.attribute_id, rv.node_id, "Types"),
        NODEID_VIEWS_FOLDER => read_object_attribute(rv.attribute_id, rv.node_id, "Views"),
        NODEID_SERVER => read_object_attribute(rv.attribute_id, rv.node_id, "Server"),
        NODEID_ORGANIZES => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "Organizes",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_REFERENCES => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "References",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_NON_HIERARCHICAL_REFERENCES => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "NonHierarchicalReferences",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HIERARCHICAL_REFERENCES => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HierarchicalReferences",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HAS_CHILD => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasChild",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_AGGREGATES => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "Aggregates",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HAS_SUBTYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasSubtype",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HAS_TYPE_DEFINITION => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasTypeDefinition",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HAS_PROPERTY => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasProperty",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_HAS_COMPONENT => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "HasComponent",
            NODECLASS_REFERENCE_TYPE,
        ),
        NODEID_BASE_OBJECT_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BaseObjectType",
            NODECLASS_OBJECT_TYPE,
        ),
        NODEID_FOLDER_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "FolderType",
            NODECLASS_OBJECT_TYPE,
        ),
        NODEID_BASE_VARIABLE_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BaseVariableType",
            NODECLASS_VARIABLE_TYPE,
        ),
        NODEID_BASE_DATA_VARIABLE_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BaseDataVariableType",
            NODECLASS_VARIABLE_TYPE,
        ),
        DATATYPE_BASE_DATA_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BaseDataType",
            NODECLASS_DATA_TYPE,
        ),
        DATATYPE_BOOLEAN => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "Boolean",
            NODECLASS_DATA_TYPE,
        ),
        DATATYPE_BYTE => {
            read_standard_type_attribute(rv.attribute_id, rv.node_id, "Byte", NODECLASS_DATA_TYPE)
        }
        DATATYPE_INT32 => {
            read_standard_type_attribute(rv.attribute_id, rv.node_id, "Int32", NODECLASS_DATA_TYPE)
        }
        DATATYPE_UINT32 => {
            read_standard_type_attribute(rv.attribute_id, rv.node_id, "UInt32", NODECLASS_DATA_TYPE)
        }
        DATATYPE_FLOAT => {
            read_standard_type_attribute(rv.attribute_id, rv.node_id, "Float", NODECLASS_DATA_TYPE)
        }
        DATATYPE_STRING => {
            read_standard_type_attribute(rv.attribute_id, rv.node_id, "String", NODECLASS_DATA_TYPE)
        }
        DATATYPE_DATETIME => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "DateTime",
            NODECLASS_DATA_TYPE,
        ),
        DATATYPE_SERVER_STATUS => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "ServerStatusDataType",
            NODECLASS_DATA_TYPE,
        ),
        NODEID_BUILD_INFO => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "BuildInfo",
            DATATYPE_BUILD_INFO,
            Some(AttributeVariant::BuildInfo(build_info)),
        ),
        DATATYPE_BUILD_INFO => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BuildInfo",
            NODECLASS_DATA_TYPE,
        ),
        NODEID_BUILD_INFO_TYPE => read_standard_type_attribute(
            rv.attribute_id,
            rv.node_id,
            "BuildInfoType",
            NODECLASS_VARIABLE_TYPE,
        ),
        NODEID_SERVER_STATUS => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "ServerStatus",
            DATATYPE_SERVER_STATUS,
            None,
        ),
        NODEID_NAMESPACE_ARRAY => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "NamespaceArray",
            DATATYPE_STRING,
            Some(AttributeVariant::StringArray(namespace_array)),
        ),
        NODEID_SERVER_ARRAY => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "ServerArray",
            DATATYPE_STRING,
            Some(AttributeVariant::StringArray(server_array)),
        ),
        NODEID_SERVER_SERVICE_LEVEL => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "ServiceLevel",
            DATATYPE_BYTE,
            Some(AttributeVariant::Byte(255)),
        ),
        NODEID_SERVER_STATUS_CURRENT_TIME => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "CurrentTime",
            DATATYPE_DATETIME,
            Some(AttributeVariant::DateTime(0)),
        ),
        NODEID_SERVER_STATUS_STATE => read_standard_variable_attribute(
            rv.attribute_id,
            rv.node_id,
            "State",
            DATATYPE_INT32,
            Some(AttributeVariant::I32(0)),
        ),
        _ => AttributeValue::Scalar(status::BAD_NODE_ID_UNKNOWN, None),
    }
}

fn read_standard_type_attribute<'a>(
    attr: u32,
    node: NodeId,
    name: &'a str,
    node_class: i32,
) -> AttributeValue<'a> {
    match attr {
        ATTR_NODEID => AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::NodeId(node)),
        ATTR_NODECLASS => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::I32(node_class))
        }
        ATTR_BROWSENAME => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::QualifiedName(0, name))
        }
        ATTR_DISPLAYNAME => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::LocalizedText(name))
        }
        _ => AttributeValue::Scalar(status::BAD_ATTRIBUTE_ID_INVALID, None),
    }
}

fn read_object_attribute<'a>(attr: u32, node: NodeId, name: &'a str) -> AttributeValue<'a> {
    match attr {
        ATTR_NODEID => AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::NodeId(node)),
        ATTR_NODECLASS => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::I32(NODECLASS_OBJECT))
        }
        ATTR_BROWSENAME => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::QualifiedName(node.namespace, name),
        ),
        ATTR_DISPLAYNAME => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::LocalizedText(name))
        }
        ATTR_EVENTNOTIFIER => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::Byte(0))
        }
        ATTR_VALUE => AttributeValue::Scalar(status::BAD_NOT_READABLE, None),
        _ => AttributeValue::Scalar(status::BAD_ATTRIBUTE_ID_INVALID, None),
    }
}

fn read_standard_variable_attribute<'a>(
    attr: u32,
    node: NodeId,
    name: &'a str,
    data_type: u32,
    value: Option<AttributeVariant<'a>>,
) -> AttributeValue<'a> {
    match attr {
        ATTR_NODEID => AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::NodeId(node)),
        ATTR_NODECLASS => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::I32(NODECLASS_VARIABLE),
        ),
        ATTR_BROWSENAME => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::QualifiedName(0, name))
        }
        ATTR_DISPLAYNAME => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::LocalizedText(name))
        }
        ATTR_DATATYPE => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::NodeId(NodeId::numeric(0, data_type)),
        ),
        ATTR_VALUERANK => AttributeValue::Variant(
            opcua_status::GOOD,
            AttributeVariant::I32(if matches!(value, Some(AttributeVariant::StringArray(_))) {
                1
            } else {
                -1
            }),
        ),
        ATTR_ACCESSLEVEL | ATTR_USERACCESSLEVEL => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::Byte(0x01))
        }
        ATTR_HISTORIZING => {
            AttributeValue::Variant(opcua_status::GOOD, AttributeVariant::Boolean(false))
        }
        ATTR_VALUE => match value {
            Some(value) => AttributeValue::Variant(opcua_status::GOOD, value),
            None => AttributeValue::Scalar(status::BAD_NOT_READABLE, None),
        },
        _ => AttributeValue::Scalar(status::BAD_ATTRIBUTE_ID_INVALID, None),
    }
}

fn datatype_for_value_kind(kind: ValueKind) -> u32 {
    match kind {
        ValueKind::Boolean => DATATYPE_BOOLEAN,
        ValueKind::Int32 => DATATYPE_INT32,
        ValueKind::Float => DATATYPE_FLOAT,
        ValueKind::UInt32 => DATATYPE_UINT32,
    }
}

fn access_level(access: Access) -> u8 {
    match access {
        Access::ReadOnly => 0x01,
        Access::WritableNumericBoolean => 0x03,
    }
}

pub(crate) fn product_object(node_id: u16) -> Option<&'static str> {
    match node_id {
        PRODUCT_OBJECT_BUCHI => Some("Buchi"),
        PRODUCT_OBJECT_INFO => Some("Info"),
        PRODUCT_OBJECT_PROCESS => Some("Process"),
        PRODUCT_OBJECT_SETTINGS => Some("Settings"),
        PRODUCT_OBJECT_HEALTH => Some("Health"),
        _ => None,
    }
}
