//! Optional presentation metadata for `config show`. Normal configuration reads
//! do not allocate it. Values are parsed once; only key order is retained here.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Default)]
pub(crate) enum Order {
    #[default]
    Scalar,
    Object(Vec<(String, Order)>),
    Array(Vec<(Option<String>, Order)>),
}

impl Order {
    pub(super) fn merge(&mut self, layer: Self, filesystem: bool) {
        match (self, layer) {
            (Self::Object(base), Self::Object(layer)) => {
                for (key, new) in layer {
                    if let Some((_, old)) = base.iter_mut().find(|(name, _)| name == &key) {
                        if filesystem && key == "scan_filters" {
                            if let (Self::Array(base), Self::Array(changes)) = (&mut *old, &new) {
                                let mut names = Vec::new();
                                let mut unnamed = Vec::new();
                                for (name, order) in changes {
                                    let Some(name) = name else {
                                        unnamed.push((None, order.clone()));
                                        continue;
                                    };
                                    if let Some((_, old)) = base.iter_mut().rev().find(|(old, _)| old.as_ref() == Some(name)) {
                                        old.merge(order.clone(), false);
                                    } else {
                                        base.push((Some(name.clone()), order.clone()));
                                    }
                                    names.push(name);
                                }
                                let mut ordered = Vec::new();
                                for name in &names {
                                    if let Some(entry) = base.iter().rev().find(|(old, _)| old.as_ref() == Some(*name)) {
                                        ordered.push(entry.clone());
                                    }
                                }
                                ordered.extend(base.drain(..).filter(|(name, _)| name.as_ref().is_none_or(|name| !names.contains(&name))));
                                ordered.extend(unnamed);
                                *base = ordered;
                                continue;
                            }
                        }
                        old.merge(new, key == "filesystem");
                    } else {
                        base.push((key, new));
                    }
                }
            }
            (old, new) => *old = new,
        }
    }
}

pub(super) struct Captured(pub Value, pub Order);
impl<'de> Deserialize<'de> for Captured {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Capture;
        impl<'de> Visitor<'de> for Capture {
            type Value = Captured;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a JSON value") }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Captured, E> { Ok(Captured(value.into(), Order::Scalar)) }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Captured, E> { Ok(Captured(value.into(), Order::Scalar)) }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Captured, E> { Ok(Captured(value.into(), Order::Scalar)) }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Captured, E> {
                serde_json::Number::from_f64(value).map(|number| Captured(Value::Number(number), Order::Scalar))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Captured, E> { self.visit_string(value.to_owned()) }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Captured, E> { Ok(Captured(value.into(), Order::Scalar)) }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Captured, E> { Ok(Captured(Value::Null, Order::Scalar)) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Captured, A::Error> {
                let mut values = Vec::new();
                let mut orders = Vec::new();
                while let Some(Captured(value, order)) = seq.next_element()? {
                    orders.push((value.get("name").and_then(Value::as_str).map(str::to_owned), order));
                    values.push(value);
                }
                Ok(Captured(Value::Array(values), Order::Array(orders)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Captured, A::Error> {
                let mut values = serde_json::Map::new();
                let mut orders: Vec<(String, Order)> = Vec::new();
                while let Some((key, Captured(value, order))) = map.next_entry::<String, Captured>()? {
                    if let Some((_, old)) = orders.iter_mut().find(|(name, _)| name == &key) { *old = order; }
                    else { orders.push((key.clone(), order)); }
                    values.insert(key, value);
                }
                Ok(Captured(Value::Object(values), Order::Object(orders)))
            }
        }
        deserializer.deserialize_any(Capture)
    }
}

pub(crate) struct Ordered<'a>(pub &'a Value, pub &'a Order);
impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match (self.0, self.1) {
            (Value::Object(values), Order::Object(order)) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, order) in order {
                    if let Some(value) = values.get(key) { map.serialize_entry(key, &Ordered(value, order))?; }
                }
                map.end()
            }
            (Value::Array(values), Order::Array(order)) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for (value, (_, order)) in values.iter().zip(order) { seq.serialize_element(&Ordered(value, order))?; }
                seq.end()
            }
            (value, _) => value.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_order_tracks_layer_merges_and_named_filter_reordering() {
        let Captured(mut value, mut order) = serde_json::from_str(
            r#"{"z":{"second":2,"first":1},"filesystem":{"scan_filters":[{"name":"a","z":0,"a":1},{"name":"b","keep":true}]},"z":{"second":3,"first":1}}"#,
        ).unwrap();
        let Captured(layer, layer_order) = serde_json::from_str(
            r#"{"filesystem":{"scan_filters":[{"name":"b","extra":7},{"name":"a","a":2,"new":3}]},"z":{"first":9,"third":4},"tail":false}"#,
        ).unwrap();
        order.merge(layer_order, false);
        super::super::merge(&mut value, layer, false);
        let text = serde_json::to_string(&Ordered(&value, &order)).unwrap();
        assert_eq!(text, r#"{"z":{"second":3,"first":9,"third":4},"filesystem":{"scan_filters":[{"name":"b","keep":true,"extra":7},{"name":"a","z":0,"a":2,"new":3}]},"tail":false}"#);
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
        // Duplicate names and unnamed entries use the same sequence as the
        // existing layer merge, including repeated output slots.
        let Captured(layer, layer_order) = serde_json::from_str(
            r#"{"filesystem":{"scan_filters":[{"name":"a","last":1},{"free":true},{"name":"a","later":2}]}}"#,
        ).unwrap();
        order.merge(layer_order, false);
        super::super::merge(&mut value, layer, false);
        let text = serde_json::to_string(&Ordered(&value, &order)).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
        assert!(text.contains(r#""new":3,"last":1,"later":2"#));
    }
}
