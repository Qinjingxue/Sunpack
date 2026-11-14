//! Borrowed diagnostics stop serialization at the same limits as Value logs.
//! An early stop carries its partial value up through the containing fields.
use serde::ser::{self, Serialize, SerializeMap, SerializeSeq};
use serde_json::{Map, Value};
use std::fmt;

pub(super) const MAX_DEPTH: usize = 8;
pub(super) const MAX_ITEMS: usize = 64;

pub(super) fn short_string<'a>(text: &'a str, max_bytes: usize, truncated: &mut bool) -> &'a str {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    *truncated |= end != text.len();
    &text[..end]
}


pub(super) fn value(value: &impl Serialize, budget: &mut usize, truncated: &mut bool) -> Value {
    match value.serialize(Bounded { budget, truncated, depth: 0 }) {
        Ok(value) => value,
        Err(Stop(value)) => { *truncated = true; value }
    }
}

#[derive(Debug)]
struct Stop(Value);
impl fmt::Display for Stop {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result { out.write_str("diagnostic limit") }
}
impl std::error::Error for Stop {}
impl ser::Error for Stop {
    fn custom<T: fmt::Display>(_: T) -> Self { Self(Value::Null) }
}
struct Bounded<'a> { budget: &'a mut usize, truncated: &'a mut bool, depth: usize }
impl<'a> Bounded<'a> {
    fn begin(&mut self) -> Result<(), Stop> {
        if *self.budget == 0 || self.depth == MAX_DEPTH { return Err(Stop(Value::Null)); }
        *self.budget = self.budget.saturating_sub(8);
        Ok(())
    }
    fn scalar(mut self, value: Value) -> Result<Value, Stop> { self.begin()?; Ok(value) }
    fn container(mut self, object: bool, variant: Option<&str>) -> Result<Container<'a>, Stop> {
        self.begin()?;
        Ok(Container { bounded: self, value: if object { Value::Object(Map::new()) } else { Value::Array(Vec::new()) },
            key: None, variant: variant.map(str::to_owned), count: 0 })
    }
}
struct Container<'a> {
    bounded: Bounded<'a>, value: Value, key: Option<String>, variant: Option<String>,
    count: usize,
}
impl Container<'_> {
    fn take(&mut self) -> Value {
        let value = std::mem::take(&mut self.value);
        match self.variant.take() { Some(name) => Value::Object(Map::from_iter([(name, value)])), None => value }
    }
    fn check(&mut self) -> Result<(), Stop> {
        if self.count == MAX_ITEMS || *self.bounded.budget == 0 { return Err(Stop(self.take())); }
        Ok(())
    }
    fn key(&mut self, key: &impl Serialize) -> Result<(), Stop> {
        self.check()?;
        // Only the shortened key is materialized, even for a borrowed long key.
        let mut available = (*self.bounded.budget).min(64) + 8;
        let key = match key.serialize(Bounded { budget: &mut available, truncated: self.bounded.truncated, depth: 0 }) {
            Ok(key) => key,
            Err(Stop(key)) => { *self.bounded.truncated = true; key }
        };
        let key = match key { Value::String(key) => key, key => key.to_string() };
        *self.bounded.budget = self.bounded.budget.saturating_sub(key.len());
        self.key = Some(key);
        Ok(())
    }
    fn item<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        if self.key.is_none() { self.check()?; }
        let result = value.serialize(Bounded { budget: self.bounded.budget,
            truncated: self.bounded.truncated, depth: self.bounded.depth + 1 });
        let value = match result {
            Ok(value) => value,
            Err(Stop(value)) => { *self.bounded.truncated = true; value },
        };
        match &mut self.value {
            Value::Array(items) => items.push(value),
            Value::Object(items) => { items.insert(self.key.take().unwrap(), value); },
            _ => unreachable!(),
        }
        self.count += 1;
        // A local depth/item limit terminates only that child container. Its
        // siblings still receive the remaining budget, as in bounded_value.
        // The next field/element checks the budget before invoking its serializer.
        // An exactly fitting last value is not itself a truncation.
        Ok(())
    }
}
macro_rules! scalar {
    ($($method:ident($kind:ty)),* $(,)?) => { $(
        fn $method(self, value: $kind) -> Result<Value, Stop> { self.scalar(Value::from(value)) }
    )* };
}
impl<'a> ser::Serializer for Bounded<'a> {
    type Ok = Value; type Error = Stop;
    type SerializeSeq = Container<'a>; type SerializeTuple = Container<'a>;
    type SerializeTupleStruct = Container<'a>; type SerializeTupleVariant = Container<'a>;
    type SerializeMap = Container<'a>; type SerializeStruct = Container<'a>; type SerializeStructVariant = Container<'a>;
    scalar!(serialize_bool(bool), serialize_i8(i8), serialize_i16(i16), serialize_i32(i32), serialize_i64(i64),
        serialize_u8(u8), serialize_u16(u16), serialize_u32(u32), serialize_u64(u64), serialize_f32(f32), serialize_f64(f64));
    fn serialize_char(self, value: char) -> Result<Value, Stop> { self.serialize_str(value.encode_utf8(&mut [0; 4])) }
    fn serialize_str(mut self, value: &str) -> Result<Value, Stop> {
        self.begin()?;
        let text = short_string(value, *self.budget, self.truncated);
        *self.budget -= text.len();
        Ok(Value::String(text.to_owned()))
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<Value, Stop> { value.serialize(self) }
    fn serialize_none(self) -> Result<Value, Stop> { self.serialize_unit() }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, Stop> { value.serialize(self) }
    fn serialize_unit(self) -> Result<Value, Stop> { self.scalar(Value::Null) }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Value, Stop> { self.serialize_unit() }
    fn serialize_unit_variant(self, _: &'static str, _: u32, name: &'static str) -> Result<Value, Stop> { self.serialize_str(name) }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, value: &T) -> Result<Value, Stop> { value.serialize(self) }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _: &'static str, _: u32, name: &'static str, value: &T) -> Result<Value, Stop> {
        let mut object = self.container(true, None)?; object.key(&name)?; object.item(value)?; Ok(object.take())
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Stop> { self.container(false, None) }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Stop> { self.container(false, None) }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeTupleStruct, Stop> { self.container(false, None) }
    fn serialize_tuple_variant(self, _: &'static str, _: u32, name: &'static str, _: usize) -> Result<Self::SerializeTupleVariant, Stop> { self.container(false, Some(name)) }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Stop> { self.container(true, None) }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Stop> { self.container(true, None) }
    fn serialize_struct_variant(self, _: &'static str, _: u32, name: &'static str, _: usize) -> Result<Self::SerializeStructVariant, Stop> { self.container(true, Some(name)) }
}
impl SerializeSeq for Container<'_> {
    type Ok = Value; type Error = Stop;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> { self.item(value) }
    fn end(mut self) -> Result<Value, Stop> { Ok(self.take()) }
}
macro_rules! tuple {
    ($($name:ident::$method:ident),*) => { $(impl ser::$name for Container<'_> {
        type Ok = Value; type Error = Stop;
        fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> { self.item(value) }
        fn end(mut self) -> Result<Value, Stop> { Ok(self.take()) }
    })* };
}
tuple!(SerializeTuple::serialize_element, SerializeTupleStruct::serialize_field, SerializeTupleVariant::serialize_field);
impl SerializeMap for Container<'_> {
    type Ok = Value; type Error = Stop;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Stop> { self.key(&key) }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> { self.item(value) }
    fn end(mut self) -> Result<Value, Stop> { Ok(self.take()) }
}
macro_rules! object {
    ($($name:ident),*) => { $(impl ser::$name for Container<'_> {
        type Ok = Value; type Error = Stop;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Stop> {
            self.key(&key)?; self.item(value)
        }
        fn end(mut self) -> Result<Value, Stop> { Ok(self.take()) }
    })* };
}
object!(SerializeStruct, SerializeStructVariant);

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Counted<'a> { visits: &'a Cell<usize>, text: &'a str }
    impl Serialize for Counted<'_> {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.visits.set(self.visits.get() + 1);
            serializer.serialize_str(self.text)
        }
    }
    #[derive(serde::Serialize)]
    struct Tree<'a> { kind: &'a str, items: Vec<Counted<'a>>, tail: Counted<'a> }

    #[test]
    fn bounded_projection_stops_visiting_and_keeps_the_partial_tree() {
        // Growing the borrowed tree cannot grow diagnostic traversal past its
        // budget. A local item cap must still allow a short trailing field;
        // global exhaustion must stop before visiting it.
        for (text, expected) in [("", MAX_ITEMS), ("x".repeat(128).as_str(), 30)] {
            for count in [128, 16_384] {
                let visits = Cell::new(0);
                let tail = Cell::new(0);
                let tree = Tree { kind: "damaged", items: (0..count).map(|_| Counted { visits: &visits, text }).collect(),
                    tail: Counted { visits: &tail, text: "tail evidence" } };
                let mut budget = 4096;
                let mut truncated = false;
                let output = value(&tree, &mut budget, &mut truncated);
                assert!(truncated);
                assert_eq!(output["kind"], "damaged");
                assert!(output["items"].as_array().is_some());
                assert!(visits.get() <= expected);
                if text.is_empty() {
                    assert_eq!(tail.get(), 1);
                    assert_eq!(output["tail"], "tail evidence");
                } else {
                    assert_eq!(tail.get(), 0);
                    assert!(output.get("tail").is_none());
                }
            }
        }
        // Depth limits, like item limits, do not hide a short later sibling.
        let mut deep = serde_json::json!("bottom");
        for _ in 0..MAX_DEPTH + 2 { deep = serde_json::json!({"inner":deep}); }
        let mut budget = 4096;
        let mut truncated = false;
        let output = value(&serde_json::json!({"deep":deep,"tail":"evidence"}), &mut budget, &mut truncated);
        assert!(truncated);
        assert_eq!(output["tail"], "evidence");
        // UTF-8 truncation retains valid strings and the containing keys.
        let mut budget = 40;
        let mut truncated = false;
        let output = value(&serde_json::json!({"nested":{"text":"多字节".repeat(1000)}}), &mut budget, &mut truncated);
        assert!(truncated);
        assert!(output["nested"]["text"].as_str().is_some());
    }
}
