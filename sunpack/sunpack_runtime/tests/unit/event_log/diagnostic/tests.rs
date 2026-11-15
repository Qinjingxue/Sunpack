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
