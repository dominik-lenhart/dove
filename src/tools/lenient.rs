//! Lenient reading of tool arguments (PLAN A68).
//!
//! Agents write a JSON value in a nearby shape: one mailbox name where a list is expected, a list or an object as
//! JSON text, `"true"` for `true`, `"20"` for `20`, `account` where the tool says `accounts`. Each of those has
//! exactly one reading, so [`normalize`] rewrites it into the canonical shape before the strict parsers run. They
//! stay strict about everything else. Nothing here widens what a call may reach: values are only reshaped, never
//! guessed (a text that is not valid JSON of the expected kind is left alone and fails in the strict parser with
//! the field named), and a value that would need an interpretation (several values for a single-value argument, a
//! time without offset) is not touched.

use serde_json::Value;

use crate::error::ToolError;

/// Which arguments of a tool are read leniently, and how.
#[derive(Default)]
pub struct Spec<'a> {
    /// `(alias, canonical)`: the alias names the canonical argument. Giving both is an error.
    pub aliases: &'a [(&'a str, &'a str)],
    /// Lists: one non-list value becomes a one-element list; JSON text of a list is parsed.
    pub lists: &'a [&'a str],
    /// Objects: JSON text of an object is parsed.
    pub objects: &'a [&'a str],
    /// Booleans: `"true"` and `"false"` in any case.
    pub bools: &'a [&'a str],
    /// Non-negative integers: digit strings and whole floats.
    pub ints: &'a [&'a str],
}

/// The arguments with every lenient reading of `spec` applied. Non-objects are returned unchanged.
pub fn normalize(args: &Value, spec: &Spec<'_>) -> Result<Value, ToolError> {
    let mut out = args.clone();
    let Some(obj) = out.as_object_mut() else { return Ok(out) };
    for (alias, canonical) in spec.aliases {
        let Some(v) = obj.remove(*alias) else { continue };
        if v.is_null() {
            continue;
        }
        if obj.get(*canonical).is_some_and(|c| !c.is_null()) {
            return Err(ToolError::invalid_at(*alias, format!("use '{canonical}' (or '{alias}'), not both")));
        }
        obj.insert((*canonical).to_string(), v);
    }
    for key in spec.lists {
        let Some(v) = obj.get_mut(*key) else { continue };
        let taken = std::mem::take(v);
        *v = match taken {
            Value::String(s) => match json_text(&s, '[') {
                Some(parsed) => parsed,
                None => Value::Array(vec![Value::String(s)]),
            },
            o @ Value::Object(_) => Value::Array(vec![o]),
            other => other,
        };
    }
    for key in spec.objects {
        let Some(v) = obj.get_mut(*key) else { continue };
        if let Value::String(s) = v
            && let Some(parsed) = json_text(s, '{')
        {
            *v = parsed;
        }
    }
    for key in spec.bools {
        if let Some(v) = obj.get_mut(*key)
            && let Value::String(s) = v
            && let Some(b) = bool_text(s)
        {
            *v = Value::Bool(b);
        }
    }
    for key in spec.ints {
        if let Some(v) = obj.get_mut(*key)
            && let Some(n) = int_value(v)
        {
            *v = Value::from(n);
        }
    }
    Ok(out)
}

/// An enum-like text argument read case-insensitively. Returns the canonical value from `allowed`. The error names
/// the argument and lists the values.
pub fn opt_enum(args: &Value, key: &str, allowed: &[&'static str]) -> Result<Option<&'static str>, ToolError> {
    let Some(v) = args.get(key).filter(|v| !v.is_null()) else { return Ok(None) };
    v.as_str()
        .map(|s| s.trim().to_ascii_lowercase())
        .and_then(|l| allowed.iter().find(|a| **a == l).copied())
        .map(Some)
        .ok_or_else(|| {
            ToolError::invalid_at(key, format!("must be one of: {}", allowed.join(", ")))
                .with_detail("allowed", Value::from(allowed.to_vec()))
        })
}

/// JSON text that starts with `open` (`[` or `{`) and parses to that kind of value.
pub fn json_text(s: &str, open: char) -> Option<Value> {
    let t = s.trim();
    if !t.starts_with(open) {
        return None;
    }
    let v: Value = serde_json::from_str(t).ok()?;
    match open {
        '[' => v.is_array().then_some(v),
        _ => v.is_object().then_some(v),
    }
}

/// `"true"` or `"false"` in any case.
pub fn bool_text(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// A non-negative integer written as digits in a string, or as a whole float (`20.0`).
pub fn int_value(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty() && t.len() <= 18 && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse().ok())?
        }
        Value::Number(n) if !n.is_u64() && !n.is_i64() => {
            n.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0 && *f < 9e15).map(|f| f as u64)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> Spec<'static> {
        Spec {
            aliases: &[("account", "accounts")],
            lists: &["accounts", "order_by"],
            objects: &["where"],
            bools: &["count_only"],
            ints: &["limit"],
        }
    }

    #[test]
    fn reshapes_only_what_has_one_reading() {
        let a = json!({
            "account": "info", "order_by": {"field": "size_bytes"}, "where": "{\"all\": []}",
            "count_only": "TRUE", "limit": "20"
        });
        let n = normalize(&a, &spec()).unwrap();
        assert_eq!(
            n,
            json!({"accounts": ["info"], "order_by": [{"field": "size_bytes"}], "where": {"all": []},
                   "count_only": true, "limit": 20})
        );
        // JSON text of a list; text that is not JSON stays a plain value; broken JSON is left for the strict parser.
        let n = normalize(&json!({"accounts": "[\"a\", \"b\"]"}), &spec()).unwrap();
        assert_eq!(n["accounts"], json!(["a", "b"]));
        let n = normalize(
            &json!({"accounts": "[broken", "where": "{broken", "limit": "20x", "count_only": "yes"}),
            &spec(),
        )
        .unwrap();
        assert_eq!(n, json!({"accounts": ["[broken"], "where": "{broken", "limit": "20x", "count_only": "yes"}));
        // Whole floats are integers; negatives and fractions are not touched.
        assert_eq!(normalize(&json!({"limit": 20.0}), &spec()).unwrap()["limit"], json!(20));
        assert_eq!(normalize(&json!({"limit": 2.5}), &spec()).unwrap()["limit"], json!(2.5));
        assert_eq!(normalize(&json!({"limit": "-1"}), &spec()).unwrap()["limit"], json!("-1"));
    }

    #[test]
    fn alias_and_canonical_together_are_an_error() {
        let e = normalize(&json!({"account": "a", "accounts": ["b"]}), &spec()).unwrap_err();
        assert_eq!(e.audit_field().as_deref(), Some("account"));
    }
}
