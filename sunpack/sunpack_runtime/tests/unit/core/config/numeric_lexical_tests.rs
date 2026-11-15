use super::*;

#[test]
fn python_numeric_config_strings_normalize_without_widening_grammar() {
    let mut strings = defaults().clone();
    strings["watch"]["clipboard_builtin_max_entries"] = Value::String("  +１_０００  ".into());
    strings["watch"]["boundary_confirmation_seconds"] = Value::String("0_5".into());
    strings["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::String("١.２e+१".into());
    strings["recursive_authorization"]["byte_ratio_exponent"] = Value::String("1_0".into());
    let mut numbers = defaults().clone();
    numbers["watch"]["clipboard_builtin_max_entries"] = Value::from(1000);
    numbers["watch"]["boundary_confirmation_seconds"] = Value::from(5.0);
    numbers["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::from(12.0);
    numbers["recursive_authorization"]["byte_ratio_exponent"] = Value::from(10.0);
    assert!(Config::parse(&strings).unwrap() == Config::parse(&numbers).unwrap());
    assert!(matches!(numeric_string(" 12.5 "), Some(Cow::Borrowed("12.5"))));
    for input in ["_1", "1_", "1__0", "+_1", "1_.0", "1._0", "1_e2", "1e_2", "1e+_2", "²", "0x10"] {
        assert!(number_value(&Value::String(input.into())).is_none(), "{input}");
        assert!(integer_value(&Value::String(input.into())).is_none(), "{input}");
    }
    for input in ["１.０", "1e２", "1_0.0"] {
        assert!(number_value(&Value::String(input.into())).is_some(), "{input}");
        assert!(integer_value(&Value::String(input.into())).is_none(), "{input}");
    }
    assert_eq!(integer_value(&Value::String("-１_２".into())), Some(0));
}

#[test]
fn numeric_normalization_keeps_field_specific_bounds_and_diagnostics() {
    for (text, expected) in [("nan", 0.0), ("-inf", 0.0), ("inf", f64::INFINITY), ("1e9999", f64::INFINITY)] {
        let mut raw = defaults().clone();
        raw["watch"]["boundary_confirmation_seconds"] = Value::String(text.into());
        raw["watch"]["runtime_cache_cleanup_idle_seconds"] = Value::String(text.into());
        let settings = Config::parse(&raw).unwrap();
        assert_eq!(settings.watch.boundary_confirmation_seconds, expected);
        assert_eq!(settings.watch.runtime_cache_cleanup_idle_seconds, expected);
    }
    for (text, expected) in [("9223372036854775808", 1u64 << 63), ("18446744073709551615", u64::MAX), ("-18446744073709551615", 1)] {
        let mut raw = defaults().clone();
        raw["watch"]["event_log_retention_days"] = Value::String(text.into());
        assert_eq!(Config::parse(&raw).unwrap().watch.event_log_retention_days, expected);
    }
    for name in ["byte_ratio_exponent", "project_ratio_exponent", "minimum_authorization_score"] {
        for text in ["nan", "inf", "-inf", "not numeric"] {
            let mut raw = defaults().clone();
            raw["recursive_authorization"][name] = Value::String(text.into());
            let error = Config::parse(&raw).err().unwrap().to_string();
            let expected = if text == "not numeric" {
                "recursive_authorization thresholds must be numeric".to_owned()
            } else if name == "minimum_authorization_score" {
                format!("recursive_authorization.{name} must be between 0 and 1")
            } else {
                format!("recursive_authorization.{name} must be positive")
            };
            assert_eq!(error, expected);
        }
    }
}

#[test]
fn python_positive_decimal_recursion_contract() {
    for (input, expected) in [("1_0", 10), ("١", 1), ("+１２", 12), (" १_२ ", 12), ("𝟙𝟘", 10)] {
        assert!(matches!(Recursion::parse(input), Ok(Recursion::Fixed(value)) if value == expected));
    }
    for input in ["", "_1", "1_", "1__0", "0", "-1", "²", "1.0", "+_1"] {
        assert!(Recursion::parse(input).is_err(), "{input}");
    }
    assert!(matches!(Recursion::parse(&"9".repeat(100)), Ok(Recursion::Fixed(usize::MAX))));
}
