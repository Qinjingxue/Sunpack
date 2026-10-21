#pragma once
#include "model.hpp"
#include <functional>
namespace spg {
// Installer-only; true returns a complete replacement with explicit null bounds.
bool migrate_range_module(const Json& old, Json& replacement,
    const std::function<std::string(const std::string&)>& raw_value);
}
