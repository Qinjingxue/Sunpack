#pragma once
#include "model.hpp"

namespace spg {
// GUI configuration presentation only; never inspects archive/file contents.
Json range_editor(const std::string& text, bool datetime);
std::string range_expression(const Json& range, bool datetime);
bool range_datetime(const std::string& text, SYSTEMTIME& value);
std::string range_datetime_text(const SYSTEMTIME& value);
}
