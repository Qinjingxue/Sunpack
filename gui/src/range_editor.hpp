#pragma once
#include "model.hpp"

namespace spg {
// Structured configuration only. Legacy interpretation belongs to the installer.
Json range_editor(const Json& module, const DYNAMIC_TIME_ZONE_INFORMATION* zone = nullptr);
Json range_configuration(const Json& form, bool datetime, const DYNAMIC_TIME_ZONE_INFORMATION* zone = nullptr);
void validate_range_module(const Json& module, bool datetime);
bool range_datetime(const std::string& text, SYSTEMTIME& value);
std::string range_datetime_text(const SYSTEMTIME& value);
int64_t range_calendar_seconds(const SYSTEMTIME& value);
SYSTEMTIME range_calendar_time(int64_t seconds);
int64_t range_utc_minutes(const std::string& value);
std::string range_utc_text(int64_t minutes);
}
