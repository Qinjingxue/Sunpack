#pragma once
#include "model.hpp"

inline std::string published_events(const std::string& events) {
    return spg::Json{{"event","state_begin"},{"schema",1}}.dump()+"\n"+events;
}
