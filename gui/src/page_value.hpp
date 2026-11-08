#pragma once
#include "model.hpp"
#include <ui_core.h>
#include <memory>

namespace spg {
inline Json page_value(UiPage page, const char* key, bool required = false) {
    std::unique_ptr<char, decltype(&ui_page_free)> text(ui_page_get_json(page, key), ui_page_free);
    if (text) return Json::parse(text.get());
    if (required) throw std::runtime_error("uiBindingFailed");
    return Json();
}
}
