#pragma once
#include "model.hpp"
#include <string_view>

namespace spg {
std::string gui_language(const Json& config);
std::string startup_language(const fs::path& data_dir);
const wchar_t* gui_text_locale(std::string_view language);
std::string tr(std::string_view key, std::string_view language);
// Keep keys/arguments until display. Arguments are literal; {"source": message}
// explicitly embeds another translatable diagnostic.
std::string error_text(const std::string& key, const Json& arguments = Json::object());
std::string translated_error(const std::string& message, const std::string& language);
Json interface_texts(const std::string& language);
Json describe_setting(const std::string& pointer, const std::string& module,
    const std::string& language);
void validate_setting(const std::string& pointer, const Json& value, const std::string& module = {});
}
