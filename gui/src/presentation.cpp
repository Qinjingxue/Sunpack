#include "presentation.hpp"
#include "catalog_json.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>

namespace spg {
namespace {
struct Locale {
    std::string_view code;
    const wchar_t* windows_name;
    const char* label;
};
constexpr Locale locales[] = {
    {"zh", L"zh-CN", "简体中文"},
    {"en", L"en-US", "English"},
    {"zh-TW", L"zh-TW", "繁體中文"},
    {"ja", L"ja-JP", "日本語"},
    {"ko", L"ko-KR", "한국어"},
};
constexpr size_t english_locale = 1;
static_assert(locales[english_locale].code == "en");

struct Message {
    std::string_view key;
    std::array<const char*, std::size(locales)> texts;
};
// Keep translations in read-only program data. Only the selected language is
// copied into the page; the JSON catalog contains setting metadata.
#include "catalog_texts.inc"

template<size_t N>
constexpr bool valid_messages(const Message (&messages)[N]) {
    for(size_t i=0; i<N; ++i) {
        if(i>0 && messages[i-1].key>=messages[i].key) return false;
        for(const auto* text:messages[i].texts) if(!text || !*text) return false;
    }
    return true;
}
static_assert(valid_messages(ui_messages));
static_assert(valid_messages(setting_messages));
static_assert(valid_messages(native_messages));

size_t locale_index(std::string_view language) {
    for(size_t index=0; index<std::size(locales); ++index)
        if(locales[index].code==language) return index;
    return english_locale;
}

template<size_t N>
const Message* find_message(const Message (&messages)[N],std::string_view key) {
    auto found=std::lower_bound(std::begin(messages),std::end(messages),key,
        [](const Message& message,std::string_view sought){return message.key<sought;});
    return found!=std::end(messages) && found->key==key?found:nullptr;
}

const Json& catalog() { static const auto data=parse_json(kCatalogJson); return data; }
const char* local(const Json& value,size_t locale) {
    const auto* message=find_message(setting_messages,value.get_ref<const std::string&>());
    return message?message->texts[locale]:"";
}
const Json& setting(const std::string& pointer,const std::string& module) {
    const auto& fields=catalog()["fields"];
    auto key=pointer;
    // Named arrays may be reordered or partially copied into the ordinary
    // config. Descriptions follow canonical module names, never array indexes
    // or global leaf-name aliases that could recognize retired fields.
    for(const std::string prefix:{"/filesystem/scan_filters/"}) {
        if(pointer.rfind(prefix,0)!=0) continue;
        auto suffix=pointer.find('/',prefix.size());
        if(!module.empty()) key=prefix+"@"+module+(suffix==std::string::npos?std::string():pointer.substr(suffix));
        break;
    }
    if(fields.contains(key)) return fields[key];
    static const Json empty=Json::object(); return empty;
}
}
std::string gui_language(const Json& config) {
    if(config.contains("cli") && config["cli"].is_object() && config["cli"].contains("language") && config["cli"]["language"].is_string()) {
        std::string_view value=config["cli"]["language"].get_ref<const std::string&>();
        const auto first=value.find_first_not_of(" \t\r\n\f\v");
        if(first!=std::string_view::npos) {
            value=value.substr(first,value.find_last_not_of(" \t\r\n\f\v")-first+1);
            const auto lower=[](char c){return c>='A' && c<='Z'?c-'A'+'a':c;};
            for(const auto& locale:locales)
                if(std::equal(value.begin(),value.end(),locale.code.begin(),locale.code.end(),
                    [&](char left,char right){return lower(left)==lower(right);}))
                    return std::string(locale.code);
        }
    }
    return std::string(locales[english_locale].code);
}
const wchar_t* gui_text_locale(std::string_view language) {
    return locales[locale_index(language)].windows_name;
}
std::string tr(std::string_view key,std::string_view language) {
    const auto* message=find_message(ui_messages,key);
    if(!message) message=find_message(native_messages,key);
    return message?std::string(message->texts[locale_index(language)]):std::string(key);
}
std::string startup_language(const fs::path& data_dir) {
    try { return gui_language(read_json(data_dir/"sunpack_config.json")); }
    catch(const std::exception&) { return "en"; }
}
std::string error_text(const std::string& key,const Json& arguments) {
    return Json{{"$guiError",key},{"arguments",arguments}}.dump();
}
Json interface_texts(const std::string& language) {
    const auto locale=locale_index(language);
    Json result=Json::object();
    auto& texts=result.get_ref<Json::object_t&>();
    texts.reserve(std::size(ui_messages));
    for(const auto& message:ui_messages) texts.emplace_back(message.key,message.texts[locale]);
    return result;
}
Json describe_setting(const std::string& pointer,const std::string& module,const std::string& language) {
    const auto& meta=setting(pointer,module);
    const auto locale=locale_index(language);
    auto group=pointer.substr(1,pointer.find('/',1)==std::string::npos?std::string::npos:pointer.find('/',1)-1);
    auto category=group=="recursive_authorization"?"recursive_extract":group;
    auto& groups=catalog()["groups"];
    std::string label=meta.contains("label")?local(meta["label"],locale):tr("readOnly",language);
    auto block=pointer.substr(0,pointer.rfind('/'));
    if(block.empty()) block=pointer;
    auto& blocks=catalog()["blocks"];
    auto& modules=catalog()["modules"];
    auto block_label=!module.empty()?(modules.contains(module)?local(modules[module],locale):module):
        blocks.contains(block)?local(blocks[block],locale):groups.contains(group)?local(groups[group],locale):label;
    bool primary=pointer.size()>=8 && pointer.compare(pointer.size()-8,8,"/enabled")==0 && !meta.empty();
    if(primary) label=block_label;
    Json result={{"label",label},{"category",category},{"categoryLabel",groups.contains(category)?local(groups[category],locale):tr("readOnly",language)},
        {"block",block},{"blockLabel",block_label},{"module",module},{"primary",primary},
        {"description",meta.contains("description")?local(meta["description"],locale):meta.empty()?tr("unknownDescription",language):std::string()},
        {"editor",meta.value("editor",std::string())},{"options",Json::array()},{"known",!meta.empty()}};
    if(pointer=="/cli/language") {
        for(const auto& choice:locales)
            result["options"].push_back({{"value",choice.code},{"label",choice.label}});
    } else if(meta.contains("options")) {
        for(const auto& option:meta["options"])
            result["options"].push_back({{"value",option["value"]},{"label",local(option["label"],locale)}});
    }
    return result;
}
void validate_setting(const std::string& pointer,const Json& value,const std::string& module) {
    const auto& meta=setting(pointer,module);
    if(meta.value("editor",std::string())=="rule_list") {
        if(!value.is_array()) throw std::runtime_error("settingTypeMismatch");
        for(const auto& entry:value) if(!entry.is_object() || entry.size()!=2 ||
            !entry.contains("value") || !entry["value"].is_string() || entry["value"].get_ref<const std::string&>().empty() ||
            !entry.contains("regex") || !entry["regex"].is_boolean()) throw std::runtime_error("validation");
    }
    if(pointer=="/cli/language") {
        if(!value.is_string() || std::none_of(std::begin(locales),std::end(locales),
            [&](const Locale& choice){return value.get_ref<const std::string&>()==choice.code;}))
            throw std::runtime_error("validation");
    } else if(pointer=="/recursive_extract") {
        auto text=value.is_string()?value.get<std::string>():value.dump();
        if(text=="*" || text=="?") return;
        if(text.empty() || text.find_first_not_of("0123456789")!=std::string::npos || text.find_first_not_of('0')==std::string::npos)
            throw std::runtime_error("validation");
    } else if(meta.contains("options")) {
        if(std::none_of(meta["options"].begin(),meta["options"].end(),[&](const Json& o){return o["value"]==value;})) throw std::runtime_error("validation");
    }
    if(value.is_number()) {
        double number=value.get<double>();
        if(!std::isfinite(number) || (meta.contains("min") && !meta["min"].is_null() && (meta.value("exclusive",false)?number<=meta["min"].get<double>():number<meta["min"].get<double>())) ||
            (meta.contains("max") && !meta["max"].is_null() && number>meta["max"].get<double>()) || (meta.value("integer",false) && std::floor(number)!=number)) throw std::runtime_error("validation");
    }
}
namespace {
std::string windows_message(DWORD code,const std::string& language) {
    wchar_t* buffer=nullptr;
    const auto locale=LANGIDFROMLCID(LocaleNameToLCID(gui_text_locale(language),0));
    auto size=FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,code,locale,reinterpret_cast<wchar_t*>(&buffer),0,nullptr);
    if(!size) return tr("windowsMessageUnavailable",language);
    std::wstring message(buffer,size); LocalFree(buffer);
    auto end=message.find_last_not_of(L" \t\r\n");
    message.resize(end==std::wstring::npos?0:end+1);
    return utf8(message);
}
std::string render_error(const std::string& message,const std::string& language,unsigned depth) {
    if(depth>8 || message.rfind("{\"$guiError\":",0)!=0) return tr(message,language);
    auto value=Json::parse(message,nullptr,false);
    if(!value.is_object() || !value.contains("$guiError") || !value["$guiError"].is_string() ||
        !value.contains("arguments") || !value["arguments"].is_object()) return message;
    auto key=value["$guiError"].get<std::string>();
    auto& arguments=value["arguments"];
    if(key=="windowsFailure" && arguments.contains("code") && arguments["code"].is_number_unsigned())
        arguments["detail"]=windows_message(arguments["code"].get<DWORD>(),language);
    auto pattern=tr(key,language);
    std::string result;
    size_t at=0;
    while(at<pattern.size()) {
        auto begin=pattern.find('{',at), end=begin==std::string::npos?begin:pattern.find('}',begin+1);
        if(end==std::string::npos) { result+=pattern.substr(at); break; }
        result+=pattern.substr(at,begin-at);
        auto field=arguments.find(pattern.substr(begin+1,end-begin-1));
        if(field==arguments.end()) result+=pattern.substr(begin,end-begin+1);
        else if(field->is_object() && field->contains("source") && (*field)["source"].is_string())
            result+=render_error((*field)["source"].get_ref<const std::string&>(),language,depth+1);
        else result+=field->is_string()?field->get_ref<const std::string&>():field->dump();
        at=end+1;
    }
    return result;
}
}
std::string translated_error(const std::string& message,const std::string& language) {
    return render_error(message,language,0);
}
}
