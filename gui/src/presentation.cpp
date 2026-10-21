#include "presentation.hpp"
#include "catalog_json.h"
#include <algorithm>
#include <cmath>

namespace spg {
namespace {
const Json& catalog() { static const auto data=parse_json(kCatalogJson); return data; }
std::string local(const Json& value,const std::string& language) {
    return value.value(language,value.value("en",std::string()));
}
const Json& setting(const std::string& pointer,const std::string& module) {
    const auto& fields=catalog()["fields"];
    auto key=pointer;
    // Named arrays may be reordered or partially copied into the ordinary
    // config. Descriptions follow canonical module names, never array indexes
    // or global leaf-name aliases that could recognize retired fields.
    for(const std::string prefix:{"/filesystem/scan_filters/","/analysis/modules/","/verification/methods/"}) {
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
        auto value=config["cli"]["language"].get<std::string>();
        value.erase(0,value.find_first_not_of(" \t\r\n"));
        auto end=value.find_last_not_of(" \t\r\n"); if(end!=std::string::npos) value.resize(end+1);
        std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return char(tolower(c));});
        if(value=="zh") return "zh";
    }
    return "en"; // Same fallback as CLI normalize_language.
}
std::string tr(const std::string& key,const std::string& language) {
    const auto& texts=catalog()["ui"];
    return texts.contains(key)?local(texts[key],language):key;
}
std::string startup_language(const fs::path& data_dir) {
    try { return gui_language(read_json(data_dir/"sunpack_config.json")); }
    catch(const std::exception&) { return "en"; }
}
std::string error_text(const std::string& key,const Json& arguments) {
    return Json{{"$guiError",key},{"arguments",arguments}}.dump();
}
Json interface_texts(const std::string& language) {
    Json result=Json::object();
    for(auto it=catalog()["ui"].begin();it!=catalog()["ui"].end();++it) result[it.key()]=local(it.value(),language);
    return result;
}
Json describe_setting(const std::string& pointer,const std::string& module,const std::string& language) {
    const auto& meta=setting(pointer,module);
    auto group=pointer.substr(1,pointer.find('/',1)==std::string::npos?std::string::npos:pointer.find('/',1)-1);
    auto category=group=="recursive_authorization"?"recursive_extract":group;
    auto& groups=catalog()["groups"];
    std::string label=meta.contains("label")?local(meta["label"],language):tr("readOnly",language);
    auto block=pointer.substr(0,pointer.rfind('/'));
    if(block.empty()) block=pointer;
    auto& blocks=catalog()["blocks"];
    auto& modules=catalog()["modules"];
    auto block_label=!module.empty()?(modules.contains(module)?local(modules[module],language):module):
        blocks.contains(block)?local(blocks[block],language):groups.contains(group)?local(groups[group],language):label;
    bool primary=pointer!="/watch/enabled" && pointer.size()>=8 && pointer.compare(pointer.size()-8,8,"/enabled")==0 && !meta.empty();
    if(primary) label=block_label;
    Json result={{"label",label},{"category",category},{"categoryLabel",groups.contains(category)?local(groups[category],language):tr("readOnly",language)},
        {"block",block},{"blockLabel",block_label},{"module",module},{"primary",primary},
        {"description",meta.contains("description")?local(meta["description"],language):meta.empty()?tr("unknownDescription",language):std::string()},
        {"editor",meta.value("editor",std::string())},{"options",Json::array()},{"known",!meta.empty()}};
    if(meta.contains("options")) for(auto& option:meta["options"]) result["options"].push_back({{"value",option["value"]},{"label",local(option["label"],language)}});
    return result;
}
void validate_setting(const std::string& pointer,const Json& value,const std::string& module) {
    const auto& meta=setting(pointer,module);
    if(pointer=="/recursive_extract") {
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
    auto locale=language=="zh"?MAKELANGID(LANG_CHINESE,SUBLANG_CHINESE_SIMPLIFIED):MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US);
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
