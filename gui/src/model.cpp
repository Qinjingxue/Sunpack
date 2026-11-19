#include "model.hpp"
#include "range_editor.hpp"
#include "presentation.hpp"
#include <algorithm>
#include <array>
#include <set>
#include <map>
#include <stdexcept>
#include <ctime>
#include <cmath>

namespace spg {
// Shared by filtering and paint-only find ranges. Non-expanding Windows case
// mapping preserves UTF-16 offsets for filenames and editable values.
std::wstring fold_search(const std::string& text) {
    auto w=wide(text);
    if(!w.empty()) CharLowerBuffW(w.data(),DWORD(w.size()));
    return w;
}
std::string task_time(double timestamp) {
    if(!std::isfinite(timestamp) || timestamp<0 || timestamp>32535215999.0) return {};
    auto seconds=static_cast<__time64_t>(timestamp);
    std::tm local{};
    if(_localtime64_s(&local,&seconds)) return {};
    char text[32]{};
    std::strftime(text,sizeof(text),"%Y-%m-%d %H:%M:%S",&local);
    return text;
}
std::string task_time_query(const std::wstring& query) {
    if(query.size()>19 || query.find_first_not_of(L"0123456789- :")!=std::wstring::npos) return {};
    std::string result; result.reserve(query.size());
    for(auto ch:query) result.push_back(static_cast<char>(ch));
    return result;
}
namespace {
std::string_view trim(std::string_view s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};
    return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
}
bool absolute_windows(const std::wstring& path) {
    const auto separator=[](wchar_t ch) { return ch==L'\\' || ch==L'/'; };
    if (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && separator(path[2])) return true;
    if (path.size() < 2 || !separator(path[0]) || !separator(path[1])) return false;
    auto slash = path.find_first_of(L"\\/", 2);
    return slash != std::wstring::npos && slash > 2 && slash+1 < path.size() && !separator(path[slash+1]);
}
std::wstring scope_key(const fs::path& path) {
    auto key=path_key(path);
    while(!key.empty() && (key.back()==L'\\' || key.back()==L'/')) key.pop_back();
    return key;
}
bool password_matches_scope_key(const Json& record,const std::wstring& selected) {
    if(record.is_null()) return false;
    if(selected.empty()) return !record.contains("scopes");
    return record.contains("scopes") && std::any_of(record["scopes"].begin(),record["scopes"].end(),[&](const Json& path) {
        return scope_key(wide(path.get<std::string>()))==selected;
    });
}
const std::string& password_text(const Json& value) {
    if (!value.is_string() || value.get_ref<const std::string&>().find('\0') != std::string::npos)
        throw std::runtime_error("passwordUnicodeRequired");
    return value.get_ref<const std::string&>();
}
void validate_password_text(const Json& value) {
    const auto& text=password_text(value);
    if (!text.empty() && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), int(text.size()), nullptr, 0))
        win_error("opDecodeUtf8");
}
void validate_password_record(const Json& record) {
    if (!record.is_object() || !record.contains("value")) throw std::runtime_error("passwordValueRequired");
    if (!record.contains("enabled") || !record["enabled"].is_boolean()) throw std::runtime_error("recordEnabledRequired");
    validate_password_text(record["value"]);
    for (auto it=record.begin(); it!=record.end(); ++it)
        if (it.key() != "value" && it.key() != "enabled" && it.key() != "scopes") throw std::runtime_error("passwordRecordUnknownField");
    if (record.contains("scopes")) {
        if (!record["scopes"].is_array() || record["scopes"].empty()) throw std::runtime_error("passwordScopesEmpty");
        for (const auto& scope : record["scopes"]) {
            if (!absolute_windows(wide(password_text(scope)))) throw std::runtime_error("passwordScopeAbsolute");
        }
    }
}
std::string pointer_escape(const std::string& key) {
    std::string out;
    for (char c : key) {
        if(c=='~') out+="~0";
        else if(c=='/') out+="~1";
        else out.push_back(c);
    }
    return out;
}
// Locate original JSON tokens after syntax validation. Splicing just the edited
// token preserves unknown fields, formatting, and numbers beyond uint64 exactly.
struct JsonTokens {
    struct Range { size_t start=0,length=0; bool descend=false; };
    const std::string& source;
    size_t at=0;
    std::unordered_map<std::string,Range> ranges;
    explicit JsonTokens(const std::string& text):source(text) {}
    void select(std::string path) {
        if(!path.empty() && path.front()!='/') return;
        ranges.try_emplace(path);
        while(!path.empty()) {
            path.resize(path.rfind('/'));
            auto& ancestor=ranges[path];
            if(ancestor.descend) break;
            ancestor.descend=true;
        }
    }
    void scan() {
        if(ranges.empty()) return;
        at=source.rfind("\xef\xbb\xbf",0)==0?3:0;
        value(ranges.find(""));
    }
    void space() { while(at<source.size() && (source[at]==' ' || source[at]=='\t' || source[at]=='\r' || source[at]=='\n')) ++at; }
    void string() {
        ++at;
        while(at<source.size()) { auto c=source[at++]; if(c=='\\') ++at; else if(c=='"') return; }
    }
    void skip_value() {
        // Unselected subtrees need no decoded keys or paths. The source has
        // already passed JSON validation, so only strings affect nesting here.
        size_t depth=0;
        do {
            const auto c=source.at(at);
            if(c=='"') { string(); continue; }
            if(c=='{' || c=='[') ++depth;
            else if(c=='}' || c==']') --depth;
            else if(!depth) {
                while(at<source.size() && std::string_view(",]} \t\r\n").find(source[at])==std::string_view::npos) ++at;
                return;
            }
            ++at;
        } while(depth);
    }
    void value(decltype(ranges)::iterator selected) {
        space(); auto start=at; auto c=source.at(at);
        if(selected==ranges.end()) { skip_value(); return; }
        const auto& path=selected->first;
        if(selected->second.descend && c=='{') {
            ++at; space();
            while(source.at(at)!='}') {
                auto begin=at; string();
                auto key=parse_json(source.substr(begin,at-begin)).get<std::string>();
                auto child=path+"/"+pointer_escape(key);
                space(); ++at; value(ranges.find(child));
                space();
                if(source.at(at)!=',') break; ++at; space();
            }
            ++at;
        } else if(selected->second.descend && c=='[') {
            ++at; space(); size_t index=0;
            while(source.at(at)!=']') {
                value(ranges.find(path+"/"+std::to_string(index++))); space();
                if(source.at(at)!=',') break; ++at; space();
            }
            ++at;
        } else skip_value();
        selected->second.start=start;
        selected->second.length=at-start;
    }
    std::string_view text(const Range& range) const { return std::string_view(source).substr(range.start,range.length); }
};
}
bool password_matches_scope(const Json& record,const std::string& scope) {
    return password_matches_scope_key(record,scope.empty() || scope=="@all"?std::wstring():scope_key(wide(scope)));
}
Json parse_json(const std::string& text) {
    std::vector<std::set<std::string>> fields;
    try { return Json::parse(text, [&fields](int, Json::parse_event_t event, Json& value) {
        if (event == Json::parse_event_t::object_start) fields.emplace_back();
        else if (event == Json::parse_event_t::key && !fields.back().insert(value.get<std::string>()).second)
            throw std::runtime_error("jsonDuplicateKey");
        else if (event == Json::parse_event_t::object_end) fields.pop_back();
        return true;
    }); } catch(const Json::parse_error& error) {
        throw std::runtime_error(error_text("invalidJson",{{"byte",error.byte}}));
    }
}
Json read_json(const fs::path& path) { return parse_json(read_file(path)); }
void validate_passwords(const Json& j) {
    if (!j.is_object() || !j.contains("passwords") || !j["passwords"].is_array())
        throw std::runtime_error("passwordArrayRequired");
    for (auto it=j.begin(); it!=j.end(); ++it)
        if (it.key() != "passwords" && it.key() != "clipboard_history") throw std::runtime_error("passwordFileUnknownField");
    for (const auto& record : j["passwords"]) validate_password_record(record);
    if (j.contains("clipboard_history")) {
        if (!j["clipboard_history"].is_array()) throw std::runtime_error("clipboardArrayRequired");
        for (const auto& item : j["clipboard_history"]) validate_password_text(item);
    }
}
static std::string format_password_document(const Json& document) {
    std::string text="{\n";
    for(auto it=document.begin();it!=document.end();++it) {
        if(it!=document.begin()) text+=",\n";
        text.append("  \"").append(it.key()).append("\": ").append(it->dump());
    }
    text+="\n}\n";
    return text;
}

static std::string patch_config(std::string source,const Json& edit) {
    Json j=parse_json(source); JsonTokens tokens(source);
    const auto& pointer=edit.at("pointer").get_ref<const std::string&>();
    tokens.select(pointer);
    tokens.scan();
    const auto& original=edit.at("original").get_ref<const std::string&>();
    const auto& type=edit.at("type").get_ref<const std::string&>();
    const auto& text=edit.at("text").get_ref<const std::string&>();
    Json::json_pointer target(pointer);
    if(!j.contains(target)) throw std::runtime_error("settingChanged");
    const auto& range=tokens.ranges.at(pointer);
    if(tokens.text(range)!=original) throw std::runtime_error("settingChanged");
    Json replacement=type=="string"?Json(text):type=="boolean"?Json(edit.at("boolean").get<bool>()):parse_json(text);
    if((type=="number" && !replacement.is_number()) || (type=="array" && !replacement.is_array()) ||
       (type=="object" && !replacement.is_object())) throw std::runtime_error("settingTypeMismatch");
    std::string module;
    const auto parent=Json::json_pointer(pointer.substr(0,pointer.find_last_of('/')));
    if(j.contains(parent)) {
        const auto& owner=j.at(parent);
        if(owner.is_object() && owner.contains("name") && owner["name"].is_string()) module=owner["name"].get<std::string>();
    }
    if(module=="size_range" || module=="mtime_range") throw std::runtime_error("rangeAtomic");
    const auto& current=j.at(target);
    if(current.is_object() && current.contains("name") && (current["name"]=="size_range" || current["name"]=="mtime_range"))
        validate_range_module(replacement,current["name"]=="mtime_range");
    else validate_setting(pointer,replacement,module);
    if(type=="string" || type=="boolean") source.replace(range.start,range.length,replacement.dump());
    else source.replace(range.start,range.length,text);
    return source;
}
// Scope identity and ancestry match the runtime's directory-scoped lookup.
// Only values touched by this edit are normalized; unrelated entries
// and significant password whitespace remain intact.
static Json deduplicate_passwords(Json& records, const std::unordered_set<std::string>& values, size_t target, size_t existing_count) {
    struct Scope { const Json* path; bool other; };
    struct Group {
        std::vector<size_t> rows;
        std::map<std::wstring,Scope> scopes;
        bool global = false, other_global = false;
    };
    std::array<std::unordered_map<std::string_view,Group>,2> groups;
    for(size_t i=0;i<records.size();++i) {
        const auto& value=records[i]["value"].get_ref<const std::string&>();
        const auto touched=values.find(value);
        if(touched==values.end()) continue;
        auto& group=groups[records[i].at("enabled").get<bool>()][*touched]; group.rows.push_back(i);
        const bool other=i!=target && i<existing_count;
        if(!records[i].contains("scopes")) { group.global=true; if(other) group.other_global=true; }
        else for(const auto& path:records[i]["scopes"]) {
            auto entry=group.scopes.try_emplace(scope_key(wide(path.get_ref<const std::string&>())),Scope{&path,other}).first;
            if(other && !entry->second.other) entry->second={&path,true};
        }
    }
    std::vector<bool> keep;
    Json saved;
    for(auto& partition:groups) for(auto& [value,group]:partition) {
        auto covered=[&](std::wstring key,bool other) {
            for(;;) {
                auto found=group.scopes.find(key);
                if(found!=group.scopes.end() && (!other || found->second.other)) return true;
                auto slash=key.rfind(L'\\');
                if(slash==std::wstring::npos) return false;
                key.resize(slash);
            }
        };
        auto inherited=[&](const std::wstring& key) {
            auto slash=key.rfind(L'\\');
            return slash!=std::wstring::npos && covered(key.substr(0,slash),false);
        };
        const bool selected=std::find(group.rows.begin(),group.rows.end(),target)!=group.rows.end();
        bool contributes=false,visible=false;
        if(selected) {
            if(!records[target].contains("scopes")) { contributes=!group.other_global; visible=true; }
            else if(!group.global) for(auto& path:records[target]["scopes"]) {
                auto key=scope_key(wide(path.get_ref<const std::string&>()));
                if(!group.other_global && !covered(key,true)) contributes=true;
                if(!inherited(key)) visible=true;
            }
        }
        // Keep an existing row's file position when a new scope joins it.
        auto canonical=group.rows.front();
        if(canonical==target) for(auto index:group.rows) if(index!=target && index<existing_count) { canonical=index; break; }
        Json record={{"value",value},{"enabled",records[canonical].at("enabled")}};
        if(!group.global) {
            Json paths=Json::array();
            for(const auto& [key,scope]:group.scopes) if(!inherited(key)) paths.push_back(*scope.path);
            record["scopes"]=std::move(paths);
        }
        records[canonical]=std::move(record);
        if(group.rows.size()>1) {
            if(keep.empty()) keep.resize(records.size(),true);
            for(auto i:group.rows) if(i!=canonical) keep[i]=false;
        }
        if(selected && contributes && visible) saved=records[canonical];
    }
    if(keep.empty()) return saved;
    size_t out=0;
    for(size_t i=0;i<records.size();++i) if(keep[i]) { if(out!=i) records[out]=std::move(records[i]); ++out; }
    records.erase(records.begin()+out,records.end());
    return saved;
}
static bool remove_password_scope(Json& record,const std::wstring& selected) {
    if(!record.contains("scopes") || selected.empty()) throw std::runtime_error("scopeNotDirect");
    auto& scopes=record["scopes"];
    auto end=std::remove_if(scopes.begin(),scopes.end(),[&](const Json& scope) {
        return scope_key(wide(scope.get_ref<const std::string&>()))==selected;
    });
    if(end==scopes.end()) throw std::runtime_error("scopeInherited");
    scopes.erase(end,scopes.end());
    return scopes.empty();
}
static Json patch_password(Json& records, const std::string& op, const Json& original,
    Json replacement, const std::string& scope) {
    const auto previous_count=records.size();
    size_t target=records.size();
    std::unordered_set<std::string> touched;
    const auto validate_replacement=[&](const Json& record) {
        validate_password_record(record);
        touched.insert(record["value"].get_ref<const std::string&>());
    };
    if (op == "add") {
        validate_replacement(replacement);
        records.push_back(std::move(replacement));
    }
    else if(op=="addMany") {
        if(!replacement.is_array() || replacement.empty()) throw std::runtime_error("batchEmpty");
        for(auto& record:replacement) {
            validate_replacement(record);
            records.push_back(std::move(record));
        }
    }
    else {
        auto it = std::find(records.begin(), records.end(), original);
        if (it == records.end()) throw std::runtime_error("passwordChanged");
        target=size_t(it-records.begin());
        if (op == "delete") records.erase(it);
        else if (op == "removeScope") {
            if(scope.empty()) throw std::runtime_error("scopeNotDirect");
            if(remove_password_scope(*it,scope_key(wide(scope)))) records.erase(it);
        } else if (op == "replace") {
            Json remaining;
            if(!scope.empty()) {
                remaining=*it;
                remove_password_scope(remaining,scope_key(wide(scope)));
            }
            validate_replacement(replacement);
            *it=std::move(replacement);
            // Editing one displayed scope must preserve all other scope links.
            if(!remaining.is_null() && !remaining["scopes"].empty()) records.push_back(std::move(remaining));
        }
        else throw std::runtime_error("passwordOperationUnknown");
    }
    if(!original.is_null()) touched.insert(original["value"].get_ref<const std::string&>());
    if(op!="add" && op!="addMany" && op!="replace") target=records.size();
    return deduplicate_passwords(records,touched,target,op=="addMany"?previous_count:records.size());
}
static Json apply_password_changes(Json& document,const Json& edits) {
    auto& records=document["passwords"];
    Json saved_record;
    bool first=true;
    for(auto& edit:edits) {
        if(edit.contains("originals")) {
            const bool history=edit.at("history").get<bool>();
            auto& rows=document.at(history?"clipboard_history":"passwords");
            const auto directory=edit.value("scope",std::string());
            const auto scope=history || directory.empty()?std::wstring():scope_key(wide(directory));
            const auto& originals=edit.at("originals");
            std::unordered_multiset<std::string> selected(originals.begin(),originals.end());
            size_t kept=0;
            for(size_t i=0;i<rows.size();++i) {
                auto& row=rows[i];
                auto found=selected.find(history?row.get_ref<const std::string&>():row.dump());
                if(found!=selected.end()) {
                    selected.erase(found);
                    if(history || scope.empty() || remove_password_scope(row,scope)) continue;
                }
                if(kept!=i) rows[kept]=std::move(row);
                ++kept;
            }
            if(!selected.empty()) throw std::runtime_error("passwordChanged");
            rows.erase(rows.begin()+kept,rows.end());
            continue;
        }
        Json replacement={{"value",edit.value("value",std::string())},{"enabled",edit.value("enabled",true)}};
        auto scopes=edit.value("scopes",Json::array()); if(!scopes.empty()) replacement["scopes"]=scopes;
        auto op=edit.at("operation").get<std::string>();
        if(op=="addMany") {
            Json batch=Json::array();
            for(auto& value:edit.at("values")) { auto record=replacement; record["value"]=value; batch.push_back(std::move(record)); }
            replacement=std::move(batch);
        }
        auto original=edit.value("original",std::string());
        auto record=patch_password(records,op,original.empty()?Json():parse_json(original),std::move(replacement),edit.value("scope",std::string()));
        if(first) saved_record=std::move(record);
        first=false;
    }
    return saved_record;
}
WatchRoots parse_roots(std::string_view text, const fs::path& base, std::string* comments) {
    WatchRoots result; std::unordered_map<std::wstring,size_t> positions;
    if (text.rfind("\xef\xbb\xbf",0) == 0) text.remove_prefix(3);
    auto flag=[](std::string_view value,const char* error) {
        if(value.empty()) return false;
        std::string lower(value);
        std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return char(tolower(c));});
        if(lower!="true" && lower!="false") throw std::runtime_error(error);
        return lower=="true";
    };
    while (!text.empty()) {
        const auto end=text.find_first_of("\r\n");
        auto line=text.substr(0,end);
        text.remove_prefix(end==std::string_view::npos?text.size():end+1);
        auto value = trim(line);
        if (value.empty()) continue;
        if (value[0]=='#') {
            if (comments) {
                comments->append(line);
                comments->push_back('\n');
            }
            continue;
        }
        std::array<std::string_view,6> parts{};
        for (size_t i=0;;++i) {
            if(i==parts.size()) throw std::runtime_error("rootsLineInvalid");
            const auto sep=value.find('|');
            parts[i]=trim(value.substr(0,sep));
            if(sep==std::string_view::npos) break;
            value.remove_prefix(sep+1);
        }
        if (parts[0].empty()) continue;
        const auto deep=flag(parts[2],"deepDetectInvalid");
        const auto scanned=flag(parts[3],"rootsLineInvalid");
        const auto recursive=flag(parts[4],"rootsLineInvalid");
        if(parts[5].empty()) throw std::runtime_error("rootsLineInvalid");
        WatchRoot entry{resolve_path(wide(parts[0]),base),std::string(parts[1]),deep,scanned,recursive,flag(parts[5],"rootsLineInvalid")};
        const auto [it,inserted]=positions.try_emplace(path_key(entry.input),result.size());
        if (inserted) result.push_back(std::move(entry));
        else { entry.input=std::move(result[it->second].input); result[it->second]=std::move(entry); }
    }
    return result;
}
WatchRoots read_roots(const fs::path& p, std::string* comments,const fs::path& base) {
    if (!fs::exists(p)) return {};
    return parse_roots(read_file(p),base.empty()?p.parent_path():base,comments);
}
static void apply_root_changes(WatchRoots& roots,const fs::path& base,const Json& edits) {
    // Normalize each existing key once. A multi-line paste must not rescan
    // and normalize the complete directory list for every added row.
    std::unordered_map<std::wstring,size_t> indices;
    indices.reserve(roots.size()+edits.size());
    for(size_t i=0;i<roots.size();++i) indices.emplace(path_key(roots[i].input),i);
    std::vector<bool> removed(roots.size(),false);
    bool compact=false;
    auto apply=[&](const Json& edit,const std::string& input) {
        std::string op=edit.at("operation"), original=edit.value("original",std::string()), output=edit.at("output");
        bool enabled=edit.value("enabled",true), deep=edit.at("deep"), recursive=edit.value("recursive",false);
        auto path = resolve_path(wide(input),base);
        if (input.empty() || input.find_first_of("|\r\n") != std::string::npos || output.find_first_of("|\r\n") != std::string::npos)
            throw std::runtime_error("rootInvalid");
        auto previous = original.empty()?std::wstring():path_key(wide(original));
        auto found=indices.find(previous);
        auto index=found==indices.end()?size_t(-1):found->second;
        if (!original.empty() && index==size_t(-1)) throw std::runtime_error("rootRemoved");
        if(!original.empty() && edit.contains("expected") && !edit["expected"].is_null() &&
            (roots[index].enabled!=edit["expected"].value("enabled",true) || roots[index].output!=edit["expected"].value("output",std::string()) || roots[index].deep!=edit["expected"].value("deep",false) || roots[index].recursive!=edit["expected"].value("recursive",false)))
            throw std::runtime_error("rootConflict");
        auto remove=[&] {
            if(index!=size_t(-1)) { removed[index]=true; indices.erase(previous); compact=true; }
        };
        if (op=="delete") remove();
        else {
            auto key=path_key(path);
            auto duplicate=indices.find(key);
            if (duplicate!=indices.end() && duplicate->second!=index) {
                const auto& record=roots[duplicate->second];
                if(record.enabled==enabled && record.output==trim(output) && record.deep==deep && record.recursive==recursive) { remove(); return; }
                throw std::runtime_error("rootDuplicate");
            }
            WatchRoot replacement{std::move(path),std::string(trim(output)),deep,false,recursive,enabled};
            if(index!=size_t(-1) && previous==key)
                replacement.initial_scanned=roots[index].initial_scanned && !(recursive && !roots[index].recursive);
            if(index==size_t(-1)) {
                indices.emplace(std::move(key),roots.size());
                roots.push_back(std::move(replacement)); removed.push_back(false);
            } else {
                indices.erase(previous); indices[std::move(key)]=index;
                roots[index]=std::move(replacement);
            }
        }
    };
    for(auto& edit:edits) {
        if(edit.at("operation")=="addMany") {
            const auto& inputs=edit.at("inputs");
            if(!inputs.is_array() || inputs.empty()) throw std::runtime_error("rootsEmpty");
            for(auto& input:inputs) apply(edit,input.get<std::string>());
        } else apply(edit,edit.at("input").get<std::string>());
    }
    if(compact) {
        size_t count=0;
        for(size_t i=0;i<roots.size();++i) if(!removed[i]) {
            if(count!=i) roots[count]=std::move(roots[i]);
            ++count;
        }
        roots.resize(count);
    }
}
static void append_roots(std::string& content,const WatchRoots& roots) {
    for(const auto& r:roots) content+=utf8(r.input.wstring())+
        " | "+r.output+" | "+(r.deep?"true":"false")+" | "+(r.initial_scanned?"true":"false")+" | "+(r.recursive?"true":"false")+" | "+(r.enabled?"true":"false")+"\n";
}
Json save_changes(const fs::path& dir,const Json& field,const Json& passwords,const Json& roots,
    PasswordSaveSnapshot* password_snapshot,std::string_view password_baseline,const fs::path& root_base) {
    Json result={{"saved",Json::array()},{"error",""}};
    struct Write { std::string section; fs::path path; std::string text; };
    std::vector<Write> writes;
    Json committed_passwords;
    Json saved_record;
    Json password_rebases=Json::array();
    bool delta_base_matches=false;
    const bool deleting_roots=std::any_of(roots.begin(),roots.end(),[](const Json& edit){return edit.at("operation")=="delete";});
    std::unordered_set<std::wstring> removed_scopes;
    std::string root_text,original_password_text;
    std::unique_ptr<FileMutex> config_lock,password_lock,roots_lock;
    try {
        // Keep GUI writers in a fixed acquisition order. Runtime writers keep
        // using their existing individual file locks.
        if(!field.is_null()) config_lock=std::make_unique<FileMutex>(dir/"sunpack_config.json");
        if(!passwords.empty() || deleting_roots) password_lock=std::make_unique<FileMutex>(dir/"builtin_passwords.json");
        if(!roots.empty()) roots_lock=std::make_unique<FileMutex>(dir/"sunpack_watch_roots.txt",L"SunPackWatchRoots");
        if(!field.is_null()) { auto path=dir/"sunpack_config.json"; writes.push_back({"config",path,patch_config(read_file(path),field)}); }
        if(!roots.empty()) {
            const auto& base=root_base.empty()?dir:root_base;
            auto updated=read_roots(dir/"sunpack_watch_roots.txt",&root_text,base);
            apply_root_changes(updated,base,roots);
            if(deleting_roots) {
                std::unordered_set<std::wstring> remaining;
                remaining.reserve(updated.size());
                for(const auto& entry:updated) remaining.insert(scope_key(entry.input));
                for(const auto& edit:roots) if(edit.at("operation")=="delete" && !edit.value("original",std::string()).empty()) {
                    auto key=scope_key(resolve_path(wide(edit.at("original").get<std::string>()),base));
                    if(!remaining.count(key)) removed_scopes.insert(std::move(key));
                }
            }
            append_roots(root_text,updated);
        }
        if(!passwords.empty() || (!removed_scopes.empty() && fs::exists(dir/"builtin_passwords.json"))) {
            auto path=dir/"builtin_passwords.json";
            original_password_text=read_file(path);
            delta_base_matches=original_password_text==password_baseline;
            auto current=parse_json(original_password_text);
            if(!deleting_roots) std::string().swap(original_password_text);
            validate_passwords(current);
            auto count=current["passwords"].size();
            struct RebaseRows { std::vector<std::string> before; const Json* after = nullptr; };
            using Rebases=std::unordered_map<std::string,RebaseRows>;
            std::array<Rebases,2> rebases;
            const auto affected=[&] { return !rebases[0].empty() || !rebases[1].empty(); };
            if(password_snapshot) {
                for(const auto& edit:passwords) {
                    auto& group=rebases[edit.value("enabled",true)];
                    if(edit.contains("value")) group.try_emplace(edit.at("value").get_ref<const std::string&>());
                    if(edit.contains("values")) for(const auto& value:edit.at("values")) group.try_emplace(value.get_ref<const std::string&>());
                    auto original=edit.value("original",std::string());
                    if(!original.empty()) {
                        auto row=parse_json(original);
                        rebases[row.at("enabled").get<bool>()].try_emplace(row.at("value").get<std::string>());
                    }
                }
                if(affected()) for(const auto& record:current["passwords"]) {
                    auto& group=rebases[record.at("enabled").get<bool>()];
                    auto found=group.find(record["value"].get_ref<const std::string&>());
                    if(found!=group.end()) found->second.before.push_back(record.dump());
                }
            }
            saved_record=apply_password_changes(current,passwords);
            committed_passwords=std::move(current);
            bool cleaned=false;
            if(!removed_scopes.empty()) {
                auto& rows=committed_passwords["passwords"];
                size_t kept=0;
                for(size_t i=0;i<rows.size();++i) {
                    auto& record=rows[i];
                    if(record.contains("scopes")) {
                        auto& scopes=record["scopes"];
                        auto matches=[&](const Json& scope){return removed_scopes.count(scope_key(wide(scope.get<std::string>())));};
                        auto first=std::find_if(scopes.begin(),scopes.end(),matches);
                        if(first!=scopes.end()) {
                            auto previous=password_snapshot?record.dump():std::string();
                            scopes.erase(std::remove_if(first,scopes.end(),matches),scopes.end()); cleaned=true;
                            if(password_snapshot) password_rebases.push_back({{"originals",Json::array({previous})},{"record",scopes.empty()?Json():record}});
                        }
                        if(scopes.empty()) continue;
                    }
                    if(kept!=i) rows[kept]=std::move(record);
                    ++kept;
                }
                rows.erase(rows.begin()+kept,rows.end());
            }
            if(affected()) {
                auto remaining=rebases[0].size()+rebases[1].size();
                for(auto& record:committed_passwords["passwords"]) {
                    auto& group=rebases[record.at("enabled").get<bool>()];
                    auto found=group.find(record["value"].get_ref<const std::string&>());
                    if(found!=group.end() && !found->second.after) {
                        found->second.after=&record;
                        if(!--remaining) break;
                    }
                }
                for(auto& group:rebases) for(auto& [value,rebase]:group) {
                    auto& previous=rebase.before;
                    const auto encoded=rebase.after?rebase.after->dump():std::string();
                    previous.erase(std::remove(previous.begin(),previous.end(),encoded),previous.end());
                    if(!previous.empty()) password_rebases.push_back({{"originals",std::move(previous)},{"record",rebase.after?*rebase.after:Json()}});
                }
            }
            delta_base_matches&=count==committed_passwords["passwords"].size();
            if(!passwords.empty() || cleaned) writes.push_back({"passwords",path,format_password_document(committed_passwords)});
        }
        if(!roots.empty()) writes.push_back({"roots",dir/"sunpack_watch_roots.txt",std::move(root_text)});
        for(auto& write:writes) {
            const auto& section=write.section;
            try { atomic_write(write.path,write.text); }
            catch(...) {
                if(section=="roots" && deleting_roots && std::find(result["saved"].begin(),result["saved"].end(),"passwords")!=result["saved"].end()) {
                    atomic_write(dir/"builtin_passwords.json",original_password_text);
                    auto& saved=result["saved"]; saved.erase(std::remove(saved.begin(),saved.end(),Json("passwords")),saved.end());
                    if(password_snapshot) *password_snapshot=PasswordSaveSnapshot{};
                }
                throw;
            }
            result["saved"].push_back(section);
            if(section=="passwords" && password_snapshot) {
                password_snapshot->document=std::move(committed_passwords);
                password_snapshot->file_text=std::move(write.text);
                password_snapshot->record=std::move(saved_record);
                password_snapshot->rebases=std::move(password_rebases);
                password_snapshot->delta_base_matches=delta_base_matches;
            }
        }
    } catch(const std::exception& error) { result["error"]=error.what(); }
    return result;
}
void EventLog::set_path(const fs::path& p) {
    if (path_==p) return;
    manifest=Json();
    path_=p;
}
bool EventLog::refresh() {
    auto next=read_json(path_);
    if(!next.is_object() || next.value("format",0)!=1) throw std::runtime_error("logRecordTooLarge");
    // File identity detects rebuilt storage even when counters collide.
    // Diagnostic-only appends can change run sizes without changing tasks.
    auto same_run=[](const Json& a,const Json& b) {
        return a.is_null() || b.is_null()?a==b:a.at("name")==b.at("name");
    };
    auto changed=manifest.is_null() || next.value("task_revision",uint64_t(0))!=manifest.value("task_revision",uint64_t(0)) ||
        !std::equal(next.at("runs").begin(),next.at("runs").end(),manifest.at("runs").begin(),manifest.at("runs").end(),same_run) ||
        !same_run(next.at("live"),manifest.at("live"));
    manifest=std::move(next);
    return changed;
}

fs::path task_directory(const Json& row) {
    auto root=row.value("root",std::string());
    auto input=fs::path(wide(row.value("path",std::string())));
    auto monitored=root.empty() || root=="@other"?input.parent_path():fs::path(wide(root));
    auto exists=[](const fs::path& path) { std::error_code error; return !path.empty() && fs::is_directory(path,error); };
    if(row.contains("outputs") && row["outputs"].is_array()) for(auto& output:row["outputs"]) {
        if(!output.is_string() || output.get_ref<const std::string&>().empty()) continue;
        auto directory=resolve_path(wide(output.get<std::string>()),monitored);
        if(exists(directory)) return directory;
    }
    if(exists(monitored)) return monitored;
    if(exists(input.parent_path())) return input.parent_path();
    throw std::runtime_error("pathMissing");
}
Json password_rows(const Json& passwords,const View& v) {
    Json rows=Json::array();
    const bool history=v.password_scope=="@history";
    const auto source=passwords.find(history?"clipboard_history":"passwords");
    if(source!=passwords.end()) {
        const auto query=fold_search(v.password_query);
        const auto selected=history || v.password_scope=="@all"?std::wstring():scope_key(wide(v.password_scope));
        for(const auto& record:*source) {
            if(!history && !password_matches_scope_key(record,selected)) continue;
            const auto& value=history?record:record.at("value");
            if(!query.empty() && fold_search(value.get_ref<const std::string&>()).find(query)==std::wstring::npos) continue;
            if(history) rows.push_back({{"value",value}});
            else rows.push_back({{"value",value},{"enabled",record.at("enabled")},{"original",record.dump()}});
        }
    }
    return {{"rows",std::move(rows)},{"scope",v.password_scope}};
}
Json config_fields(const Json& config,const std::string& source,const std::string& language) {
    Json rows=Json::array();
    if(config.empty()) return rows;
    JsonTokens tokens(source);
    std::function<void(const Json&,std::string,std::string)> walk;
    walk=[&](const Json& item,std::string pointer,std::string module) {
        if(item.is_object() && !item.empty()) {
            if(item.contains("name") && item["name"].is_string()) module=item["name"].get<std::string>();
            if(pointer.rfind("/filesystem/scan_filters/",0)==0 && pointer.find('/',25)==std::string::npos && (module=="size_range" || module=="mtime_range")) {
                tokens.select(pointer);
                auto field=describe_setting(pointer,module,language);
                field.update(Json{{"id",pointer},{"key",pointer+"@"+language+"@"+module},{"type","object"},
                    {"boolean",false},{"choice",-1},{"items",Json::array()},
                    {"block",pointer},{"primary",true},{"editor",module=="mtime_range"?"datetime_range":"size_range"},{"range",range_editor(item)}});
                rows.push_back(std::move(field)); return;
            }
            for(auto it=item.begin();it!=item.end();++it) if(it.key()!="name" || module.empty()) walk(it.value(),pointer+"/"+pointer_escape(it.key()),module);
            return;
        }
        auto field=describe_setting(pointer,module,language);
        if(item.is_array() && !item.empty() && field["editor"]!="rule_list" && std::all_of(item.begin(),item.end(),[](const Json& i){return i.is_object();})) {
            for(size_t i=0;i<item.size();++i) walk(item[i],pointer+"/"+std::to_string(i),module); return;
        }
        std::string type=item.is_boolean()?"boolean":item.is_string()?"string":item.is_number()?"number":item.is_array()?"array":item.is_object()?"object":"null";
        tokens.select(pointer);
        std::string editor=field["editor"], text=item.is_string()?item.get<std::string>():std::string();
        if(editor.empty()) editor=!field["known"].get<bool>()?"readonly":!field["options"].empty()?"choice":type=="boolean"?"toggle":type=="string"||type=="number"?"text":"readonly";
        int choice=-1;
        for(size_t i=0;i<field["options"].size();++i) if(field["options"][i]["value"]==item) choice=int(i);
        if(editor=="recursive" && choice<0) choice=2;
        field.update(Json{{"id",pointer},{"key",pointer+"@"+language},{"type",type},{"text",std::move(text)},{"boolean",item.is_boolean()?item.get<bool>():false},
            {"editor",editor},{"choice",choice},{"items",editor=="rule_list"?item:Json::array()}});
        rows.push_back(std::move(field));
    };
    walk(config,"","");
    tokens.scan();
    for(auto& field:rows) {
        const auto& id=field["id"].get_ref<const std::string&>();
        const auto& range=tokens.ranges.at(id);
        if(!range.length) throw std::out_of_range("settingChanged");
        const auto raw=tokens.text(range);
        field["original"]=std::string(raw);
        if(field["type"]!="string") field["text"]=std::string(raw);
    }
    return rows;
}
Json directory_rows(const WatchRoots& roots) {
    Json rows=Json::array();
    for(auto& r:roots) {
        auto key=path_key(r.input);
        rows.push_back({{"id",utf8(key)},{"path",utf8(r.input.wstring())},{"name",utf8(r.input.filename().wstring())},
            {"output",r.output},{"deep",r.deep},{"recursive",r.recursive},{"enabled",r.enabled}});
    }
    return rows;
}
}
