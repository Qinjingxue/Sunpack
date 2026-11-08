#include "model.hpp"
#include "range_editor.hpp"
#include "presentation.hpp"
#include <algorithm>
#include <set>
#include <map>
#include <sstream>
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
std::string trim(std::string s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
}
bool contains_folded(const std::string& text, const std::wstring& folded_query) {
    return folded_query.empty() || fold_search(text).find(folded_query)!=std::wstring::npos;
}
bool absolute_windows(const std::string& value) {
    auto p = wide(value); std::replace(p.begin(), p.end(), L'/', L'\\');
    if (p.size() >= 3 && iswalpha(p[0]) && p[1] == L':' && p[2] == L'\\') return true;
    if (p.rfind(L"\\\\", 0) != 0) return false;
    auto slash = p.find(L'\\', 2);
    return slash != std::wstring::npos && slash > 2 && slash+1 < p.size() && p[slash+1] != L'\\';
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
void check_text(const Json& value) {
    if (!value.is_string() || value.get_ref<const std::string&>().find('\0') != std::string::npos)
        throw std::runtime_error("passwordUnicodeRequired");
    wide(value.get<std::string>());
}
std::string pointer_escape(const std::string& key) {
    std::string out;
    for (char c : key) out += c == '~' ? "~0" : c == '/' ? "~1" : std::string(1,c);
    return out;
}
// Locate original JSON tokens after syntax validation. Splicing just the edited
// token preserves unknown fields, formatting, and numbers beyond uint64 exactly.
struct JsonTokens {
    const std::string& source;
    size_t at=0;
    std::unordered_map<std::string,std::pair<size_t,size_t>> ranges;
    void space() { while(at<source.size() && (source[at]==' ' || source[at]=='\t' || source[at]=='\r' || source[at]=='\n')) ++at; }
    void string() {
        ++at;
        while(at<source.size()) { auto c=source[at++]; if(c=='\\') ++at; else if(c=='"') return; }
    }
    void value(const std::string& path) {
        space(); auto start=at; auto c=source.at(at);
        if(c=='{') {
            ++at; space();
            while(source.at(at)!='}') {
                auto begin=at; string();
                auto key=parse_json(source.substr(begin,at-begin)).get<std::string>();
                auto child=path+"/"+pointer_escape(key);
                space(); ++at; value(child);
                space();
                if(source.at(at)!=',') break; ++at; space();
            }
            ++at;
        } else if(c=='[') {
            ++at; space(); size_t index=0;
            while(source.at(at)!=']') {
                value(path+"/"+std::to_string(index++)); space();
                if(source.at(at)!=',') break; ++at; space();
            }
            ++at;
        } else if(c=='"') string();
        else while(at<source.size() && std::string(",]} \t\r\n").find(source[at])==std::string::npos) ++at;
        ranges[path]={start,at-start};
    }
    explicit JsonTokens(const std::string& text):source(text) { if(text.rfind("\xef\xbb\xbf",0)==0) at=3; value(""); }
    std::string token(const std::string& path) const { auto r=ranges.at(path); return source.substr(r.first,r.second); }
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
    for (auto& record : j["passwords"]) {
        if (!record.is_object() || !record.contains("value")) throw std::runtime_error("passwordValueRequired");
        check_text(record["value"]);
        for (auto it=record.begin(); it!=record.end(); ++it)
            if (it.key() != "value" && it.key() != "scopes") throw std::runtime_error("passwordRecordUnknownField");
        if (record.contains("scopes")) {
            if (!record["scopes"].is_array() || record["scopes"].empty()) throw std::runtime_error("passwordScopesEmpty");
            for (auto& scope : record["scopes"]) {
                check_text(scope);
                if (!absolute_windows(scope.get<std::string>())) throw std::runtime_error("passwordScopeAbsolute");
            }
        }
    }
    if (j.contains("clipboard_history")) {
        if (!j["clipboard_history"].is_array()) throw std::runtime_error("clipboardArrayRequired");
        for (auto& item : j["clipboard_history"]) check_text(item);
    }
}
namespace {
struct ConfigEditError:std::runtime_error {
    std::string pointer;
    ConfigEditError(std::string pointer,const std::string& message):std::runtime_error(message),pointer(std::move(pointer)) {}
};
}
static std::string patch_config(std::string source,const Json& edits) {
    Json j=parse_json(source); JsonTokens tokens(source);
    struct Change { size_t start,length; std::string value; };
    std::vector<Change> changes;
    for(auto& edit:edits) {
        std::string pointer=edit.at("pointer"), original=edit.at("original"), type=edit.at("type"), text=edit.at("text");
        bool boolean=edit.at("boolean");
        try {
        Json::json_pointer target(pointer);
        if (!j.contains(target) || tokens.token(pointer) != original) throw std::runtime_error("settingChanged");
        Json replacement = type == "string" ? Json(text) : type == "boolean" ? Json(boolean) : parse_json(text);
        if ((type == "number" && !replacement.is_number()) || (type == "array" && !replacement.is_array()) ||
            (type == "object" && !replacement.is_object())) throw std::runtime_error("settingTypeMismatch");
        std::string module;
        auto parent=pointer.substr(0,pointer.find_last_of('/'));
        if(j.contains(Json::json_pointer(parent))) {
            const auto& owner=j.at(Json::json_pointer(parent));
            if(owner.is_object() && owner.contains("name") && owner["name"].is_string()) module=owner["name"].get<std::string>();
        }
        if(module=="size_range" || module=="mtime_range") throw std::runtime_error("rangeAtomic");
        const auto& current=j.at(target);
        if(current.is_object() && current.contains("name") && (current["name"]=="size_range" || current["name"]=="mtime_range"))
            validate_range_module(replacement,current["name"]=="mtime_range");
        else validate_setting(pointer,replacement,module);
        auto range=tokens.ranges.at(pointer);
        changes.push_back({range.first,range.second,type=="string" || type=="boolean"?replacement.dump():text});
        } catch(const std::exception& error) { throw ConfigEditError(pointer,error.what()); }
    }
    std::sort(changes.begin(),changes.end(),[](const Change& a,const Change& b){return a.start>b.start;});
    size_t boundary=source.size();
    for(auto& change:changes) {
        if(change.start+change.length>boundary) throw std::runtime_error("validation");
        source.replace(change.start,change.length,change.value); boundary=change.start;
    }
    return source;
}
// Scope identity and ancestry match the runtime's directory-scoped lookup.
// Only values touched by this edit are normalized; unrelated entries
// and significant password whitespace remain intact.
static Json deduplicate_passwords(Json& records, const std::unordered_set<std::string>& values, size_t target, size_t existing_count) {
    struct Scope { Json path; bool other = false; };
    struct Group {
        std::vector<size_t> rows;
        std::map<std::wstring,Scope> scopes;
        bool global = false, other_global = false;
    };
    std::unordered_map<std::string,Group> groups;
    for(size_t i=0;i<records.size();++i) {
        const auto& value=records[i]["value"].get_ref<const std::string&>();
        if(!values.count(value)) continue;
        auto& group=groups[value]; group.rows.push_back(i);
        const bool other=i!=target && i<existing_count;
        if(!records[i].contains("scopes")) { group.global=true; if(other) group.other_global=true; }
        else for(auto& path:records[i]["scopes"]) {
            auto entry=group.scopes.try_emplace(scope_key(wide(path.get<std::string>())),Scope{path}).first;
            if(other) { if(!entry->second.other) entry->second.path=path; entry->second.other=true; }
        }
    }
    std::vector<bool> keep(records.size(),true);
    Json saved;
    for(auto& [value,group]:groups) {
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
                auto key=scope_key(wide(path.get<std::string>()));
                if(!group.other_global && !covered(key,true)) contributes=true;
                if(!inherited(key)) visible=true;
            }
        }
        // Keep an existing row's file position when a new scope joins it.
        auto canonical=group.rows.front();
        if(canonical==target) for(auto index:group.rows) if(index!=target && index<existing_count) { canonical=index; break; }
        Json record={{"value",value}};
        if(!group.global) {
            Json paths=Json::array();
            for(auto& [key,scope]:group.scopes) if(!inherited(key)) paths.push_back(std::move(scope.path));
            record["scopes"]=std::move(paths);
        }
        records[canonical]=std::move(record);
        for(auto i:group.rows) if(i!=canonical) keep[i]=false;
        if(selected && contributes && visible) saved=records[canonical];
    }
    size_t out=0;
    for(size_t i=0;i<records.size();++i) if(keep[i]) { if(out!=i) records[out]=std::move(records[i]); ++out; }
    records.erase(records.begin()+out,records.end());
    return saved;
}
static Json patch_password(Json& j, const std::string& op, const Json& original,
    const Json& replacement, const std::string& scope) {
    auto& records = j["passwords"];
    const auto previous_count=records.size();
    size_t target=records.size();
    std::unordered_set<std::string> touched;
    if (op == "add") { records.push_back(replacement); }
    else if(op=="addMany") {
        if(!replacement.is_array() || replacement.empty()) throw std::runtime_error("batchEmpty");
        for(auto& record:replacement) records.push_back(record);
    }
    else {
        auto it = std::find(records.begin(), records.end(), original);
        if (it == records.end()) throw std::runtime_error("passwordChanged");
        target=size_t(it-records.begin());
        if (op == "delete") records.erase(it);
        else if (op == "removeScope") {
            if (!it->contains("scopes") || scope.empty()) throw std::runtime_error("scopeNotDirect");
            auto& scopes = (*it)["scopes"];
            auto end = std::remove_if(scopes.begin(), scopes.end(), [selected_scope=scope_key(wide(scope))](const Json& s) {
                return scope_key(wide(s.get<std::string>())) == selected_scope;
            });
            if (end == scopes.end()) throw std::runtime_error("scopeInherited");
            scopes.erase(end, scopes.end());
            if (scopes.empty()) records.erase(it);
        } else if (op == "replace") {
            Json remaining;
            if(!scope.empty()) {
                if(!it->contains("scopes")) throw std::runtime_error("scopeNotDirect");
                remaining=*it;
                auto& paths=remaining["scopes"];
                auto end=std::remove_if(paths.begin(),paths.end(),[selected=scope_key(wide(scope))](const Json& path) {
                    return scope_key(wide(path.get<std::string>()))==selected;
                });
                if(end==paths.end()) throw std::runtime_error("scopeInherited");
                paths.erase(end,paths.end());
            }
            *it=replacement;
            // Editing one displayed scope must preserve all other scope links.
            if(!remaining.is_null() && !remaining["scopes"].empty()) records.push_back(std::move(remaining));
        }
        else throw std::runtime_error("passwordOperationUnknown");
    }
    validate_passwords(j);
    if(!original.is_null()) touched.insert(original["value"].get<std::string>());
    if(op=="addMany") for(auto& record:replacement) touched.insert(record["value"].get<std::string>());
    else if(op=="add" || op=="replace") touched.insert(replacement["value"].get<std::string>());
    if(op!="add" && op!="addMany" && op!="replace") target=records.size();
    return deduplicate_passwords(records,touched,target,op=="addMany"?previous_count:records.size());
}
Json apply_password_changes(Json document,const Json& edits,Json* saved_record) {
    validate_passwords(document);
    bool first=true;
    for(auto& edit:edits) {
        Json replacement={{"value",edit.value("value",std::string())}};
        auto scopes=edit.value("scopes",Json::array()); if(!scopes.empty()) replacement["scopes"]=scopes;
        auto op=edit.at("operation").get<std::string>();
        if(op=="addMany") {
            Json batch=Json::array();
            for(auto& value:edit.at("values")) { auto record=replacement; record["value"]=value; batch.push_back(std::move(record)); }
            replacement=std::move(batch);
        }
        auto original=edit.value("original",std::string());
        auto record=patch_password(document,op,original.empty()?Json():parse_json(original),replacement,edit.value("scope",std::string()));
        if(first && saved_record) *saved_record=std::move(record);
        first=false;
    }
    return document;
}
WatchRoots parse_roots(const std::string& raw, const fs::path& base) {
    WatchRoots result; std::unordered_map<std::wstring,size_t> positions;
    std::string text = raw;
    if (text.rfind("\xef\xbb\xbf",0) == 0) text.erase(0,3);
    std::istringstream in(text); std::string line;
    while (std::getline(in, line)) {
        auto value = trim(line);
        if (value.empty()) continue;
        if (value[0]=='#') { if (!line.empty() && line.back()=='\r') line.pop_back(); result.comments.push_back(line); continue; }
        std::vector<std::string> parts; size_t at=0;
        for (;;) {
            auto sep=value.find('|',at); parts.push_back(trim(value.substr(at,sep==std::string::npos?sep:sep-at)));
            if (sep==std::string::npos) break; at=sep+1;
        }
        if (parts.size()>5) throw std::runtime_error("rootsLineInvalid");
        if (parts[0].empty()) continue;
        std::string deep = parts.size()>=3 ? parts[2] : "";
        std::transform(deep.begin(),deep.end(),deep.begin(),[](unsigned char c){ return char(tolower(c)); });
        if (!deep.empty() && deep!="true" && deep!="false") throw std::runtime_error("deepDetectInvalid");
        std::string scanned = parts.size()>=4 ? parts[3] : "";
        std::transform(scanned.begin(),scanned.end(),scanned.begin(),[](unsigned char c){ return char(tolower(c)); });
        if (!scanned.empty() && scanned!="true" && scanned!="false") throw std::runtime_error("rootsLineInvalid");
        std::string recursive=parts.size()>=5?parts[4]:"";
        std::transform(recursive.begin(),recursive.end(),recursive.begin(),[](unsigned char c){return char(tolower(c));});
        if(!recursive.empty() && recursive!="true" && recursive!="false") throw std::runtime_error("rootsLineInvalid");
        WatchRoot entry{resolve_path(wide(parts[0]),base), parts.size()>=2?parts[1]:"", deep=="true", scanned=="true", recursive=="true"};
        auto key=path_key(entry.input); auto it=positions.find(key);
        if (it==positions.end()) { positions[key]=result.entries.size(); result.entries.push_back(entry); }
        else { entry.input=result.entries[it->second].input; result.entries[it->second]=entry; }
    }
    return result;
}
WatchRoots read_roots(const fs::path& p) {
    if (!fs::exists(p)) return {};
    return parse_roots(read_file(p),p.parent_path());
}
static WatchRoots apply_root_changes(WatchRoots roots,const fs::path& base,const Json& edits) {
    // Normalize each existing key once. A multi-line paste must not rescan
    // and normalize the complete directory list for every added row.
    std::unordered_map<std::wstring,size_t> indices;
    indices.reserve(roots.entries.size()+edits.size());
    for(size_t i=0;i<roots.entries.size();++i) indices.emplace(path_key(roots.entries[i].input),i);
    std::vector<bool> removed(roots.entries.size(),false);
    bool compact=false;
    auto apply=[&](const Json& edit,const std::string& input) {
        std::string op=edit.at("operation"), original=edit.value("original",std::string()), output=edit.at("output");
        bool deep=edit.at("deep"), recursive=edit.value("recursive",false);
        auto path = resolve_path(wide(input),base);
        if (input.empty() || input.find_first_of("|\r\n") != std::string::npos || output.find_first_of("|\r\n") != std::string::npos)
            throw std::runtime_error("rootInvalid");
        if (op!="delete" && !fs::is_directory(path)) throw std::runtime_error("rootMissing");
        auto previous = original.empty()?std::wstring():path_key(wide(original));
        auto found=indices.find(previous);
        auto index=found==indices.end()?size_t(-1):found->second;
        if (!original.empty() && index==size_t(-1)) throw std::runtime_error("rootRemoved");
        if(!original.empty() && edit.contains("expected") && !edit["expected"].is_null() &&
            (roots.entries[index].output!=edit["expected"].value("output",std::string()) || roots.entries[index].deep!=edit["expected"].value("deep",false) || roots.entries[index].recursive!=edit["expected"].value("recursive",false)))
            throw std::runtime_error("rootConflict");
        auto remove=[&] {
            if(index!=size_t(-1)) { removed[index]=true; indices.erase(previous); compact=true; }
        };
        if (op=="delete") remove();
        else {
            auto key=path_key(path);
            auto duplicate=indices.find(key);
            if (duplicate!=indices.end() && duplicate->second!=index) {
                const auto& record=roots.entries[duplicate->second];
                if(record.output==trim(output) && record.deep==deep && record.recursive==recursive) { remove(); return; }
                throw std::runtime_error("rootDuplicate");
            }
            WatchRoot replacement{path,trim(output),deep,false,recursive};
            if(index!=size_t(-1) && path_key(roots.entries[index].input)==key)
                replacement.initial_scanned=roots.entries[index].initial_scanned && !(recursive && !roots.entries[index].recursive);
            if(index==size_t(-1)) {
                indices.emplace(std::move(key),roots.entries.size());
                roots.entries.push_back(std::move(replacement)); removed.push_back(false);
            } else {
                indices.erase(previous); indices[std::move(key)]=index;
                roots.entries[index]=std::move(replacement);
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
        for(size_t i=0;i<roots.entries.size();++i) if(!removed[i]) {
            if(count!=i) roots.entries[count]=std::move(roots.entries[i]);
            ++count;
        }
        roots.entries.resize(count);
    }
    return roots;
}
static std::string roots_text(const WatchRoots& roots) {
    std::string content;
    for(auto& c:roots.comments) content+=c+"\n";
    for(auto& r:roots.entries) content+=utf8(r.input.wstring())+
        " | "+r.output+" | "+(r.deep?"true":"false")+" | "+(r.initial_scanned?"true":"false")+" | "+(r.recursive?"true":"false")+"\n";
    return content;
}
Json save_changes(const fs::path& dir,const Json& fields,const Json& passwords,const Json& roots,
    PasswordSaveSnapshot* password_snapshot,std::string_view password_baseline) {
    Json result={{"saved",Json::array()},{"error",""},{"section",""}};
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
    std::string section;
    try {
        // Keep GUI writers in a fixed acquisition order. Runtime writers keep
        // using their existing individual file locks.
        if(!fields.empty()) config_lock=std::make_unique<FileMutex>(dir/"sunpack_config.json");
        if(!passwords.empty() || deleting_roots) password_lock=std::make_unique<FileMutex>(dir/"builtin_passwords.json");
        if(!roots.empty()) roots_lock=std::make_unique<FileMutex>(dir/"sunpack_watch_roots.txt",L"SunPackWatchRoots");
        if(!fields.empty()) { section="config"; auto path=dir/"sunpack_config.json"; writes.push_back({section,path,patch_config(read_file(path),fields)}); }
        if(!roots.empty()) {
            section="roots";
            auto updated=apply_root_changes(read_roots(dir/"sunpack_watch_roots.txt"),dir,roots);
            std::unordered_set<std::wstring> remaining;
            for(auto& entry:updated.entries) remaining.insert(scope_key(entry.input.wstring()));
            for(auto& edit:roots) if(edit.at("operation")=="delete" && !edit.value("original",std::string()).empty()) {
                auto key=scope_key(resolve_path(wide(edit.at("original").get<std::string>()),dir).wstring());
                if(!remaining.count(key)) removed_scopes.insert(std::move(key));
            }
            root_text=roots_text(updated);
        }
        if(!passwords.empty() || (!removed_scopes.empty() && fs::exists(dir/"builtin_passwords.json"))) {
            section="passwords"; auto path=dir/"builtin_passwords.json";
            original_password_text=read_file(path);
            auto current=parse_json(original_password_text); validate_passwords(current);
            auto count=current["passwords"].size();
            struct RebaseRows { std::vector<std::string> before; const Json* after = nullptr; };
            std::unordered_map<std::string,RebaseRows> rebases;
            if(password_snapshot) {
                for(auto& edit:passwords) {
                    if(edit.contains("value") && edit["value"].is_string()) rebases.try_emplace(edit["value"].get_ref<const std::string&>());
                    if(edit.contains("values")) for(auto& value:edit["values"]) if(value.is_string()) rebases.try_emplace(value.get_ref<const std::string&>());
                    auto original=edit.value("original",std::string());
                    if(!original.empty()) rebases.try_emplace(parse_json(original)["value"].get<std::string>());
                }
                if(!rebases.empty()) {
                    for(auto& record:current["passwords"]) {
                        auto found=rebases.find(record["value"].get_ref<const std::string&>());
                        if(found!=rebases.end()) found->second.before.push_back(record.dump());
                    }
                    for(auto it=rebases.begin();it!=rebases.end();) {
                        if(it->second.before.empty()) it=rebases.erase(it);
                        else ++it;
                    }
                }
            }
            committed_passwords=apply_password_changes(std::move(current),passwords,&saved_record);
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
            if(!rebases.empty()) {
                for(auto& record:committed_passwords["passwords"]) {
                    auto found=rebases.find(record["value"].get_ref<const std::string&>());
                    if(found!=rebases.end() && !found->second.after) found->second.after=&record;
                }
                for(auto& [value,rebase]:rebases) {
                    auto& previous=rebase.before;
                    const auto encoded=rebase.after?rebase.after->dump():std::string();
                    previous.erase(std::remove(previous.begin(),previous.end(),encoded),previous.end());
                    if(!previous.empty()) password_rebases.push_back({{"originals",std::move(previous)},{"record",rebase.after?*rebase.after:Json()}});
                }
            }
            delta_base_matches=count==committed_passwords["passwords"].size() && original_password_text==password_baseline;
            if(!passwords.empty() || cleaned) writes.push_back({section,path,committed_passwords.dump(2)+"\n"});
        }
        if(!roots.empty()) writes.push_back({"roots",dir/"sunpack_watch_roots.txt",std::move(root_text)});
        for(auto& write:writes) {
            section=write.section;
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
    } catch(const ConfigEditError& error) { result["error"]=error.what(); result["section"]=section; result["field"]=error.pointer; }
    catch(const std::exception& error) { result["error"]=error.what(); result["section"]=section; }
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
        next.value("dropped",uint64_t(0))!=manifest.value("dropped",uint64_t(0)) ||
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
        if(history) {
            for(const auto& p:*source) if(contains_folded(p.get_ref<const std::string&>(),query))
                rows.push_back({{"id",std::to_string(rows.size())},{"value",p},{"original",""}});
        } else {
            const auto selected=v.password_scope=="@all"?std::wstring():scope_key(wide(v.password_scope));
            for(const auto& p:*source) {
                if(!password_matches_scope_key(p,selected)) continue;
                const auto& value=p.at("value");
                if(!contains_folded(value.get_ref<const std::string&>(),query)) continue;
                // The UI assigns and preserves saved-row ids across snapshots.
                rows.push_back({{"value",value},{"original",p.dump()}});
            }
        }
    }
    const auto total=rows.size();
    return {{"rows",std::move(rows)},{"total",total},{"scope",v.password_scope}};
}
Json config_fields(const Json& config,const std::string& source,const std::string& language) {
    Json rows=Json::array();
    if(config.empty()) return rows;
    std::unique_ptr<JsonTokens> tokens;
    if(!source.empty()) tokens=std::make_unique<JsonTokens>(source);
    std::function<void(const Json&,std::string,std::string)> walk;
    walk=[&](const Json& item,std::string pointer,std::string module) {
        if(item.is_object() && !item.empty()) {
            if(item.contains("name") && item["name"].is_string()) module=item["name"].get<std::string>();
            if(pointer.rfind("/filesystem/scan_filters/",0)==0 && pointer.find('/',25)==std::string::npos && (module=="size_range" || module=="mtime_range")) {
                auto raw=tokens?tokens->token(pointer):item.dump();
                auto field=describe_setting(pointer,module,language);
                field.update(Json{{"id",pointer},{"key",pointer+"@"+language+"@"+module},{"type","object"},
                    {"original",raw},{"text",raw},{"boolean",false},{"choice",-1},{"items",Json::array()},
                    {"block",pointer},{"primary",true},{"editor",module=="mtime_range"?"datetime_range":"size_range"},{"range",range_editor(item)}});
                rows.push_back(std::move(field)); return;
            }
            for(auto it=item.begin();it!=item.end();++it) if(it.key()!="name" || module.empty()) walk(it.value(),pointer+"/"+pointer_escape(it.key()),module);
            return;
        }
        if(item.is_array() && !item.empty() && describe_setting(pointer,module,language)["editor"]!="rule_list" && std::all_of(item.begin(),item.end(),[](const Json& i){return i.is_object();})) {
            for(size_t i=0;i<item.size();++i) walk(item[i],pointer+"/"+std::to_string(i),module); return;
        }
        std::string type=item.is_boolean()?"boolean":item.is_string()?"string":item.is_number()?"number":item.is_array()?"array":item.is_object()?"object":"null";
        auto raw=tokens?tokens->token(pointer):item.dump(2);
        auto field=describe_setting(pointer,module,language);
        std::string editor=field["editor"], text=item.is_string()?item.get<std::string>():raw;
        if(editor.empty()) editor=!field["known"].get<bool>()?"readonly":!field["options"].empty()?"choice":type=="boolean"?"toggle":type=="string"||type=="number"?"text":"readonly";
        int choice=-1;
        for(size_t i=0;i<field["options"].size();++i) if(field["options"][i]["value"]==item) choice=int(i);
        if(editor=="recursive" && choice<0) choice=2;
        field.update(Json{{"id",pointer},{"key",pointer+"@"+language},{"type",type},{"original",raw},{"text",text},{"boolean",item.is_boolean()?item.get<bool>():false},
            {"editor",editor},{"choice",choice},{"items",editor=="rule_list"?item:Json::array()}});
        rows.push_back(std::move(field));
    };
    walk(config,"",""); return rows;
}
Json directory_rows(const WatchRoots& roots) {
    Json rows=Json::array();
    for(auto& r:roots.entries) {
        auto key=path_key(r.input);
        rows.push_back({{"id",utf8(key)},{"path",utf8(r.input.wstring())},{"name",utf8(r.input.filename().wstring())},
            {"output",r.output},{"deep",r.deep},{"recursive",r.recursive}});
    }
    return rows;
}
fs::path log_directory(const fs::path& dir) {
    return dir/".sunpack_watch";
}
}
