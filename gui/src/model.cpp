#include "model.hpp"
#include "range_editor.hpp"
#include "presentation.hpp"
#include <algorithm>
#include <chrono>
#include <set>
#include <map>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <ctime>
#include <cmath>
#include <optional>

namespace spg {
namespace {
std::string trim(std::string s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
}
// Search uses the same non-expanding Windows casing as path identity.
std::wstring fold_search(const std::string& text) {
    auto w=wide(text);
    if(!w.empty()) CharLowerBuffW(w.data(),DWORD(w.size()));
    return w;
}
bool contains_folded(const std::string& text, const std::wstring& folded_query) {
    return folded_query.empty() || fold_search(text).find(folded_query)!=std::wstring::npos;
}
bool contains(const std::string& text, const std::string& query) {
    return query.empty() || contains_folded(text,fold_search(query));
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
std::string text_at(HANDLE f, uint64_t offset, size_t count) {
    LARGE_INTEGER pos{}; pos.QuadPart = offset;
    if (!SetFilePointerEx(f, pos, nullptr, FILE_BEGIN)) win_error("opSeekLog");
    std::string out(count, 0); DWORD got = 0;
    if (count && !ReadFile(f, out.data(), DWORD(count), &got, nullptr)) win_error("opReadLog");
    out.resize(got); return out;
}
bool terminal(const Task& task) { return task.status=="taskSucceeded" || task.status=="taskFailed"; }
// Longest directory-prefix match by walking up the task path, not by scanning
// every watch root for every task. Normalized keys retain the existing NT
// case-folding/UNC rules; trimming the final separator also handles C:\\ roots.
using RootIndex=std::unordered_map<std::wstring,std::string>;
RootIndex index_roots(const WatchRoots& roots) {
    RootIndex index; index.reserve(roots.entries.size());
    for(const auto& root:roots.entries) {
        auto key=path_key(root.input);
        while(!key.empty() && (key.back()==L'\\' || key.back()==L'/')) key.pop_back();
        index.emplace(std::move(key),utf8(root.input.wstring()));
    }
    return index;
}
std::string indexed_root(const std::wstring& key,const RootIndex& index) {
    std::wstring current=key;
    while(!current.empty() && (current.back()==L'\\' || current.back()==L'/')) current.pop_back();
    while(!current.empty()) {
        auto found=index.find(current);
        if(found!=index.end()) return found->second;
        auto separator=current.find_last_of(L"\\/");
        if(separator==std::wstring::npos) break;
        current.resize(separator);
    }
    return "@other";
}
std::optional<double> iso_timestamp(const std::string& text) {
    std::tm time{}; std::istringstream in(text);
    in>>std::get_time(&time,"%Y-%m-%dT%H:%M:%S");
    if(in.fail()) return {};
    double seconds=double(_mkgmtime64(&time));
    size_t at=19;
    if(at<text.size() && text[at]=='.') {
        char* end=nullptr; seconds+=std::strtod(text.c_str()+at,&end); at=size_t(end-text.c_str());
    }
    if(at+5<text.size() && (text[at]=='+' || text[at]=='-')) {
        auto zone=text.substr(at+1,2)+text.substr(at+4,2);
        if(zone.find_first_not_of("0123456789")==std::string::npos) {
            int minutes=std::stoi(zone.substr(0,2))*60+std::stoi(zone.substr(2,2));
            seconds+=text[at]=='+'?-minutes*60:minutes*60;
        }
    }
    return seconds;
}
std::string task_time(const Task& task) {
    if(!task.has_timestamp || !std::isfinite(task.timestamp) || task.timestamp<0 || task.timestamp>32535215999.0) return {};
    auto seconds=static_cast<__time64_t>(task.timestamp);
    std::tm local{};
    if(_localtime64_s(&local,&seconds)) return {};
    char text[32]{};
    std::strftime(text,sizeof(text),"%Y-%m-%d %H:%M:%S",&local);
    return text;
}
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
void save_config_field(const fs::path& p,const std::string& pointer,const std::string& original,
    const std::string& type,const std::string& text,bool boolean) {
    FileMutex lock(p);
    atomic_write(p,patch_config(read_file(p),Json::array({Json{{"pointer",pointer},{"original",original},{"type",type},{"text",text},{"boolean",boolean}}})));
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
void edit_password(const fs::path& p,const std::string& op,const Json& original,const Json& replacement,const std::string& scope) {
    FileMutex lock(p); auto document=read_json(p); validate_passwords(document);
    patch_password(document,op,original,replacement,scope); atomic_write(p,document.dump(2)+"\n");
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
WatchRoots apply_root_changes(WatchRoots roots,const fs::path& base,const Json& edits) {
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
void edit_root(const fs::path& p,const std::string& op,const std::string& original,const std::string& input,const std::string& output,bool deep) {
    auto result=save_changes(p.parent_path(),Json::array(),Json::array(),Json::array({Json{{"operation",op},{"original",original},{"input",input},{"output",output},{"deep",deep}}}));
    if(result["error"]!="") throw std::runtime_error(result["error"].get<std::string>());
}
Json save_changes(const fs::path& dir,const Json& fields,const Json& passwords,const Json& roots,
    PasswordSaveSnapshot* password_snapshot) {
    Json result={{"saved",Json::array()},{"error",""},{"section",""}};
    struct Write { std::string section; fs::path path; std::string text; };
    std::vector<Write> writes;
    Json committed_passwords;
    Json saved_record;
    Json password_rebases=Json::array();
    bool password_count_changed=false;
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
            std::unordered_map<std::string,std::vector<std::string>> originals;
            if(password_snapshot) {
                std::unordered_set<std::string> affected;
                for(auto& edit:passwords) {
                    if(edit.contains("value") && edit["value"].is_string()) affected.insert(edit["value"].get<std::string>());
                    if(edit.contains("values")) for(auto& value:edit["values"]) if(value.is_string()) affected.insert(value.get<std::string>());
                    auto original=edit.value("original",std::string());
                    if(!original.empty()) affected.insert(parse_json(original)["value"].get<std::string>());
                }
                for(auto& record:current["passwords"]) {
                    const auto& value=record["value"].get_ref<const std::string&>();
                    if(affected.count(value)) originals[value].push_back(record.dump());
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
            if(!originals.empty()) {
                std::unordered_map<std::string,const Json*> records;
                for(auto& record:committed_passwords["passwords"]) records.emplace(record["value"].get<std::string>(),&record);
                for(auto& [value,previous]:originals) {
                    auto found=records.find(value);
                    const auto record=found==records.end()?Json():*found->second;
                    const auto encoded=record.is_null()?std::string():record.dump();
                    previous.erase(std::remove(previous.begin(),previous.end(),encoded),previous.end());
                    if(!previous.empty()) password_rebases.push_back({{"originals",std::move(previous)},{"record",record}});
                }
            }
            password_count_changed=count!=committed_passwords["passwords"].size();
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
                password_snapshot->count_changed=password_count_changed;
            }
        }
    } catch(const ConfigEditError& error) { result["error"]=error.what(); result["section"]=section; result["field"]=error.pointer; }
    catch(const std::exception& error) { result["error"]=error.what(); result["section"]=section; }
    return result;
}
std::string root_for(const fs::path& path,const WatchRoots& roots) {
    return indexed_root(path_key(path),index_roots(roots));
}
struct EventLog::Publication {
    Handle process, dirty, published, mapping, stop{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    const volatile LONG64* revision = nullptr;
    std::thread thread;
    explicit Publication(const Json& header,const std::function<void()>& changed) {
        auto name=wide(header.value("generation",std::string()));
        if(name.rfind(L"Local\\SunPack.State.",0)!=0 || name.size()>200) return;
        process.value=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,header.value("owner_pid",DWORD(0)));
        FILETIME created{},exit{},kernel{},user{};
        if(!process.value || !GetProcessTimes(process,&created,&exit,&kernel,&user)) return;
        auto started=(uint64_t(created.dwHighDateTime)<<32)|created.dwLowDateTime;
        if(std::to_string(started)!=header.value("owner_started",std::string())) return;
        dirty.value=OpenEventW(SYNCHRONIZE,FALSE,(name+L".dirty").c_str());
        published.value=OpenEventW(SYNCHRONIZE,FALSE,(name+L".published").c_str());
        mapping.value=OpenFileMappingW(FILE_MAP_READ,FALSE,(name+L".revision").c_str());
        if(mapping.value) revision=static_cast<const volatile LONG64*>(MapViewOfFile(mapping,FILE_MAP_READ,0,0,8));
        if(!dirty.value || !published.value || !revision) return;
        const bool initial_health=valid();
        if(changed) thread=std::thread([this,changed,initial_health]{
            bool healthy=initial_health;
            for(;;) {
                HANDLE waits[]={stop,process,healthy?dirty.value:published.value};
                auto signal=WaitForMultipleObjects(3,waits,FALSE,INFINITE);
                if(signal==WAIT_OBJECT_0 || signal==WAIT_FAILED) return;
                changed();
                if(signal==WAIT_OBJECT_0+1) return;
                healthy=valid();
            }
        });
    }
    bool valid() const {
        return process.value && dirty.value && published.value && revision &&
            WaitForSingleObject(process,0)==WAIT_TIMEOUT &&
            WaitForSingleObject(dirty,0)==WAIT_TIMEOUT && WaitForSingleObject(published,0)==WAIT_OBJECT_0;
    }
    bool matches(uint64_t expected) const { return valid() && uint64_t(*revision)==expected && valid(); }
    uint64_t current_revision() const { return valid()?uint64_t(*revision):0; }
    ~Publication() { SetEvent(stop); if(thread.joinable()) thread.join(); if(revision) UnmapViewOfFile(const_cast<const LONG64*>(revision)); }
};
EventLog::EventLog(std::function<void()> changed):publication_changed_(std::move(changed)) {}
EventLog::~EventLog() = default;
bool EventLog::unverify() {
    if(!verified_) return false;
    verified_=false; for(auto& pair:tasks) mark_changed(pair.first); return true;
}
void EventLog::set_path(const fs::path& p) {
    if (path_==p) return;
    path_=p; offset_=identity_=sequence_=volume_=0; prefix_.clear(); anchor_.clear(); pending_.clear(); tasks.clear(); aliases_.clear(); malformed=0;
    changed_keys.clear(); rebuilt=true;
    publication_.reset(); generation_.clear(); publication_revision_=retried_revision_=0; state_ready_=verified_=false;
}
void EventLog::mark_changed(const std::wstring& key) {
    ++sequence_;
    changed_keys.insert(key);
}
void EventLog::erase_task(const std::wstring& key) {
    auto it=tasks.find(key);
    if(it==tasks.end()) return;
    for(auto& member:it->second.members) aliases_.erase(member);
    tasks.erase(it); mark_changed(key);
}
void EventLog::accept_group(const Json& group) {
    if(!group.is_object() || !group.contains("path") || !group["path"].is_string() ||
        !group.contains("members") || !group["members"].is_array()) return;
    auto path=group["path"].get<std::string>();
    if(path.empty()) return;
    std::unordered_set<std::wstring> members;
    for(auto& member:group["members"]) if(member.is_string() && !member.get_ref<const std::string&>().empty()) {
        members.insert(path_key(wide(member.get_ref<const std::string&>())));
    }
    if(members.empty()) return;
    auto key=path_key(wide(path));
    std::unordered_set<std::wstring> previous;
    for(auto& member:members) {
        auto alias=aliases_.find(member);
        auto old=alias==aliases_.end()?member:alias->second;
        if(tasks.count(old)) previous.insert(old);
    }
    if(tasks.count(key)) previous.insert(key);
    // Keep the established card ID even when a newly arrived first volume
    // changes the descriptor's main path. Provisional request cards retire.
    for(auto& old:previous) if(!tasks.at(old).name.empty()) { key=old; break; }
    Task task;
    for(auto& old:previous) {
        auto& candidate=tasks.at(old);
        if(candidate.sequence>task.sequence) task=candidate;
    }
    for(auto& old:previous) erase_task(old);
    task.path=path;
    task.name=group.value("name",std::string());
    if(task.name.empty()) task.name=utf8(fs::path(wide(path)).filename().wstring());
    task.multipart=task.multipart || members.size()>1 || group.value("multipart",false);
    task.members=std::move(members);
    for(auto& member:task.members) aliases_[member]=key;
    tasks[key]=std::move(task); mark_changed(key);
}
void EventLog::accept(const Json& j) {
    if(!j.is_object() || !j.contains("event") || !j["event"].is_string()) return;
    auto event=j["event"].get<std::string>();
    if(event=="state_begin") {
        publication_.reset(); state_ready_=false; verified_=false;
        publication_revision_=0;
        for(auto& pair:tasks) mark_changed(pair.first);
        tasks.clear(); aliases_.clear();
        auto generation=j.value("generation",std::string());
        if(generation_!=generation) retried_revision_=0;
        generation_=std::move(generation);
        if(j.value("schema",0)==1) publication_=std::make_unique<Publication>(j,publication_changed_);
        return;
    }
    if(event=="state_ready") { state_ready_=!generation_.empty() && j.value("generation",std::string())==generation_; return; }
    if(event=="state_commit") { publication_revision_=j.value("revision",uint64_t(0)); return; }
    if(event=="pipeline_sources_claimed") {
        if(j.contains("groups") && j["groups"].is_array()) for(auto& group:j["groups"]) {
            accept_group(group);
            if(j.value("processing",false) && group.is_object()) accept(Json{{"event","processing_started"},
                {"path",group.value("path",std::string())},{"ts",j.value("ts",Json())},{"time",j.value("time",Json())}});
        }
        return;
    }
    if(!j.contains("path") || !j["path"].is_string()) return;
    auto path=j["path"].get<std::string>();
    if(path.empty()) return;
    auto physical=path_key(wide(path));
    auto alias=aliases_.find(physical);
    auto key=alias==aliases_.end()?physical:alias->second;
    if(event=="task_retired") { erase_task(key); return; }
    if(event=="blocker_cleared") {
        auto found=tasks.find(key);
        if(found!=tasks.end() && !terminal(found->second)) {
            found->second.status="taskWaiting"; found->second.waiting_reason="taskWaitingQueued"; mark_changed(key);
        }
        return;
    }
    if(event=="candidate_departed") {
        bool recursive=j.value("recursive",false);
        std::vector<std::wstring> affected;
        if(recursive) {
            for(auto& pair:tasks) if(!terminal(pair.second)) {
                if(pair.second.members.empty()) {
                    if(is_under(pair.first,physical)) affected.push_back(pair.first);
                } else for(auto& member:pair.second.members) if(is_under(member,physical)) {
                    affected.push_back(pair.first); break;
                }
            }
        } else if(tasks.count(key) && !terminal(tasks.at(key))) affected.push_back(key);
        for(auto& id:affected) {
            auto& task=tasks.at(id);
            for(auto it=task.members.begin();it!=task.members.end();) {
                if(recursive?is_under(*it,physical):*it==physical) {
                    aliases_.erase(*it); it=task.members.erase(it);
                } else ++it;
            }
            if(task.members.empty()) erase_task(id);
            else {
                if(!task.status.empty()) { task.status="taskWaiting"; task.waiting_reason="taskWaitingVolumes"; }
                mark_changed(id);
            }
        }
        return;
    }
    if(event=="no_tasks_found" || event=="pipeline_request_coalesced") {
        auto it=tasks.find(key);
        // A sibling request ending says nothing about its confirmed owner's
        // outcome. Never erase the shared card (or completed history).
        if(it!=tasks.end() && !terminal(it->second) &&
            (it->second.name.empty() || (event=="no_tasks_found" && (it->second.members.size()==1 || j.value("retire_group",false))))) erase_task(key);
        return;
    }
    std::string status, reason;
    if(event=="processing_started") status="taskProcessing";
    else if(event=="task_queued") { status="taskWaiting"; reason="taskWaitingQueued"; }
    else if(event=="failed_password" || event=="suspended_missing_volume") {
        status="taskWaiting"; reason=event=="failed_password"?"taskWaitingPassword":"taskWaitingVolumes";
    } else if(event=="done") status="taskSucceeded";
    else if(event=="failed_terminal" || event=="partial_rejected") status="taskFailed";
    else return;
    std::vector<std::string> outputs;
    double timestamp=0;
    bool has_timestamp=false;
    if(j.contains("output_dirs") && j["output_dirs"].is_array())
        for(auto& output:j["output_dirs"]) if(output.is_string() && !output.get_ref<const std::string&>().empty()) outputs.push_back(output.get<std::string>());
    if(j.contains("ts") && j["ts"].is_number()) { timestamp=j["ts"].get<double>(); has_timestamp=std::isfinite(timestamp); if(!has_timestamp) timestamp=0; }
    else if(j.contains("time") && j["time"].is_string()) {
        if(auto parsed=iso_timestamp(j["time"].get<std::string>())) { timestamp=*parsed; has_timestamp=true; }
    }
    auto& task=tasks[key];
    const auto& next_path=task.name.empty()?path:task.path;
    if(task.path==next_path && task.status==status && task.waiting_reason==reason &&
       task.outputs==outputs && task.timestamp==timestamp && task.has_timestamp==has_timestamp) return;
    task.path=next_path;
    task.status=std::move(status); task.waiting_reason=std::move(reason);
    task.outputs=std::move(outputs); task.timestamp=timestamp; task.has_timestamp=has_timestamp;
    mark_changed(key); task.sequence=sequence_;
}
bool EventLog::refresh(bool missing_is_final) {
    try {
    const bool was_verified=verified_;
    retry_required=false; changed_keys.clear(); rebuilt=false;
    Handle f(CreateFileW(path_.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
    if(f.value==INVALID_HANDLE_VALUE) {
        if(GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND) {
            if(!missing_is_final) { SetLastError(ERROR_FILE_NOT_FOUND); win_error("opReadEventLog"); }
            bool changed=!tasks.empty(); rebuilt=changed; offset_=identity_=volume_=0; prefix_.clear(); anchor_.clear(); pending_.clear(); tasks.clear(); aliases_.clear(); malformed=0;
            publication_.reset(); generation_.clear(); publication_revision_=0; state_ready_=verified_=false; return changed;
        }
        win_error("opReadEventLog");
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(f,&info)) win_error("opLogIdentity");
    uint64_t id=(uint64_t(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
    uint64_t size=(uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    bool reset=id!=identity_ || info.dwVolumeSerialNumber!=volume_ || size<offset_;
    if(!reset && !prefix_.empty()) reset=text_at(f,0,prefix_.size())!=prefix_;
    if(!reset && !anchor_.empty()) reset=text_at(f,offset_-anchor_.size(),anchor_.size())!=anchor_;
    bool changed=reset; rebuilt=reset;
    if(reset) { offset_=sequence_=0; prefix_.clear(); anchor_.clear(); pending_.clear(); tasks.clear(); aliases_.clear(); malformed=0;
        publication_.reset(); generation_.clear(); publication_revision_=0; state_ready_=false; }
    identity_=id; volume_=info.dwVolumeSerialNumber;
    // Parse bounded chunks, retaining only the unfinished record and logical task projections.
    while(offset_<size) {
        auto chunk=text_at(f,offset_,size_t(std::min<uint64_t>(65536,size-offset_)));
        if(chunk.empty()) break;
        // Retain anchors from the bytes actually parsed, not a later file
        // read which could already belong to a concurrent rewrite.
        if(!offset_) {
            prefix_=chunk.substr(0,4096);
            auto line=prefix_.find('\n'); if(line!=std::string::npos) prefix_.resize(line+1);
        }
        if(chunk.size()>=256) anchor_=chunk.substr(chunk.size()-256);
        else { anchor_+=chunk; if(anchor_.size()>256) anchor_.erase(0,anchor_.size()-256); }
        offset_+=chunk.size(); bytes_parsed+=chunk.size(); pending_+=chunk;
        size_t start=0, end;
        while((end=pending_.find('\n',start))!=std::string::npos) {
            try { auto event=parse_json(pending_.substr(start,end-start)); auto old=sequence_; accept(event); changed|=sequence_!=old; }
            catch(const std::exception&) { ++malformed; changed=true; }
            start=end+1;
        }
        pending_.erase(0,start);
        if(pending_.size()>16*1024*1024) throw std::runtime_error("logRecordTooLarge");
    }
    BY_HANDLE_FILE_INFORMATION after{};
    if(!GetFileInformationByHandle(f,&after)) win_error("opLogGeneration");
    if(after.nFileSizeHigh!=info.nFileSizeHigh || after.nFileSizeLow!=info.nFileSizeLow ||
        CompareFileTime(&after.ftLastWriteTime,&info.ftLastWriteTime)!=0) {
        const auto after_size=(uint64_t(after.nFileSizeHigh)<<32)|after.nFileSizeLow;
        // A growing log with unchanged parsed anchors can resume at offset_;
        // forcing a rebuild here replays the entire history during streams.
        // Same-size writes, truncations and changed anchors still rebuild.
        const bool appended=after_size>size &&
            (prefix_.empty() || text_at(f,0,prefix_.size())==prefix_) &&
            (anchor_.empty() || text_at(f,offset_-anchor_.size(),anchor_.size())==anchor_);
        if(!appended) identity_=0;
        retry_required=true;
    }
    verified_=state_ready_ && publication_ && publication_->matches(publication_revision_) && pending_.empty() && malformed==0 && !retry_required;
    const auto published=publication_?publication_->current_revision():0;
    // A reader can have opened the old file just before atomic replacement.
    // Retry that revision once. A persistently truncated/corrupt log must stay
    // unverified and wait for an actual publication/file event, never spin.
    if(state_ready_ && published && published!=publication_revision_ && published!=retried_revision_) {
        retried_revision_=published; retry_required=true;
    }
    if(verified_!=was_verified) { changed=true; for(auto& pair:tasks) mark_changed(pair.first); }
    return changed;
    } catch(...) { unverify(); throw; }
}
namespace {
// Both snapshot and incremental updates project a task identically.
Json project_task(const std::wstring& key,const Task& t,const RootIndex& roots,
    const std::string& language,std::unordered_map<std::string,std::string>& translated_statuses,bool verified) {
    auto& cache=t.display;
    if(cache.path!=t.path) {
        const fs::path path=wide(t.path);
        cache.directory=utf8(path.parent_path().wstring());
        cache.filename=utf8(path.filename().wstring());
        cache.path=t.path;
    }
    if(!cache.time_valid || cache.timestamp!=t.timestamp || cache.has_timestamp!=t.has_timestamp) {
        cache.time=task_time(t);
        cache.timestamp=t.timestamp;
        cache.has_timestamp=t.has_timestamp;
        cache.time_valid=true;
    }
    const auto status=verified?t.status:std::string("taskUnverified");
    const char* tone=status=="taskSucceeded"?"success":status=="taskFailed"?"failure":
        status=="taskWaiting"?"waiting":"info";
    const auto label=verified?(t.waiting_reason.empty()?t.status:t.waiting_reason):std::string("taskUnverified");
    auto found=translated_statuses.find(label);
    if(found==translated_statuses.end()) found=translated_statuses.emplace(label,tr(label,language)).first;
    return {{"id",utf8(key)},{"name",t.name.empty()?cache.filename:t.name},{"directory",cache.directory},
        {"path",t.path},{"root",indexed_root(key,roots)},{"status",status},{"statusText",found->second},{"partCount",t.multipart?t.members.size():0},{"time",cache.time},
        {"statusTone",tone},{"outputs",verified?t.outputs:std::vector<std::string>{}},{"sortTimestamp",t.timestamp},{"sortSequence",t.sequence}};
}
bool task_matches(const Task& t,const std::wstring& key,const RootIndex& roots,const View& v,
    const std::wstring& folded_query,bool verified) {
    if(t.status.empty() || (!v.task_status.empty() && (verified?t.status:std::string("taskUnverified"))!=v.task_status) ||
        (!v.task_root.empty() && indexed_root(key,roots)!=v.task_root)) return false;
    if(contains_folded(t.path,folded_query) || contains_folded(t.name,folded_query)) return true;
    return std::any_of(t.members.begin(),t.members.end(),[&](const auto& member){return contains_folded(utf8(member),folded_query);});
}
}
Json task_rows(const EventLog& log,const WatchRoots& roots,const View& v,const std::string& language,
    std::vector<std::wstring>* selected_ids,const std::vector<std::wstring>* previous_ids,
    TaskProjectionStats* stats) {
    using Clock=std::chrono::steady_clock;
    const auto started=stats?Clock::now():Clock::time_point{};
    const auto root_index=index_roots(roots);
    const auto query=fold_search(v.task_query);
    using TaskEntry=decltype(log.tasks)::value_type;
    std::vector<const TaskEntry*> rows;
    rows.reserve(log.tasks.size());
    for(auto& pair:log.tasks) if(task_matches(pair.second,pair.first,root_index,v,query,log.verified())) rows.push_back(&pair);
    const auto filtered=stats?Clock::now():Clock::time_point{};
    std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){
        if(a->second.timestamp!=b->second.timestamp) return a->second.timestamp>b->second.timestamp;
        return a->second.sequence>b->second.sequence;
    });
    const auto sorted=stats?Clock::now():Clock::time_point{};
    if(selected_ids) {
        selected_ids->clear();
        selected_ids->reserve(rows.size());
        for(const auto* task:rows) selected_ids->push_back(task->first);
    }
    const bool unchanged=previous_ids && selected_ids && *selected_ids==*previous_ids;
    Json result;
    if(!unchanged) {
        result={{"rows",Json::array()},{"total",rows.size()},{"malformed",log.malformed}};
        auto& projected=result["rows"];
        std::unordered_map<std::string,std::string> labels;
        for(auto* task:rows) projected.push_back(project_task(task->first,task->second,root_index,language,labels,log.verified()));
    }
    if(stats) {
        const auto finished=Clock::now();
        auto millis=[](Clock::duration d){return std::chrono::duration<double,std::milli>(d).count();};
        stats->filter_ms=millis(filtered-started);
        stats->sort_ms=millis(sorted-filtered);
        stats->project_ms=millis(finished-sorted);
        stats->selected=rows.size();
        stats->reused=unchanged;
    }
    return result;
}
Json task_delta(const EventLog& log,const WatchRoots& roots,const View& v,const std::string& language) {
    const auto root_index=index_roots(roots);
    const auto query=fold_search(v.task_query);
    std::unordered_map<std::string,std::string> labels;
    Json changes=Json::array();
    for(const auto& key:log.changed_keys) {
        Json change={{"id",utf8(key)}};
        auto it=log.tasks.find(key);
        if(it!=log.tasks.end() && task_matches(it->second,key,root_index,v,query,log.verified()))
            change["row"]=project_task(key,it->second,root_index,language,labels,log.verified());
        changes.push_back(std::move(change));
    }
    return {{"changes",std::move(changes)},{"malformed",log.malformed}};
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
Json password_rows(const Json& passwords,const View& v,const std::string& language) {
    Json rows=Json::array();
    if(v.password_scope=="@history") {
        for(auto& p:passwords.value("clipboard_history",Json::array())) if(contains(p.get<std::string>(),v.password_query))
            rows.push_back({{"id",std::to_string(rows.size())},{"value",p},{"original",""}});
    } else {
        const auto selected=v.password_scope=="@all"?std::wstring():scope_key(wide(v.password_scope));
        for(auto& p:passwords.value("passwords",Json::array())) {
            if(!password_matches_scope_key(p,selected)) continue;
            if(!contains(p["value"].get<std::string>(),v.password_query)) continue;
            rows.push_back({{"id",p.dump()+"#"+std::to_string(rows.size())},{"value",p["value"]},{"original",p.dump()}});
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
        if(item.is_array() && !item.empty() && std::all_of(item.begin(),item.end(),[](const Json& i){return i.is_object();})) {
            for(size_t i=0;i<item.size();++i) walk(item[i],pointer+"/"+std::to_string(i),module); return;
        }
        std::string type=item.is_boolean()?"boolean":item.is_string()?"string":item.is_number()?"number":item.is_array()?"array":item.is_object()?"object":"null";
        auto raw=tokens?tokens->token(pointer):item.dump(2);
        auto field=describe_setting(pointer,module,language);
        std::string editor=field["editor"], text=item.is_string()?item.get<std::string>():raw;
        bool lines=item.is_array() && std::all_of(item.begin(),item.end(),[](const Json& i){return i.is_string();});
        if(editor.empty()) editor=lines?"list":!field["known"].get<bool>()?"readonly":!field["options"].empty()?"choice":type=="boolean"?"toggle":type=="string"||type=="number"?"text":"readonly";
        int choice=-1;
        for(size_t i=0;i<field["options"].size();++i) if(field["options"][i]["value"]==item) choice=int(i);
        if(editor=="recursive" && choice<0) choice=2;
        field.update(Json{{"id",pointer},{"key",pointer+"@"+language},{"type",type},{"original",raw},{"text",text},{"boolean",item.is_boolean()?item.get<bool>():false},
            {"editor",editor},{"choice",choice},{"items",lines?item:Json::array()}});
        rows.push_back(std::move(field));
    };
    walk(config,"",""); return rows;
}
Json directory_rows(const WatchRoots& roots,const Json& config) {
    Json rows=Json::array();
    std::string default_out=".";
    if(config.contains("watch") && config["watch"].is_object() && config["watch"].contains("out_dir") && config["watch"]["out_dir"].is_string()) default_out=config["watch"]["out_dir"].get<std::string>();
    for(auto& r:roots.entries) {
        auto key=path_key(r.input);
        rows.push_back({{"id",utf8(key)},{"path",utf8(r.input.wstring())},{"name",utf8(r.input.filename().wstring())},
            {"watch",true},{"output",r.output},{"effectiveOutput",utf8(resolve_path(wide(r.output.empty()?default_out:r.output),r.input).wstring())},{"deep",r.deep},{"recursive",r.recursive}});
    }
    return rows;
}
fs::path log_directory(const fs::path& dir,const Json& config) {
    if(config.contains("watch") && config["watch"].is_object() && config["watch"].contains("state_dir") && config["watch"]["state_dir"].is_string()) {
        auto s=trim(config["watch"]["state_dir"].get<std::string>()); if(!s.empty()) return resolve_path(wide(s),dir);
    }
    return dir/".sunpack_watch";
}
}
