#include "model.hpp"
#include "presentation.hpp"
#include "defaults_json.h"
#include <cassert>
#include <fstream>
#include <iostream>

using namespace spg;
void service_notifications();
namespace {
void fails(const std::function<void()>& action) { bool failed=false; try { action(); } catch(const std::exception&) { failed=true; } assert(failed); }
struct Fixture {
    fs::path dir;
    Fixture() { GUID id{}; CoCreateGuid(&id); wchar_t token[40]; StringFromGUID2(id,token,40); dir=fs::temp_directory_path()/token; fs::create_directory(dir); }
    ~Fixture() { std::error_code ec; fs::remove_all(dir,ec); }
};
void overwrite(const fs::path& p,const std::string& text,bool append=false) {
    std::ofstream out(p,std::ios::binary|(append?std::ios::app:std::ios::trunc)); out<<text;
}
std::string event(const std::string& type,const fs::path& p,int ts) {
    return Json({{"event",type},{"path",utf8(p.wstring())},{"ts",ts}}).dump()+"\n";
}
// These coarse scenarios cover independent contracts: projection/reset, coordinated edits,
// Windows identity/root policy. No benchmark assertions or implementation-mirroring tests.
void projection(Fixture& f) {
    auto p=f.dir/"events.jsonl", source=f.dir/L"伪装.bin.001";
    EventLog log; log.set_path(p);
    overwrite(p,event("candidate_active",source,1)+event("processing_started",source,2)+event("done",source,3)+event("cleanup",source,4));
    assert(log.refresh()); assert(log.tasks.size()==1);
    auto& task=log.tasks.begin()->second;
    assert(task.status=="taskSucceeded"); // Cleanup never replaces the task's terminal state.
    auto parsed=log.bytes_parsed; assert(!log.refresh()); assert(log.bytes_parsed==parsed);
    for(auto type:{"failed_terminal","failed_password","suspended_missing_volume","done","partial_rejected"}) {
        auto line=event(type,source,5); overwrite(p,line.substr(0,line.size()-2),true); log.refresh();
        auto sequence=log.tasks.begin()->second.sequence;
        overwrite(p,line.substr(line.size()-2),true); log.refresh();
        assert(log.tasks.begin()->second.sequence>sequence);
        assert(!log.tasks.begin()->second.status.empty());
    }
    auto reset_source=f.dir/L"载体.fake";
    std::string replacement=event("processing_started",reset_source,50);
    for(int i=0;i<120;++i) replacement+=Json({{"event","scheduler_tick"},{"padding",std::string(80,'x')}}).dump()+"\n";
    overwrite(p,replacement); log.refresh();
    assert(log.tasks.size()==1 && log.tasks.begin()->second.path==utf8(reset_source.wstring()));
    // Same first record and file ID, truncate/regrow past old offset: tail anchor detects it.
    auto first=event("processing_started",reset_source,50);
    replacement=first+event("done",source,51)+std::string(replacement.size()+40,' ')+"\n";
    overwrite(p,replacement); log.refresh(); assert(log.tasks.size()==2);
    overwrite(p,"{invalid}\n"+event("failed_password",reset_source,52)); log.refresh();
    assert(log.malformed==1 && log.tasks.size()==1);
    fs::remove(p); fails([&]{log.refresh();}); assert(!log.tasks.empty()); log.refresh(true); assert(log.tasks.empty());
    // Equivalent ISO offsets and numeric epochs must display the same local
    // wall time. TZ is process-only.
    char* previous=nullptr; size_t count=0; _dupenv_s(&previous,&count,"TZ");
    std::string old_zone=previous?previous:""; std::free(previous);
    _putenv_s("TZ","UTC-8"); _tzset();
    for(auto value:{"2026-10-19T09:15:42.731112+00:00","2026-10-19T17:15:42.731112+08:00","2026-10-19T04:15:42-05:00","2026-10-19T09:15:42Z"}) {
        log.accept(Json{{"event","done"},{"path",utf8(source.wstring())},{"time",value}});
        auto row=task_rows(log,{},{}).at("rows").at(0);
        assert(row["time"]=="2026-10-19 17:15:42");
        assert(!row.contains("details"));
        auto stamp=log.tasks.begin()->second.timestamp;
        log.accept(Json{{"event","done"},{"path",utf8(source.wstring())},{"ts",stamp}});
        assert(task_rows(log,{},{}).at("rows").at(0).at("time")==row["time"]);
    }
    for(auto value:{"","invalid"}) {
        log.accept(Json{{"event","done"},{"path",utf8(source.wstring())},{"time",value}});
        assert(task_rows(log,{},{}).at("rows").at(0).at("time")=="");
    }
    log.accept(Json{{"event","done"},{"path",utf8(source.wstring())},{"ts",0}});
    assert(task_rows(log,{},{}).at("rows").at(0).at("time")=="1970-01-01 08:00:00");
    _putenv_s("TZ",old_zone.c_str()); _tzset();

    // Resolve navigation from the same projected row at activation, including
    // deleted input archives and outputs moved after the page was displayed.
    auto monitor=f.dir/L"监控", nested=monitor/L"子目录", output=f.dir/L"输出";
    fs::create_directories(nested); fs::create_directory(output);
    auto file=nested/L"已删除的载体.001";
    WatchRoots roots; roots.entries={{f.dir,"",false},{monitor,"",false}};
    log.tasks.clear();
    log.accept(Json{{"event","done"},{"path",utf8(file.wstring())},{"output_dirs",{utf8((f.dir/L"missing").wstring()),utf8(output.wstring())}}});
    auto row=task_rows(log,roots,{}).at("rows").at(0);
    assert(row["root"]==utf8(monitor.wstring()));
    assert(row["directory"]==utf8(nested.wstring()));
    assert(task_directory(row)==output);
    fs::remove(output);
    assert(task_directory(row)==monitor);
    auto old_root=task_rows(log,{},{}).at("rows").at(0);
    assert(old_root["directory"]==row["directory"]);
    assert(task_directory(old_root)==nested);
    log.accept(Json{{"event","failed_password"},{"path",utf8(file.wstring())}});
    assert(task_directory(task_rows(log,roots,{}).at("rows").at(0))==monitor);
    fs::remove(nested); fs::remove(monitor);
    fails([&]{task_directory(row);});
}
// One real JSONL replay covers logical ownership, removal and delta delivery.
// The original projection scenario cannot expose cross-path aliasing failures;
// without this scenario duplicate/stale cards can pass all scalar status checks.
void logical_projection(Fixture& f) {
    EventLog log; auto file=f.dir/"logical.jsonl"; log.set_path(file);
    auto a=utf8((f.dir/"parts"/"disguised.a").wstring());
    auto b=utf8((f.dir/"parts"/"unrelated.bin").wstring());
    auto c=utf8((f.dir/"parts"/"third.blob").wstring());
    auto other=utf8((f.dir/"parts-extra"/"unrelated.bin").wstring());
    std::unordered_map<std::string,Json> displayed;
    int ts=0;
    auto replay=[&](Json record) {
        record["ts"]=++ts;
        overwrite(file,record.dump()+"\n",true); log.refresh();
        if(log.rebuilt || log.changed_overflow) {
            displayed.clear();
            auto snapshot=task_rows(log,{},{});
            for(auto& row:snapshot["rows"]) displayed[row["id"]]=row;
        } else { auto delta=task_delta(log,{},{}); for(auto& change:delta["changes"]) {
            auto id=change["id"].get<std::string>();
            if(change.contains("row")) displayed[id]=change["row"]; else displayed.erase(id);
        }}
        auto snapshot=task_rows(log,{},{});
        assert(displayed.size()==snapshot["total"].get<size_t>());
        for(auto& row:snapshot["rows"]) assert(displayed.at(row["id"].get<std::string>())==row);
    };
    auto send=[&](const char* type,const std::string& path) { replay(Json{{"event",type},{"path",path}}); };
    auto group=[&](const std::string& path,const std::vector<std::string>& members) {
        replay(Json{{"event","pipeline_sources_claimed"},{"path",path},
            {"groups",Json::array({Json{{"path",path},{"name","movie.rar"},{"members",members}}})}});
    };
    auto row=[&]() { return task_rows(log,{},{}).at("rows").at(0); };
    // Unrecognized and preparation events do not create visible work.
    overwrite(file,event("candidate_active",wide(a),0)); log.refresh();
    assert(task_rows(log,{},{}).at("total")==0);
    send("processing_started",b); group(b,{b}); send("suspended_missing_volume",b);
    auto id=row()["id"];
    assert(row()["status"]=="taskWaiting" && row()["statusText"]=="等待分卷");
    send("processing_started",a);
    group(a,{a,b,c}); // Main path changes; the existing logical card survives.
    assert(displayed.size()==1 && row()["id"]==id && row()["name"]=="movie.rar");
    assert(row()["partCount"]==3 && row()["status"]=="taskProcessing");
    View member_search; member_search.task_query="unrelated.bin";
    assert(task_rows(log,{},member_search).at("total")==1);
    send("suspended_missing_volume",a);
    send("retry_password_failure",b); // No change to the waiting reason.
    assert(row()["statusText"]=="等待分卷");
    send("pipeline_request_coalesced",a);
    assert(displayed.size()==1);
    replay(Json{{"event","candidate_departed"},{"path",b},{"forgotten",false}});
    assert(row()["partCount"]==2 && row()["statusText"]=="等待分卷");
    send("processing_started",c); send("failed_password",a);
    View waiting; waiting.task_status="taskWaiting";
    assert(task_rows(log,{},waiting).at("total")==1);
    assert(task_rows(log,{},waiting,"en").at("rows").at(0).at("statusText")=="Waiting for password");
    // Recursive deletion has a path boundary and ignores persistent-state flags.
    send("failed_password",other);
    replay(Json{{"event","candidate_departed"},{"path",utf8((f.dir/"parts").wstring())},{"recursive",true},{"forgotten",false}});
    assert(displayed.size()==1 && row()["path"]==other);
    send("candidate_departed",other); assert(displayed.empty());
    send("processing_started",a); send("no_tasks_found",a); assert(displayed.empty());
    send("processing_started",b); send("pipeline_request_coalesced",b); assert(displayed.empty());
    // Two tasks in one claim must stay independent, including nested inputs.
    replay(Json{{"event","pipeline_sources_claimed"},{"path",a},{"groups",Json::array({
        Json{{"path",a},{"name","movie.rar"},{"members",{a,b}}},
        Json{{"path",other},{"name","inner.zip"},{"members",{other}}}})}});
    assert(displayed.empty());
    send("processing_started",a); send("failed_password",other);
    assert(displayed.size()==2);
    send("done",b); send("pipeline_request_coalesced",a); send("no_tasks_found",b);
    send("candidate_departed",a); send("candidate_departed",b);
    assert(displayed.size()==2); // Terminal history remains and aliases retain the result.
    send("candidate_departed",other); assert(displayed.size()==1 && row()["status"]=="taskSucceeded");
    // Reset must release aliases as well as visible history.
    overwrite(file,event("processing_started",wide(b),100)); assert(log.refresh() && log.rebuilt);
    assert(row()["name"]=="unrelated.bin" && row()["partCount"]==0);
}
void editing(Fixture& f) {
    auto p=f.dir/"builtin_passwords.json";
    Json original={{"value","  #中文 密码  "},{"scopes",{"C:/A","D:/B"}}};
    atomic_write(p,Json({{"passwords",{original}},{"clipboard_history",{"后台密码"}}}).dump());
    edit_password(p,"removeScope",original,Json(),"c:\\a");
    auto j=read_json(p); assert(j["passwords"][0]["scopes"]==Json::array({"D:/B"}));
    assert(j["clipboard_history"][0]=="后台密码");
    edit_password(p,"removeScope",j["passwords"][0],Json(),"d:\\b");
    assert(read_json(p)["passwords"].empty());
    edit_password(p,"add",Json(),Json({{"value"," p # "}})); assert(read_json(p)["passwords"][0]["value"]==" p # ");
    fails([&]{edit_password(p,"replace",original,Json({{"value","wrong record"}}));});
    for(auto raw:{"{\"passwords\":[{\"value\":\"a\",\"scopes\":[]}]}","{\"passwords\":[],\"unknown\":1}","{\"passwords\":[{\"value\":\"a\",\"unknown\":1}]}","{\"passwords\":[],\"passwords\":[]}"})
        fails([&]{validate_passwords(parse_json(raw));});
    validate_passwords(parse_json(R"({"passwords":[{"value":"#","scopes":["\\\\server\\share","C:/中文"]}],"clipboard_history":[]})"));
    // Coordinate with a second writer using the exact production lock.
    std::thread writer([&]{ FileMutex lock(p); auto current=read_json(p); current["clipboard_history"].push_back("latest"); atomic_write(p,current.dump()); }); writer.join();
    edit_password(p,"add",Json(),Json({{"value","after history"}})); assert(read_json(p)["clipboard_history"].back()=="latest");
    auto before=read_file(p);
    fails([&]{edit_password(p,"addMany",Json(),Json::array({Json{{"value","valid"}},Json{{"value","invalid"},{"scopes",Json::array()}}}));});
    assert(read_file(p)==before); // A bad record cannot commit a partial batch.
    edit_password(p,"addMany",Json(),Json::array({Json{{"value"," # batch "}},Json{{"value"," # batch "}},Json{{"value","other"}}}));
    assert(read_json(p)["passwords"].size()==4 && read_json(p)["clipboard_history"].back()=="latest");
    auto c=f.dir/"sunpack_config.json";
    atomic_write(c,R"({"watch":{"out_dir":"."},"unknown":{"large":9007199254740993,"huge":123456789012345678901234567890},"filters":[{"name":"x","rules":["*","r",3]}]})");
    save_config_field(c,"/watch/out_dir","\".\"","string","中文",false);
    auto conf=read_json(c); assert(conf["unknown"]["large"].dump()=="9007199254740993");
    assert(read_file(c).find("123456789012345678901234567890")!=std::string::npos);
    auto fields=config_fields(conf,read_file(c));
    auto huge=std::find_if(fields.begin(),fields.end(),[](const Json& field){return field["id"]=="/unknown/huge";});
    assert((*huge)["text"]=="123456789012345678901234567890");
    assert(conf["filters"][0]["rules"]==Json::array({"*","r",3}));
    fails([&]{save_config_field(c,"/watch/out_dir","\".\"","string","stale",false);});
    fails([&]{validate_setting("/runtime/process_mode",Json("typo"));});
    fails([&]{validate_setting("/watch/max_folders",Json(0));});
    fails([&]{validate_setting("/embedded_scan/recursive_candidate_ratio",Json(1.5));});
    validate_setting("/recursive_extract",Json("12"));
    fails([&]{validate_setting("/recursive_extract",Json("0"));});
    // One coarse catalog contract covers every shipped setting, including
    // fields nested in filter/module arrays, in both CLI-supported languages.
    for(auto language:{"zh","en"}) {
        auto defaults=parse_json(kDefaultsJson);
        for(auto& field:config_fields(defaults,kDefaultsJson,language)) {
            if(!field["known"].get<bool>()) throw std::runtime_error("Missing setting description: "+field["id"].get<std::string>());
            assert(!field["label"].get<std::string>().empty() && !field["description"].get<std::string>().empty());
        }
        assert(!describe_setting("/retired/enabled","",language)["known"].get<bool>());
        assert(!describe_setting("/watch/directory_password_file_auto_create","",language)["known"].get<bool>());
        assert(!describe_setting("/passwords/directory_passwords_enabled","",language)["known"].get<bool>());
        // Module identity, rather than position, survives copying/reordering.
        auto module=config_fields(parse_json(R"({"analysis":{"modules":[{"name":"gzip","max_probe_bytes":2048}]}})"),"",language);
        assert(module.size()==1 && module[0]["known"].get<bool>() && module[0]["module"]=="gzip" && module[0]["blockLabel"]=="GZIP");
    }
    assert(log_directory(f.dir,Json({{"watch",{{"state_dir","other"}}}}))==f.dir/"other");
}
// Existing file/edit tests only check rejection. This coarse scenario catches
// leaked message keys, frozen locales and lost Windows codes across the same
// exception/string boundary used by background saves, without extra processes.
void localization(Fixture& fixture) {
    auto rejected=[&](const std::function<void()>& action,const char* expected) {
        try { action(); assert(false); }
        catch(const std::exception& error) {
            assert(std::string(error.what())==expected);
            auto zh=translated_error(error.what(),"zh"), en=translated_error(error.what(),"en");
            assert(zh==tr(expected,"zh") && en==tr(expected,"en") && zh!=en && en!=expected);
        }
    };
    rejected([]{parse_json(R"({"a":1,"a":2})");},"jsonDuplicateKey");
    rejected([]{validate_passwords(Json::object());},"passwordArrayRequired");
    rejected([]{parse_roots("C:/input | out | maybe",{});},"deepDetectInvalid");
    try { parse_json("{invalid}"); assert(false); }
    catch(const std::exception& error) {
        assert(translated_error(error.what(),"en").find("Invalid JSON near byte ")==0);
        assert(translated_error(error.what(),"zh").find("JSON 格式无效")==0);
    }
    try { read_file(fixture.dir/"missing-file"); assert(false); }
    catch(const WinError& error) {
        assert(error.code==ERROR_FILE_NOT_FOUND);
        auto en=translated_error(error.what(),"en"), zh=translated_error(error.what(),"zh");
        assert(en.find("Read file failed (Windows error 2): ")==0 && en.find("opReadFile")==std::string::npos);
        assert(zh.find("读取文件失败（Windows 错误 2）")==0 && en!=zh);
        auto startup=error_text("startupFailure",{{"stage",{{"source","stageLayout"}}},{"detail",{{"source",error.what()}}}});
        assert(translated_error(startup,"en").find("Startup failed (Load layout): Read file failed")==0);
    }
    auto literal=error_text("cliFailureOutput",{{"failure",{{"source","pathMissing"}}},{"output","taskFailed {code}"}});
    assert(translated_error(literal,"en")=="The path does not currently exist.\ntaskFailed {code}");
    auto data=fixture.dir/"locale"; fs::create_directory(data);
    assert(startup_language(data)=="en");
    atomic_write(data/"sunpack_config.json",R"({"cli":{"language":"zh"}})");
    assert(startup_language(data)=="zh");
    atomic_write(data/"sunpack_config.json","{"); assert(startup_language(data)=="en");
}
void installer_upgrade(Fixture& fixture) {
    auto path=fixture.dir/"upgrade.json";
    const std::string keep=R"("advanced":{"integer":123456789012345678901234567890,"text":"directory_password_file_auto_create"})";
    const std::vector<std::string> inputs={
        R"({"watch":{"directory_password_file_auto_create":true,"password_retry_include_subtree":false}})",
        R"({"passwords":{"directory_passwords_enabled":true,"directory_passwords_max_file_bytes":1048576,"directory_passwords_max_password_length":512},"watch":{"directory_password_file_auto_create":false}})",
        "{\"watch\":{\"directory_password_file_auto_create\":true,\"quiet_max_seconds\":13,\"password_retry_include_subtree\":false},"+keep+"}",
        "{\"passwords\":{\"clipboard_passwords_enabled\":true,\"directory_passwords_enabled\":false,\"directory_passwords_max_file_bytes\":1,\"directory_passwords_max_password_length\":1},"+keep+"}"
    };
    for(auto& input:inputs) {
        atomic_write(path,input); upgrade_config_file(path);
        auto output=read_file(path); auto config=parse_json(output);
        assert(!config.contains(Json::json_pointer("/watch/directory_password_file_auto_create")));
        assert(!config.contains(Json::json_pointer("/watch/password_retry_include_subtree")));
        for(auto name:{"directory_passwords_enabled","directory_passwords_max_file_bytes","directory_passwords_max_password_length"})
            assert(!config.contains(Json::json_pointer(std::string("/passwords/")+name)));
        if(config.contains("advanced")) assert(output.find(keep)!=std::string::npos);
        if(config.contains("watch")) assert(config["watch"]["quiet_max_seconds"]==13);
        if(config.contains("passwords")) assert(config["passwords"]["clipboard_passwords_enabled"]==true);
        upgrade_config_file(path); assert(read_file(path)==output);
    }
    // Retained advanced values are not normalized or reformatted on upgrade.
    atomic_write(path,kDefaultsJson); upgrade_config_file(path); assert(read_file(path)==kDefaultsJson);
    atomic_write(path,"{invalid}"); fails([&]{upgrade_config_file(path);}); assert(read_file(path)=="{invalid}");
}
void roots(Fixture& f) {
    auto p=f.dir/"sunpack_watch_roots.txt";
    atomic_write(p,"# 保留注释\n"+utf8(f.dir.wstring())+" | relative | false\n"+utf8(f.dir.wstring())+" | 末条 | TRUE\n");
    auto roots=read_roots(p); assert(roots.entries.size()==1 && roots.entries[0].deep && roots.entries[0].output=="末条");
    auto nested=f.dir/"Data"; fs::create_directory(nested);
    edit_root(p,"save","",utf8(nested.wstring()),"",false);
    auto all=read_roots(p); assert(all.entries.size()==2);
    assert(root_for(nested/"x.bin",all)==utf8(nested.wstring()));
    assert(root_for(f.dir/"Data2"/"x.bin",all)==utf8(f.dir.wstring()));
    // The nearest path-component root wins even with hundreds of unrelated
    // roots; sibling prefixes must never match each other.
    WatchRoots prefix_roots;
    prefix_roots.entries={{f.dir,"",false},{nested,"",false},{f.dir/"Data2","",false}};
    assert(root_for(nested/"deep"/"part.zip",prefix_roots)==utf8(nested.wstring()));
    assert(root_for(f.dir/"Data2"/"part.zip",prefix_roots)==utf8((f.dir/"Data2").wstring()));
    assert(root_for(f.dir/"Data20"/"part.zip",prefix_roots)==utf8(f.dir.wstring()));
    assert(root_for(f.dir.parent_path()/"untracked.zip",prefix_roots)=="@other");
    fails([&]{edit_root(p,"save","",utf8(nested.wstring()),"",false);});
    edit_root(p,"delete",utf8(nested.wstring()),utf8(nested.wstring()),"",false);
    assert(read_file(p).find("# 保留注释")!=std::string::npos);
    assert(path_key(L"C:/İ/中文/../A")==path_key(L"c:\\İ\\a"));
    assert(path_key(L"C:/Data/")==path_key(L"c:\\data"));
    assert(!is_under(path_key(L"C:/Data2/a"),path_key(L"C:/Data")));
    View view;
    EventLog log;
    for(int i=0;i<501;++i) {
        all.entries.push_back({f.dir/std::to_wstring(i),"",false});
        log.accept(Json({{"event","done"},{"path",utf8((f.dir/std::to_wstring(i)/"file").wstring())},{"ts",i}}));
    }
    auto rows=task_rows(log,all,view); assert(rows["total"]==501 && rows["rows"].size()==501 && !rows.contains("pages"));
    assert(directory_rows(all,Json::object()).size()==503);
    log.changed_keys.clear();
    auto changed_path=utf8((f.dir/L"0"/L"file").wstring());
    log.accept(Json{{"event","failed_terminal"},{"path",changed_path},{"ts",99999}});
    auto delta=task_delta(log,all,view);
    auto latest=task_rows(log,all,view);
    assert(delta["changes"].size()==1 && latest["rows"][0]["status"]=="taskFailed");
    assert(delta["changes"][0]["row"]==latest["rows"][0]);
    view.task_status="taskSucceeded";
    auto removal=task_delta(log,all,view);
    assert(removal["changes"].size()==1 && !removal["changes"][0].contains("row"));
}
void batch_editing(Fixture& fixture) {
    auto dir=fixture.dir/"batch"; fs::create_directory(dir);
    auto config=dir/"sunpack_config.json", passwords=dir/"builtin_passwords.json", roots=dir/"sunpack_watch_roots.txt";
    atomic_write(config,R"({"watch":{"out_dir":".","toast_enabled":true,"max_folders":1},"large":123456789012345678901234567890})");
    Json old={{"value","old"},{"scopes",{utf8(dir.wstring())}}};
    atomic_write(passwords,Json{{"passwords",{old}},{"clipboard_history",{"latest background history"}}}.dump());
    atomic_write(roots,"# retained\n"+utf8(dir.wstring())+"\n");
    Json fields=Json::array({Json{{"pointer","/watch/out_dir"},{"original","\".\""},{"type","string"},{"text","output"},{"boolean",false}},
        Json{{"pointer","/watch/toast_enabled"},{"original","true"},{"type","boolean"},{"text",""},{"boolean",false}}});
    Json pwd=Json::array({Json{{"operation","replace"},{"original",old.dump()},{"value","changed"},{"scopes",{utf8(dir.wstring())}}}});
    Json root=Json::array({Json{{"operation","save"},{"original",utf8(dir.wstring())},{"input",utf8(dir.wstring())},{"output","new"},{"deep",true},{"expected",{{"output",""},{"deep",false}}}}});
    auto before_config=read_file(config), before_passwords=read_file(passwords), before_roots=read_file(roots);
    auto invalid=fields; invalid.push_back({{"pointer","/watch/max_folders"},{"original","1"},{"type","number"},{"text","0"},{"boolean",false}});
    auto rejected=save_changes(dir,invalid,pwd,root);
    assert(rejected["saved"].empty() && rejected["error"]!="");
    assert(read_file(config)==before_config && read_file(passwords)==before_passwords && read_file(roots)==before_roots);
    atomic_write(roots,utf8(dir.wstring())+" | external\n");
    rejected=save_changes(dir,fields,pwd,root); assert(rejected["saved"].empty() && rejected["error"]=="rootConflict");
    assert(read_file(config)==before_config && read_file(passwords)==before_passwords);
    atomic_write(roots,before_roots);
    {
        // Preflight can read this file, but Windows denies its replacement.
        Handle held(CreateFileW(roots.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
        assert(held.value!=INVALID_HANDLE_VALUE);
        auto partial=save_changes(dir,fields,pwd,root);
        assert(partial["saved"]==Json::array({"config","passwords"}) && partial["error"]!="");
        assert(read_file(roots)==before_roots);
    }
    auto retry=save_changes(dir,Json::array(),Json::array(),root);
    assert(retry["error"]=="" && retry["saved"]==Json::array({"roots"}));
    // Successful commits expose their already-validated on-disk snapshot.
    // A failed preflight must never report a committed snapshot.
    PasswordSaveSnapshot failed_snapshot;
    Json bad_password=Json::array({Json{{"operation","replace"},{"original","{\"value\":\"not found\"}"},{"value","bad"},{"scopes",Json::array()}}});
    auto rejected_password=save_changes(dir,Json::array(),bad_password,Json::array(),&failed_snapshot);
    assert(rejected_password["saved"].empty() && failed_snapshot.document.is_null());
    PasswordSaveSnapshot snapshot;
    Json updated_password=Json::array({Json{{"operation","replace"},
        {"original",Json{{"value","changed"},{"scopes",{utf8(dir.wstring())}}}.dump()},
        {"value","fast-delta"},{"scopes",{utf8(dir.wstring())}}}});
    auto committed=save_changes(dir,Json::array(),updated_password,Json::array(),&snapshot);
    assert(committed["error"]=="" && committed["saved"]==Json::array({"passwords"}));
    assert(snapshot.document==read_json(passwords) && snapshot.file_text==read_file(passwords));
    assert(snapshot.document["passwords"][0]["value"]=="fast-delta");
    assert(read_file(config).find("123456789012345678901234567890")!=std::string::npos);
    assert(read_json(config)["watch"]["toast_enabled"]==false);
    assert(read_json(passwords)["passwords"][0]["value"]=="fast-delta");
    assert(read_json(passwords)["clipboard_history"][0]=="latest background history");
    assert(read_roots(roots).entries[0].deep && read_file(roots).find("# retained")!=std::string::npos);
    // Batch folder additions preflight together and ignore identical duplicates.
    auto first=dir/"first", second=dir/"second"; fs::create_directory(first); fs::create_directory(second);
    Json batch=Json::array({Json{{"operation","addMany"},{"inputs",{utf8(first.wstring()),utf8((dir/"missing").wstring())}},{"output",""},{"deep",true}}});
    auto before=read_file(roots);
    auto bad=save_changes(dir,Json::array(),Json::array(),batch);
    assert(!bad["error"].get<std::string>().empty() && read_file(roots)==before);
    batch[0]["inputs"]=Json::array({utf8(first.wstring()),utf8(second.wstring()),utf8(first.wstring())});
    assert(save_changes(dir,Json::array(),Json::array(),batch)["error"]=="");
    assert(read_roots(roots).entries.size()==3 && read_roots(roots).entries.back().deep);
    View view;
    auto saved=read_json(passwords);
    saved["passwords"].push_back({{"value","everywhere"}});
    assert(password_rows(saved,view)["total"]==2);
    view.password_query=utf8(dir.wstring());
    auto matches=password_rows(saved,view); assert(matches["total"]==1 && matches["rows"][0]["scopes"]==utf8(dir.wstring()));
}
}
int wmain(int argc,wchar_t** argv) {
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(argc==3 && std::wstring(argv[1])==L"--mutex") { std::cout<<utf8(mutex_name(argv[2]))<<"\n"<<utf8(mutex_name(argv[2],L"SunPackWatchRoots"))<<"\n"; return 0; }
    if(argc>=2 && std::wstring(argv[1])==L"--echo") { Json args=Json::array(); for(int i=2;i<argc;++i) args.push_back(utf8(argv[i])); std::cout<<args.dump(); return 7; }
    if(argc==4 && std::wstring(argv[1])==L"--password-add") { edit_password(argv[2],"add",Json(),Json({{"value",utf8(argv[3])}})); return 0; }
    try { Fixture f; projection(f); logical_projection(f); editing(f); roots(f); localization(f); installer_upgrade(f); batch_editing(f); service_notifications(); std::cout<<"GUI file contracts passed\n"; }
    catch(const std::exception& e) { std::cerr<<e.what()<<"\n"; return 1; }
    CliCommand cli{executable_path(),fs::temp_directory_path(),{L"--echo"}};
    Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    auto output=run_cli(cli,{L"watch",L"start",L"中文 空格",L"quote\"tail\\"},stop);
    assert(output.code==7 && parse_json(output.output)==Json::array({"watch","start","中文 空格","quote\"tail\\"}));
    CoUninitialize(); return 0;
}
