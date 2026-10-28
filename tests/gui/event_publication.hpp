#pragma once
#include "model.hpp"
#include "lz4.h"
#include <fstream>
#include <array>
#include <cstring>

// Test-only publisher; the shipping GUI never writes display history.
inline void publish_events(const spg::fs::path& path,const std::string& events,const spg::Json& retained_runs=spg::Json::array()) {
    using namespace spg;
    EventLog projection;
    size_t at=0;
    while(at<events.size()) { auto end=events.find('\n',at); if(end==std::string::npos) end=events.size();
        if(end>at) projection.accept(Json::parse(events.substr(at,end-at))); at=end+1;
    }
    static uint64_t generation=0;
    auto name="fixture-"+std::to_string(++generation);
    auto folder=path.parent_path()/(path.filename().wstring()+L".store"); fs::create_directories(folder);
    std::vector<Json> rows;
    for(auto& [id,task]:projection.tasks) {
        std::string event=task.status=="taskSucceeded"?"done":task.status=="taskFailed"?"failed_terminal":
            task.status=="taskWaiting"?(task.waiting_reason=="taskWaitingPassword"?"failed_password":"suspended_missing_volume"):"processing_started";
        Json value={{"event",event},{"path",task.path},{"task_id",utf8(id)},{"ts",task.timestamp},
            {"error",task.error},{"error_kind",task.error_kind},{"output_dirs",task.outputs}};
        if(!task.name.empty()) {
            Json members=Json::array();
            for(auto& member:task.members) members.push_back(utf8((fs::path(member.key).parent_path()/wide(member.filename)).wstring()));
            value["group"]={{"path",task.path},{"name",task.name},{"members",members},{"multipart",task.multipart},{"task_id",utf8(id)}};
        }
        rows.push_back(std::move(value));
    }
    std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){return a["ts"]<b["ts"];});
    std::ofstream data(folder/(name+".data"),std::ios::binary), index(folder/(name+".index"),std::ios::binary);
    for(const auto& row:rows) {
        auto raw=Json::to_msgpack(row); std::vector<char> compressed(size_t(LZ4_compressBound(int(raw.size()))));
        auto size=LZ4_compress_default(reinterpret_cast<const char*>(raw.data()),compressed.data(),int(raw.size()),int(compressed.size()));
        std::array<char,64> entry{}; auto time=int64_t(row["ts"].get<double>()*1000000); auto offset=uint64_t(data.tellp());
        auto length=uint32_t(size), raw_size=uint32_t(raw.size()); uint32_t kind=1;
        auto event=row["event"].get<std::string>(); if(event=="done") kind=4; else if(event=="failed_terminal") kind=5;
        else if(event=="failed_password") kind=2; else if(event=="suspended_missing_volume") kind=3;
        memcpy(entry.data(),&time,8); memcpy(entry.data()+8,&offset,8); memcpy(entry.data()+16,&length,4);
        memcpy(entry.data()+20,&raw_size,4); memcpy(entry.data()+24,&kind,4); memset(entry.data()+32,255,32);
        data.write(compressed.data(),size); index.write(entry.data(),64);
    }
    data.close(); index.close();
    auto run=Json{{"name",name},{"head",0},{"count",rows.size()}};
    auto runs=retained_runs; runs.push_back(std::move(run));
    atomic_write(path,Json{{"format",1},{"revision",generation},{"task_revision",generation},{"runs",std::move(runs)},{"live",nullptr},{"dropped",0}}.dump());
}
