#pragma once
#include "model.hpp"
#include "lz4.h"
#include <fstream>
#include <array>
#include <cstring>

// Test-only publisher; the shipping GUI never writes display history.
inline void publish_events(const spg::fs::path& path,const std::string& events,const spg::Json& retained_runs=spg::Json::array(),bool live=false) {
    using namespace spg;
    std::unordered_map<std::string,Json> snapshots;
    size_t at=0;
    while(at<events.size()) {
        auto end=events.find('\n',at);
        if(end==std::string::npos) end=events.size();
        if(end>at) {
            auto row=Json::parse(events.substr(at,end-at));
            auto id=row.value("task_id",std::string());
            if(id.empty()) id=utf8(path_key(wide(row.at("path").get_ref<const std::string&>())));
            row["task_id"]=id;
            snapshots.insert_or_assign(std::move(id),std::move(row));
        }
        at=end+1;
    }
    static uint64_t generation=0;
    auto name="fixture-"+std::to_string(++generation);
    auto folder=path.parent_path()/(path.filename().wstring()+L".store"); fs::create_directories(folder);
    auto timestamp=[](const Json& row) {
        const auto at=row.find("ts");
        return at!=row.end() && at->is_number()?at->get<double>():0.0;
    };
    std::vector<Json> rows;
    for(auto& [id,row]:snapshots) rows.push_back(std::move(row));
    std::sort(rows.begin(),rows.end(),[&](const auto& a,const auto& b){return timestamp(a)<timestamp(b);});
    std::ofstream data(folder/(name+".data"),std::ios::binary), index(folder/(name+".index"),std::ios::binary);
    if(live) { std::array<char,64> header{}; memcpy(header.data(),&generation,8); index.write(header.data(),header.size()); }
    for(const auto& row:rows) {
        auto raw=Json::to_msgpack(row); std::vector<char> compressed(size_t(LZ4_compressBound(int(raw.size()))));
        auto size=LZ4_compress_default(reinterpret_cast<const char*>(raw.data()),compressed.data(),int(raw.size()),int(compressed.size()));
        std::array<char,64> entry{}; auto time=int64_t(timestamp(row)*1000000); auto offset=uint64_t(data.tellp());
        auto length=uint32_t(size), raw_size=uint32_t(raw.size()); uint32_t kind=1;
        auto event=row["event"].get<std::string>(); if(event=="done") kind=4; else if(event=="failed_terminal" || event=="partial_rejected") kind=5;
        else if(event=="failed_password") kind=2; else if(event=="suspended_missing_volume") kind=3;
        memcpy(entry.data(),&time,8); memcpy(entry.data()+8,&offset,8); memcpy(entry.data()+16,&length,4);
        auto ordinal=uint32_t(uint64_t(index.tellp())/64);
        memcpy(entry.data()+20,&raw_size,4); memcpy(entry.data()+24,&kind,4); memcpy(entry.data()+28,&ordinal,4); memset(entry.data()+32,255,32);
        data.write(compressed.data(),size); index.write(entry.data(),64);
    }
    data.close(); index.close();
    auto run=Json{{"name",name},{"head",live?1:0},{"count",rows.size()+(live?1:0)},{"unordered",live}};
    auto runs=retained_runs; if(!live) runs.push_back(run);
    atomic_write(path,Json{{"format",1},{"revision",generation},{"task_revision",generation},{"runs",std::move(runs)},{"live",live?run:Json()},{"dropped",0}}.dump());
}
