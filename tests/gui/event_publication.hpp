#pragma once
#include "model.hpp"

// A real volatile publication identity for file fixtures. Legacy JSONL is now
// deliberately unverified; tests of grouping/filtering need a live publisher.
struct EventPublicationFixture {
    spg::Handle dirty, published, mapping;
    std::string prefix;
    EventPublicationFixture() {
        GUID guid{}; CoCreateGuid(&guid); wchar_t token[40]; StringFromGUID2(guid,token,40);
        auto name=std::wstring(L"Local\\SunPack.State.Test.")+token;
        dirty.value=CreateEventW(nullptr,TRUE,FALSE,(name+L".dirty").c_str());
        published.value=CreateEventW(nullptr,TRUE,TRUE,(name+L".published").c_str());
        mapping.value=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,8,(name+L".revision").c_str());
        FILETIME created{},exit{},kernel{},user{}; GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user);
        auto started=(uint64_t(created.dwHighDateTime)<<32)|created.dwLowDateTime;
        prefix=spg::Json{{"event","state_begin"},{"schema",1},{"generation",spg::utf8(name)},
            {"owner_pid",GetCurrentProcessId()},{"owner_started",std::to_string(started)}}.dump()+"\n"+
            spg::Json{{"event","state_ready"},{"generation",spg::utf8(name)}}.dump()+"\n"+
            spg::Json{{"event","state_commit"},{"revision",0}}.dump()+"\n";
    }
};
inline std::string published_events(const std::string& events) {
    static EventPublicationFixture owner;
    return owner.prefix+events;
}
