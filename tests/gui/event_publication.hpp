#pragma once
#include "model.hpp"

// Fixture owns only a fault notification. Ordinary file updates never signal it.
struct EventPublicationFixture {
    spg::Handle fault;
    std::string prefix;
    EventPublicationFixture() {
        GUID guid{}; CoCreateGuid(&guid); wchar_t token[40]; StringFromGUID2(guid,token,40);
        auto name=std::wstring(L"Local\\SunPack.Log.Test.")+token;
        fault.value=CreateEventW(nullptr,TRUE,FALSE,name.c_str());
        FILETIME created{},exit{},kernel{},user{}; GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user);
        auto started=(uint64_t(created.dwHighDateTime)<<32)|created.dwLowDateTime;
        prefix=spg::Json{{"event","state_begin"},{"schema",1},{"generation",spg::utf8(name)},
            {"fault_event",spg::utf8(name)},{"owner_pid",GetCurrentProcessId()},{"owner_started",std::to_string(started)}}.dump()+"\n"+
            spg::Json{{"event","state_ready"},{"generation",spg::utf8(name)}}.dump()+"\n";
    }
};
inline std::string published_events(const std::string& events) {
    static EventPublicationFixture owner;
    return owner.prefix+events;
}
