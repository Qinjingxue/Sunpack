#include "model.hpp"
#include "presentation.hpp"
#include "lz4.h"
#include <array>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <tuple>
#include <streambuf>
#include <istream>
extern "C" NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR);

namespace spg {
namespace {
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
// See io/display_store.rs. Little-endian, 64 bytes per entry; no archive I/O.
constexpr size_t EntryBytes=64, PageRows=100, PageBytes=8*1024*1024;
struct Entry { int64_t time; uint64_t offset; uint32_t compressed,raw,kind,reserved; uint64_t bits[4]; };
static_assert(sizeof(Entry)==EntryBytes);
// Run names are immutable and owned by the readers for the whole query.
using Cursor=std::tuple<int64_t,std::string_view,uint64_t>;
std::wstring folded(const std::string& value) {
    auto text=wide(value); for(auto& ch:text) ch=RtlDowncaseUnicodeChar(ch); return text;
}
uint32_t mix(uint32_t value) {
    value^=value>>16; value*=0x7feb352d; value^=value>>15; value*=0x846ca68b; return value^(value>>16);
}
std::array<uint64_t,4> filter(const std::wstring& text) {
    std::array<uint64_t,4> bits{};
    for(size_t i=0;i<text.size();++i) {
        auto add=[&](uint32_t token) { auto hash=mix(token); for(auto bit:{hash&255,(hash>>8)&255}) bits[bit/64]|=uint64_t(1)<<(bit%64); };
        add(uint16_t(text[i]));
        if(i) add(0x80000000u^(uint32_t(uint16_t(text[i-1]))<<16)^uint16_t(text[i]));
    }
    return bits;
}
bool includes(const Entry& entry,const std::array<uint64_t,4>& bits) {
    for(size_t i=0;i<4;++i) if((entry.bits[i]&bits[i])!=bits[i]) return false; return true;
}
void read_at(HANDLE file,uint64_t offset,void* output,size_t bytes) {
    LARGE_INTEGER position; position.QuadPart=offset;
    if(!SetFilePointerEx(file,position,nullptr,FILE_BEGIN)) win_error("opReadEventLog");
    auto p=static_cast<char*>(output);
    while(bytes) { DWORD got=0; auto take=DWORD(std::min<size_t>(bytes,1024*1024));
        if(!ReadFile(file,p,take,&got,nullptr)) win_error("opReadEventLog");
        if(!got) throw std::runtime_error("logRecordTooLarge"); p+=got; bytes-=got;
    }
}
Handle open_reader(const fs::path& path) {
    auto file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE) win_error("opReadEventLog"); return Handle(file);
}
std::string run_name(const Json& run) {
    auto name=run.at("name").get<std::string>();
    if(name.empty() || name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-")!=std::string::npos)
        throw std::runtime_error("logRecordTooLarge");
    return name;
}
// Large records stream through the same MessagePack reader, one LZ4 block at
// a time. The fixed-width index retains its original size and ordering fields.
struct RecordBuffer : std::streambuf {
    HANDLE file; uint64_t cursor, packed_remaining, raw_remaining;
    std::vector<char> packed,raw;
    RecordBuffer(HANDLE f,uint64_t at,uint64_t packed_size,uint64_t raw_size):file(f),cursor(at),packed_remaining(packed_size),raw_remaining(raw_size) {}
    int_type underflow() override {
        if(gptr() && gptr()<egptr()) return traits_type::to_int_type(*gptr());
        if(!raw_remaining) {
            if(packed_remaining) throw std::runtime_error("logRecordTooLarge");
            return traits_type::eof();
        }
        if(packed_remaining<8) throw std::runtime_error("logRecordTooLarge");
        std::array<uint32_t,2> sizes{}; read_at(file,cursor,sizes.data(),8); cursor+=8;packed_remaining-=8;
        if(!sizes[1] || sizes[1]>1024*1024 || sizes[1]>raw_remaining || !sizes[0] || sizes[0]>uint32_t(LZ4_compressBound(int(sizes[1]))) || sizes[0]>packed_remaining)
            throw std::runtime_error("logRecordTooLarge");
        packed.resize(sizes[0]);raw.resize(sizes[1]);read_at(file,cursor,packed.data(),packed.size());
        if(LZ4_decompress_safe(packed.data(),raw.data(),int(packed.size()),int(raw.size()))!=int(raw.size())) throw std::runtime_error("logRecordTooLarge");
        cursor+=packed.size();packed_remaining-=packed.size();raw_remaining-=raw.size();
        setg(raw.data(),raw.data(),raw.data()+raw.size());return traits_type::to_int_type(*gptr());
    }
};
struct RunReader {
    std::string name;
    fs::path data_path;
    Handle index;
    std::optional<Handle> data;
    uint64_t head=0,count=0,revision=0;
    int64_t position=-1;
    Entry current{};
    std::vector<Entry> cache;
    bool unordered=false, filtered=false;
    std::vector<Entry> selected;
    uint64_t cache_start=0;
    RunReader(const fs::path& folder,const Json& run,const std::optional<Cursor>& before,uint64_t revision):name(run_name(run)),
        data_path(folder/(name+".data")),index(open_reader(folder/(name+".index"))),revision(revision) {
        head=run.at("head").get<uint64_t>(); count=run.at("count").get<uint64_t>();
        unordered=run.value("unordered",false);
        validate();
        LARGE_INTEGER size{}; if(!GetFileSizeEx(index,&size)) win_error("opReadEventLog");
        count=std::min(count,uint64_t(size.QuadPart)/EntryBytes);
        if(head>=count) return;
        auto end=count;
        if(before && !unordered) {
            uint64_t lo=head,hi=count;
            while(lo<hi) { auto middle=lo+(hi-lo)/2; auto row=at(middle);
                if(Cursor{row.time,name,middle}<*before) lo=middle+1; else hi=middle;
            }
            end=lo;
        }
        if(end>head) { position=int64_t(end-1); current=at(uint64_t(position)); }
    }
    void validate() const {
        if(unordered) {
            if(head!=1) throw std::runtime_error("logRecordTooLarge");
            uint64_t committed=0; read_at(index,0,&committed,sizeof(committed));
            if(!committed || committed!=revision) throw WinError(ERROR_SHARING_VIOLATION,"opReadEventLog");
        }
    }
    Entry at(uint64_t pos) {
        if(cache.empty() || pos<cache_start || pos>=cache_start+cache.size()) {
            cache_start=pos>255?std::max(head,pos-255):head;
            auto length=std::min<uint64_t>(512,count-cache_start);
            cache.resize(size_t(length)); read_at(index,cache_start*EntryBytes,cache.data(),cache.size()*EntryBytes);
        }
        return cache[size_t(pos-cache_start)];
    }
    Cursor key() const { return {current.time,name,unordered?current.offset:uint64_t(position)}; }
    void previous() { if(position<=int64_t(filtered?0:head)) position=-1; else { --position; current=filtered?selected[size_t(position)]:at(uint64_t(position)); } }
    Json value(std::vector<char>& packed,std::vector<char>& raw) {
        try { return decode_value(packed,raw); }
        catch(...) {
            validate();
            Entry after{};
            auto ordinal=unordered?uint64_t(current.reserved):uint64_t(position);
            read_at(index,ordinal*EntryBytes,&after,EntryBytes);
            if(std::memcmp(&after,&current,EntryBytes)!=0)
                throw WinError(ERROR_SHARING_VIOLATION,"opReadEventLog");
            throw;
        }
    }
    Json decode_value(std::vector<char>& packed,std::vector<char>& raw) {
        if(!data) data.emplace(open_reader(data_path));
        if(!current.raw && !current.compressed) {
            std::array<char,24> header{};read_at(*data,current.offset,header.data(),header.size());
            uint64_t size=0,raw_size=0;std::memcpy(&size,header.data()+8,8);std::memcpy(&raw_size,header.data()+16,8);
            LARGE_INTEGER file_size{};if(!GetFileSizeEx(*data,&file_size)) win_error("opReadEventLog");
            if(std::memcmp(header.data(),"SPDC",4) || size<24 || !raw_size || current.offset>uint64_t(file_size.QuadPart) || size>uint64_t(file_size.QuadPart)-current.offset)
                throw std::runtime_error("logRecordTooLarge");
            RecordBuffer buffer(*data,current.offset+24,size-24,raw_size);std::istream stream(&buffer);
            stream.exceptions(std::ios::badbit);
            return Json::from_msgpack(stream);
        }
        if(!current.raw || !current.compressed || current.raw>uint32_t(INT_MAX) || current.compressed>uint32_t(LZ4_compressBound(int(current.raw))))
            throw std::runtime_error("logRecordTooLarge");
        packed.resize(current.compressed); raw.resize(current.raw);
        read_at(*data,current.offset,packed.data(),packed.size());
        if(LZ4_decompress_safe(packed.data(),raw.data(),int(packed.size()),int(raw.size()))!=int(raw.size()))
            throw std::runtime_error("logRecordTooLarge");
        return Json::from_msgpack(raw.begin(),raw.end());
    }
};
bool matches(const Json& value,const std::wstring& query,const std::string& time_query) {
    if(query.empty()) return true;
    auto contains=[&](const Json& v) { return v.is_string() && folded(v.get_ref<const std::string&>()).find(query)!=std::wstring::npos; };
    auto path=value.find("path");
    if(path!=value.end() && contains(*path)) return true;
    auto ts=value.find("ts");
    if(!time_query.empty() && ts!=value.end() && ts->is_number() && task_time(ts->get<double>()).find(time_query)!=std::string::npos) return true;
    if(value.contains("group")) {
        const auto& group=value["group"];
        for(const char* field:{"path","name"}) if(group.contains(field) && contains(group[field])) return true;
        if(group.contains("members")) for(const auto& member:group["members"]) {
            if(contains(member)) return true;
            if(member.is_string()) { auto normalized=path_key(wide(member.get<std::string>())); if(normalized.find(query)!=std::wstring::npos) return true; }
        }
    }
    return false;
}
struct TaskRow { Json value; double timestamp=0; };
TaskRow project_task(const Json& value,const RootIndex& roots,const std::string& language,
    std::unordered_map<std::string,std::string>& labels) {
    auto input=value.find("path"), event_name=value.find("event");
    if(input==value.end() || !input->is_string() || event_name==value.end() || !event_name->is_string()) return {};
    const auto& path=input->get_ref<const std::string&>();
    if(path.empty()) return {};
    const auto& event=event_name->get_ref<const std::string&>();
    const char* status;
    const char* tone;
    const char* label;
    if(event=="processing_started") {
        label=status="taskProcessing"; tone="info";
    } else if(event=="failed_password" || event=="suspended_missing_volume") {
        status="taskWaiting"; tone="waiting";
        label=event=="failed_password"?"taskWaitingPassword":"taskWaitingVolumes";
    } else if(event=="done") {
        label=status="taskSucceeded"; tone="success";
    } else if(event=="failed_terminal" || event=="partial_rejected") {
        label=status="taskFailed"; tone="failure";
    } else return {};
    auto translate=[&](const std::string& key) -> const std::string& {
        auto [at,inserted]=labels.try_emplace(key);
        if(inserted) at->second=tr(key,language);
        return at->second;
    };

    const auto group=value.find("group");
    const bool grouped=group!=value.end() && group->is_object();
    auto display_path=grouped?group->value("path",path):path;
    const fs::path source=wide(display_path);
    auto id=value.value("task_id",std::string());
    if(id.empty()) id=utf8(path_key(wide(path)));
    auto parts=Json::array();
    if(grouped && group->contains("members") && (*group)["members"].is_array()) {
        std::unordered_set<std::wstring> seen;
        for(const auto& member:(*group)["members"]) if(member.is_string() && !member.get_ref<const std::string&>().empty()) {
            const fs::path part=wide(member.get_ref<const std::string&>());
            if(seen.insert(path_key(part)).second) parts.push_back(utf8(part.filename().wstring()));
        }
    }
    if((grouped && group->value("multipart",false)) || parts.size()>1 || event=="suspended_missing_volume") {
        if(parts.empty()) parts.push_back(utf8(fs::path(wide(path)).filename().wstring()));
    } else parts.clear();

    std::string error,error_type;
    if(status==std::string_view("taskFailed")) {
        auto text=value.find("error"), kind=value.find("error_kind");
        if(text!=value.end() && text->is_string()) error=text->get<std::string>();
        if(kind!=value.end() && kind->is_string()) error_type=kind->get<std::string>();
        if(!error.empty() || !error_type.empty()) {
            const auto key="taskError_"+(error_type.empty()?std::string("unknown"):error_type);
            const auto& translated=translate(key);
            error_type=translated==key?translate("taskError_unknown"):translated;
        }
    }
    auto outputs=Json::array();
    if(value.contains("output_dirs") && value["output_dirs"].is_array())
        for(const auto& output:value["output_dirs"])
            if(output.is_string() && !output.get_ref<const std::string&>().empty()) outputs.push_back(output);
    const auto ts=value.find("ts");
    const auto timestamp=ts!=value.end() && ts->is_number()?ts->get<double>():std::numeric_limits<double>::quiet_NaN();
    return {{{"id",std::move(id)},{"name",utf8(source.filename().wstring())},{"directory",utf8(source.parent_path().wstring())},
        {"path",std::move(display_path)},{"root",indexed_root(path_key(source),roots)},{"status",status},
        {"statusText",translate(label)},{"time",task_time(timestamp)},{"statusTone",tone},{"parts",std::move(parts)},
        {"error",std::move(error)},{"errorType",std::move(error_type)},{"outputs",std::move(outputs)}},
        std::isfinite(timestamp)?timestamp:0.0};
}

}
Json EventLog::query(const WatchRoots& roots,const View& view,const std::string& language) const {
    if(manifest.is_null()) return {{"rows",Json::array()},{"total",0},{"hasMore",false},{"dropped",0},{"next",""}};
    const auto root_index=index_roots(roots);
    auto folder=path().parent_path()/(path().filename().wstring()+L".store");
    std::string before_name;
    std::optional<Cursor> before;
    if(!view.task_cursor.empty()) {
        auto cursor=Json::parse(view.task_cursor);
        before_name=cursor.at(1).get<std::string>();
        before=Cursor{cursor.at(0).get<int64_t>(),before_name,cursor.at(2).get<uint64_t>()};
    }
    std::vector<std::unique_ptr<RunReader>> runs;
    auto revision=manifest.value("task_revision",uint64_t(0));
    for(const auto& run:manifest.at("runs")) runs.push_back(std::make_unique<RunReader>(folder,run,before,revision));
    auto query=folded(view.task_query); auto bits=filter(query);
    // UTC microseconds are already indexed, including in old stores. Check
    // local display time before rejecting the path bloom, decode candidates
    // only, and reuse formatting across records within the same second.
    const auto time_query=task_time_query(query);
    int64_t time_second=INT64_MIN; bool time_match=false;
    auto matches_time=[&](const Entry& row) {
        if(time_query.empty()) return false;
        const auto second=row.time/1000000;
        if(second!=time_second) {
            time_second=second; time_match=task_time(double(row.time)/1000000).find(time_query)!=std::string::npos;
        }
        return time_match;
    };
    auto root_text=folded(view.task_root); std::replace(root_text.begin(),root_text.end(),L'/',L'\\'); auto root_bits=filter(root_text);
    std::vector<TaskRow> projected;
    projected.reserve(PageRows);
    std::unordered_set<std::string> ids;
    std::unordered_map<std::string,std::string> labels;
    double previous_timestamp=std::numeric_limits<double>::infinity();
    bool needs_sort=false;
    auto matches_root=[&](const Json& value) {
        return view.task_root.empty() || indexed_root(path_key(wide(value.value("path",std::string()))),root_index)==view.task_root;
    };
    std::optional<Cursor> last;
    std::vector<char> packed,raw;
    size_t bytes=0,scanned=0;
    bool more=false;
    const uint32_t desired=view.task_status=="taskSucceeded"?4:view.task_status=="taskFailed"?5:view.task_status=="taskProcessing"?1:0;
    const bool waiting=view.task_status=="taskWaiting";
    auto matches_entry=[&](const Entry& row) {
        return row.kind && (!desired || row.kind==desired) && (!waiting || row.kind==2 || row.kind==3) &&
            includes(row,root_bits) && (includes(row,bits) || matches_time(row));
    };
    auto matches_value=[&](const Json& value) {
        return matches(value,query,time_query) && matches_root(value);
    };
    const bool filter_values=!query.empty() || !view.task_root.empty();
    if(manifest.contains("live") && manifest["live"].is_object()) {
        auto live=std::make_unique<RunReader>(folder,manifest["live"],before,revision);
        if(live->unordered) {
            // Keep at most one page of live candidates. Only filters on record
            // contents need decoding before the merge with historical runs.
            auto earlier=[](const Entry& a,const Entry& b) { return std::tie(a.time,a.offset)<std::tie(b.time,b.offset); };
            while(live->position>=0) {
                if((++scanned&63)==0 && cancelled && cancelled()) return Json();
                auto key=live->key(); auto row=live->current;
                if((!before || key<*before) && (live->selected.size()<PageRows+1 || earlier(live->selected.front(),row)) && matches_entry(row)) {
                    if(!filter_values || matches_value(live->value(packed,raw))) {
                        auto at=std::lower_bound(live->selected.begin(),live->selected.end(),row,earlier);
                        live->selected.insert(at,row);
                        if(live->selected.size()>PageRows+1) live->selected.erase(live->selected.begin());
                    }
                }
                live->previous();
            }
            live->filtered=true; live->position=int64_t(live->selected.size())-1;
            if(live->position>=0) live->current=live->selected.back();
        }
        runs.push_back(std::move(live));
    }
    for(;;) {
        if((++scanned&63)==0 && cancelled && cancelled()) return Json();
        RunReader* selected=nullptr;
        for(auto& run:runs) if(run->position>=0 && (!selected || run->key()>selected->key())) selected=run.get();
        if(!selected) break;
        auto cursor=selected->key(); auto record=selected->current;
        // The unordered live run already applied both filters in its bounded
        // selection. Decode again only when the row fits on the page.
        if(!selected->filtered && !matches_entry(record)) { selected->previous(); continue; }
        const bool check_value=filter_values && !selected->filtered;
        Json value;
        if(check_value) {
            value=selected->value(packed,raw);
            if(!matches_value(value)) { selected->previous(); continue; }
        }
        if(projected.size()>=PageRows || (bytes+(record.raw?record.raw:PageBytes)>PageBytes && !projected.empty())) { more=true; break; }
        // These are independent snapshots. Keep the first card for each ID.
        if(!check_value) value=selected->value(packed,raw);
        auto row=project_task(value,root_index,language,labels);
        if(!row.value.is_null() && ids.insert(row.value.at("id").get_ref<const std::string&>()).second) {
            needs_sort|=row.timestamp>previous_timestamp;
            previous_timestamp=row.timestamp;
            projected.push_back(std::move(row));
        }
        bytes+=record.raw?record.raw:PageBytes; last=std::move(cursor); selected->previous();
    }
    if(cancelled && cancelled()) return Json();
    // Even an empty/filtered page can have crossed a live-slot mutation.
    // Reuse the GUI's existing observed-conflict retry, retaining its last page.
    for(const auto& run:runs) run->validate();
    // The disk index already orders by microseconds. Distinct display
    // timestamps in the same index tick can still require a page-local sort.
    if(needs_sort) std::stable_sort(projected.begin(),projected.end(),[](const TaskRow& a,const TaskRow& b) {
        return a.timestamp>b.timestamp;
    });
    Json::array_t rows;
    rows.reserve(projected.size());
    for(auto& row:projected) rows.push_back(std::move(row.value));
    const auto count=projected.size();
    return {{"rows",std::move(rows)},{"total",count},{"hasMore",more},{"dropped",manifest.value("dropped",uint64_t(0))},
        {"next",more && last?Json({std::get<0>(*last),std::get<1>(*last),std::get<2>(*last)}).dump():std::string()}};
}
}
