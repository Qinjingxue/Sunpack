#include "model.hpp"
#include "lz4.h"
#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <tuple>
#include <streambuf>
#include <istream>
extern "C" NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR);

namespace spg {
namespace {
// See io/display_store.rs. Little-endian, 64 bytes per entry; no archive I/O.
constexpr size_t EntryBytes=64, PageRows=100, PageBytes=8*1024*1024;
struct Entry { int64_t time; uint64_t offset; uint32_t compressed,raw,kind,reserved; uint64_t bits[4]; };
static_assert(sizeof(Entry)==EntryBytes);
using Cursor=std::tuple<int64_t,std::string,uint64_t>;
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
HANDLE open_reader(const fs::path& path) {
    auto file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE) win_error("opReadEventLog"); return file;
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
    std::unique_ptr<Handle> data;
    uint64_t head=0,count=0;
    int64_t position=-1;
    Entry current{};
    std::vector<Entry> cache;
    bool unordered=false, filtered=false;
    std::vector<std::pair<Cursor,Entry>> selected;
    uint64_t cache_start=0;
    RunReader(const fs::path& folder,const Json& run,const std::optional<Cursor>& before):name(run_name(run)),
        data_path(folder/(name+".data")),index(open_reader(folder/(name+".index"))) {
        head=run.at("head").get<uint64_t>(); count=run.at("count").get<uint64_t>();
        LARGE_INTEGER size{}; if(!GetFileSizeEx(index,&size)) win_error("opReadEventLog");
        count=std::min(count,uint64_t(size.QuadPart)/EntryBytes);
        if(head>=count) return;
        unordered=run.value("unordered",false);
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
    Entry at(uint64_t pos) {
        if(cache.empty() || pos<cache_start || pos>=cache_start+cache.size()) {
            cache_start=pos>255?std::max(head,pos-255):head;
            auto length=std::min<uint64_t>(512,count-cache_start);
            cache.resize(size_t(length)); read_at(index,cache_start*EntryBytes,cache.data(),cache.size()*EntryBytes);
        }
        return cache[size_t(pos-cache_start)];
    }
    Cursor key() const { if(filtered) return selected[size_t(position)].first; return {current.time,name,unordered?current.offset:uint64_t(position)}; }
    void previous() { if(position<=int64_t(filtered?0:head)) position=-1; else { --position; current=filtered?selected[size_t(position)].second:at(uint64_t(position)); } }
    Json value(std::vector<char>& packed,std::vector<char>& raw) {
        try { return decode_value(packed,raw); }
        catch(...) {
            Entry after{};
            auto ordinal=unordered?uint64_t(current.reserved):uint64_t(position);
            read_at(index,ordinal*EntryBytes,&after,EntryBytes);
            if(std::memcmp(&after,&current,EntryBytes)!=0)
                throw WinError(ERROR_SHARING_VIOLATION,"opReadEventLog");
            throw;
        }
    }
    Json decode_value(std::vector<char>& packed,std::vector<char>& raw) {
        if(!data) data=std::make_unique<Handle>(open_reader(data_path));
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
bool matches(const Json& value,const std::wstring& query) {
    if(query.empty()) return true;
    auto contains=[&](const Json& v) { return v.is_string() && folded(v.get_ref<const std::string&>()).find(query)!=std::wstring::npos; };
    if(contains(value.value("path",Json()))) return true;
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
}
Json EventLog::query(const WatchRoots& roots,const View& view,const std::string& language) const {
    auto folder=path().parent_path()/(path().filename().wstring()+L".store");
    std::optional<Cursor> before;
    if(!view.task_cursor.empty()) { auto c=Json::parse(view.task_cursor); before=Cursor{c.at(0).get<int64_t>(),c.at(1).get<std::string>(),c.at(2).get<uint64_t>()}; }
    std::vector<std::unique_ptr<RunReader>> runs;
    for(const auto& run:manifest.at("runs")) runs.push_back(std::make_unique<RunReader>(folder,run,before));
    auto query=folded(view.task_query); auto bits=filter(query);
    auto root_text=folded(view.task_root); std::replace(root_text.begin(),root_text.end(),L'/',L'\\'); auto root_bits=filter(root_text);
    EventLog page;
    std::optional<Cursor> last;
    std::vector<char> packed,raw;
    size_t bytes=0,scanned=0;
    bool more=false;
    uint32_t desired=view.task_status=="taskSucceeded"?4:view.task_status=="taskFailed"?5:view.task_status=="taskProcessing"?1:0;
    if(manifest.contains("live") && manifest["live"].is_object()) {
        auto live=std::make_unique<RunReader>(folder,manifest["live"],before);
        if(live->unordered) {
            // Live slots are mutable. Scan only their compact metadata, keeping
            // at most one page of candidates; historical runs remain seekable.
            while(live->position>=0) {
                if((++scanned&63)==0 && cancelled && cancelled()) return Json();
                auto key=live->key(); auto row=live->current;
                bool possible=row.kind && (!before || key<*before) && (!desired || row.kind==desired) &&
                    (view.task_status!="taskWaiting" || row.kind==2 || row.kind==3) && includes(row,bits) && includes(row,root_bits);
                if(possible && (live->selected.size()<PageRows+1 || key>live->selected.front().first)) {
                    auto value=live->value(packed,raw);
                    if(matches(value,query) && (view.task_root.empty() || root_for(wide(value.value("path",std::string())),roots)==view.task_root)) {
                        auto at=std::lower_bound(live->selected.begin(),live->selected.end(),key,[](const auto& item,const Cursor& key){return item.first<key;});
                        live->selected.insert(at,{key,row});
                        if(live->selected.size()>PageRows+1) live->selected.erase(live->selected.begin());
                    }
                }
                live->previous();
            }
            live->filtered=true; live->position=int64_t(live->selected.size())-1;
            if(live->position>=0) live->current=live->selected.back().second;
        }
        runs.push_back(std::move(live));
    }
    for(;;) {
        if((++scanned&63)==0 && cancelled && cancelled()) return Json();
        RunReader* selected=nullptr;
        for(auto& run:runs) if(run->position>=0 && (!selected || run->key()>selected->key())) selected=run.get();
        if(!selected) break;
        auto cursor=selected->key(); auto record=selected->current;
        if(!record.kind || (desired && record.kind!=desired) ||
           (view.task_status=="taskWaiting" && record.kind!=2 && record.kind!=3) || !includes(record,bits) || !includes(record,root_bits)) { selected->previous(); continue; }
        auto value=selected->value(packed,raw);
        if(!matches(value,query) || (!view.task_root.empty() && root_for(wide(value.value("path",std::string())),roots)!=view.task_root)) { selected->previous(); continue; }
        if(page.tasks.size()>=PageRows || (bytes+(record.raw?record.raw:PageBytes)>PageBytes && !page.tasks.empty())) { more=true; break; }
        // These are independent snapshots, not events to merge across owners.
        // An older family's descriptor must never absorb a current retry card.
        EventLog item; item.accept(value);
        for(auto& pair:item.tasks) {
            pair.second.sequence=PageRows-page.tasks.size();
            page.tasks.emplace(pair.first,std::move(pair.second));
        }
        bytes+=record.raw?record.raw:PageBytes; last=std::move(cursor); selected->previous();
    }
    if(cancelled && cancelled()) return Json();
    View selected_view; // Already filtered using complete on-disk member lists.
    auto result=task_rows(page,roots,selected_view,language);
    result["hasMore"]=more; result["dropped"]=manifest.value("dropped",uint64_t(0));
    result["next"]=more && last?Json({std::get<0>(*last),std::get<1>(*last),std::get<2>(*last)}).dump():std::string();
    return result;
}
}
