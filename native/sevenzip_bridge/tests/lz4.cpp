#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include "lz4.h"
#include "stream.h"
#define XXH_NAMESPACE SUNPACK_LZ4_
#include "xxhash.h"
#include "sevenzip_bridge/bridge.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <array>
#include <windows.h>
#include <winioctl.h>
#include <Unknwn.h>
#include <OleAuto.h>
#include "7zip/Common/CreateCoder.h"

using Bytes = std::vector<unsigned char>;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
class CodecStreams final : public ISequentialInStream, public ISequentialOutStream,
    public ICompressProgressInfo, public CMyUnknownImp {
public:
    const Bytes &source;
    Bytes output;
    size_t offset = 0;
    HRESULT read_status = S_OK, write_status = S_OK;
    bool cancel = false;
    explicit CodecStreams(const Bytes &bytes) : source(bytes) {}
    Z7_COM_QI_BEGIN2(ISequentialInStream)
    Z7_COM_QI_ENTRY(ISequentialOutStream)
    Z7_COM_QI_ENTRY(ICompressProgressInfo)
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE
    Z7_COM7F_IMF(Read(void *data, UInt32 size, UInt32 *count)) {
        *count = 0; if (read_status != S_OK) return read_status;
        *count = static_cast<UInt32>((std::min)({size_t(size), size_t(31), source.size() - offset}));
        std::memcpy(data, source.data() + offset, *count); offset += *count; return S_OK;
    }
    Z7_COM7F_IMF(Write(const void *data, UInt32 size, UInt32 *count)) {
        *count = 0; if (write_status != S_OK) return write_status;
        *count = (std::min)(size, UInt32(4093));
        const auto *begin = static_cast<const Byte *>(data);
        output.insert(output.end(), begin, begin + *count); return S_OK;
    }
    Z7_COM7F_IMF(SetRatioInfo(const UInt64 *, const UInt64 *)) { return cancel ? E_ABORT : S_OK; }
};
static void test_codec(const Bytes &packed, const Bytes &expected) {
    CMyComPtr<ICompressCoder> coder;
    check(CreateCoder_Id(EXTERNAL_CODECS_VARS_G 0x04F71104, false, coder) == S_OK && coder,
          "LZ4 codec registrar retained");
    CMyComPtr<ICompressSetDecoderProperties2> properties;
    CMyComPtr<ICompressSetFinishMode> finish;
    CMyComPtr<ICompressGetInStreamProcessedSize> processed;
    check(coder->QueryInterface(IID_ICompressSetDecoderProperties2, (void **)&properties) == S_OK,
          "codec properties interface");
    check(coder->QueryInterface(IID_ICompressSetFinishMode, (void **)&finish) == S_OK,
          "codec finish interface");
    check(coder->QueryInterface(IID_ICompressGetInStreamProcessedSize, (void **)&processed) == S_OK,
          "codec consumption interface");
    const Byte hints[] = {1, 10, 1, 0, 0};
    check(properties->SetDecoderProperties2(hints, 4) != S_OK, "bad codec properties rejected");
    check(properties->SetDecoderProperties2(hints, 5) == S_OK, "codec properties accepted");
    const UInt64 input_size = packed.size(), output_size = expected.size();
    auto invoke = [&](UInt64 size, bool full, HRESULT read_error, HRESULT write_error, bool cancel) {
        auto *streams = new CodecStreams(packed);
        CMyComPtr<ISequentialInStream> owner = streams;
        streams->read_status = read_error; streams->write_status = write_error; streams->cancel = cancel;
        finish->SetFinishMode(full);
        const HRESULT status = coder->Code(streams, streams, &input_size, &size, streams);
        return std::make_pair(status, std::move(streams->output));
    };
    auto full = invoke(output_size, true, S_OK, S_OK, false);
    check(full.first == S_OK && full.second == expected, "codec full fragmented decode");
    UInt64 consumed = 0; processed->GetInStreamProcessedSize(&consumed);
    check(consumed == input_size, "codec consumed full range");
    auto partial = invoke(17, false, S_OK, S_OK, false);
    check(partial.first == S_OK && partial.second == Bytes(expected.begin(), expected.begin() + 17),
          "codec partial solid output");
    check(invoke(17, true, S_OK, S_OK, false).first == S_FALSE, "codec full size mismatch rejected");
    check(invoke(output_size, true, E_ABORT, S_OK, false).first == E_ABORT, "codec read cancellation propagated");
    check(invoke(output_size, true, S_OK, E_ACCESSDENIED, false).first == E_ACCESSDENIED, "codec write failure propagated");
    check(invoke(output_size, true, S_OK, S_OK, true).first == E_ABORT, "codec progress cancellation propagated");
    check(invoke(0, false, S_OK, S_OK, false).first == S_OK, "codec empty partial output");
}
static void word(Bytes &out, unsigned int n) { for (int i=0;i<4;++i) out.push_back(static_cast<unsigned char>(n>>(8*i))); }
static void save(const std::filesystem::path &path, const Bytes &data) {
    std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char *>(data.data()), data.size()); check(bool(f),"fixture write");
}
static Bytes frame(const Bytes &input, int block, bool linked, bool content, bool checksum, bool size, const Bytes *dict=nullptr, unsigned int id=0, int level=0) {
    LZ4F_preferences_t prefs{};
    prefs.frameInfo.blockSizeID=static_cast<LZ4F_blockSizeID_t>(block);
    prefs.frameInfo.blockMode=linked?LZ4F_blockLinked:LZ4F_blockIndependent;
    prefs.frameInfo.contentChecksumFlag=content?LZ4F_contentChecksumEnabled:LZ4F_noContentChecksum;
    prefs.frameInfo.blockChecksumFlag=checksum?LZ4F_blockChecksumEnabled:LZ4F_noBlockChecksum;
    prefs.frameInfo.contentSize=size?input.size():0;
    prefs.frameInfo.dictID=id;
    prefs.compressionLevel=level;
    Bytes out(LZ4F_compressFrameBound(input.size(), &prefs));
    size_t n;
    if (dict) {
        LZ4F_cctx *ctx=nullptr; check(!LZ4F_isError(LZ4F_createCompressionContext(&ctx,LZ4F_VERSION)),"compress context");
        LZ4F_CDict *cdict=LZ4F_createCDict(dict->data(),dict->size()); check(cdict!=nullptr,"compress dictionary");
        n=LZ4F_compressFrame_usingCDict(ctx,out.data(),out.size(),input.data(),input.size(),cdict,&prefs);
        LZ4F_freeCDict(cdict); LZ4F_freeCompressionContext(ctx);
    } else n=LZ4F_compressFrame(out.data(),out.size(),input.data(),input.size(),&prefs);
    check(!LZ4F_isError(n),"frame compression"); out.resize(n); return out;
}
struct Memory {
    const Bytes *source; Bytes output; size_t offset=0, chunk=256*1024;
    const Bytes *dictionary=nullptr; unsigned int id=0; bool cancel=false;
};
static ptrdiff_t read_mem(void *p,void *dst,size_t n) {
    auto &s=*static_cast<Memory *>(p); n=(std::min)({n,s.chunk,s.source->size()-s.offset});
    std::memcpy(dst,s.source->data()+s.offset,n); s.offset+=n; return n;
}
static int write_mem(void *p,const void *src,size_t n) {
    auto &s=*static_cast<Memory *>(p); const auto *b=static_cast<const unsigned char *>(src);
    s.output.insert(s.output.end(),b,b+n); return 0;
}
static int dict_mem(void *p,uint32_t id,int has_id,const void **data,size_t *n) {
    auto &s=*static_cast<Memory *>(p); if (!s.dictionary || (has_id && id!=s.id)) return 0;
    *data=s.dictionary->data(); *n=s.dictionary->size(); return 1;
}
static int progress_mem(void *p,uint64_t,uint64_t) { return static_cast<Memory *>(p)->cancel; }
static sup_lz4_result decode(const Bytes &source,const Bytes &expected,size_t chunk=256*1024,const Bytes *dictionary=nullptr,unsigned int id=0,int error=0) {
    Memory s{&source,{},0,chunk,dictionary,id}; sup_lz4_result result{};
    int rc=sup_lz4_decode(&s,read_mem,nullptr,write_mem,dict_mem,progress_mem,&result);
    check(rc==error,"decoder result");
    if (!rc) {check(s.output==expected,"decoded content"); check(result.input_bytes==source.size(),"input coverage"); check(result.output_bytes==expected.size(),"output coverage");}
    return result;
}
static Bytes legacy(const Bytes &input) {
    Bytes out; word(out,0x184c2102);
    for(size_t offset=0;offset<input.size();) {
        const int n=static_cast<int>((std::min)(input.size()-offset,size_t{8*1024*1024}));
        Bytes block(LZ4_compressBound(n));
        const int got=LZ4_compress_default(reinterpret_cast<const char *>(input.data()+offset),reinterpret_cast<char *>(block.data()),n,static_cast<int>(block.size()));
        check(got>0,"legacy compression");word(out,got);out.insert(out.end(),block.begin(),block.begin()+got); offset+=n;
    }
    return out;
}
static Bytes tar(const Bytes &input) {
    Bytes out(512,0); std::memcpy(out.data(),"hello.txt",9);std::memcpy(out.data()+100,"0000644",7);
    std::memcpy(out.data()+108,"0000000",7);std::memcpy(out.data()+116,"0000000",7);
    char size[12]; std::snprintf(size,sizeof(size),"%011o",static_cast<unsigned>(input.size()));std::memcpy(out.data()+124,size,12);
    std::memcpy(out.data()+136,"00000000000",11); std::fill(out.begin()+148,out.begin()+156,' ');out[156]='0';
    std::memcpy(out.data()+257,"ustar",5);std::memcpy(out.data()+263,"00",2);
    unsigned sum=0;for(auto b:out)sum+=b;char crc[8];std::snprintf(crc,sizeof(crc),"%06o",sum);std::memcpy(out.data()+148,crc,7);out[155]=' ';
    out.insert(out.end(),input.begin(),input.end());out.resize(((out.size()+511)/512)*512+1024);return out;
}
static void compress_files_to_lz4(const std::vector<std::filesystem::path> &source_paths, const std::filesystem::path &target_path) {
    check(!source_paths.empty(), "LZ4 benchmark needs at least one source");
    std::ofstream output(target_path, std::ios::binary | std::ios::trunc);
    check(output.good(), "LZ4 benchmark target open");

    LZ4F_preferences_t preferences{};
    preferences.frameInfo.blockMode = LZ4F_blockIndependent;
    LZ4F_cctx *context = nullptr;
    check(!LZ4F_isError(LZ4F_createCompressionContext(&context, LZ4F_VERSION)), "LZ4 benchmark context");
    std::vector<unsigned char> source(1024 * 1024);
    std::vector<unsigned char> packed(LZ4F_compressBound(source.size(), &preferences));
    auto write = [&](size_t size) {
        output.write(reinterpret_cast<const char *>(packed.data()), static_cast<std::streamsize>(size));
        check(output.good(), "LZ4 benchmark write");
    };
    const size_t header_size = LZ4F_compressBegin(context, packed.data(), packed.size(), &preferences);
    check(!LZ4F_isError(header_size), "LZ4 benchmark frame header");
    write(header_size);
    for (const auto &source_path : source_paths) {
        std::ifstream input(source_path, std::ios::binary);
        check(input.good(), "LZ4 benchmark source open");
        while (input) {
            input.read(reinterpret_cast<char *>(source.data()), static_cast<std::streamsize>(source.size()));
            const auto count = static_cast<size_t>(input.gcount());
            if (!count) break;
            const size_t packed_size = LZ4F_compressUpdate(context, packed.data(), packed.size(), source.data(), count, nullptr);
            check(!LZ4F_isError(packed_size), "LZ4 benchmark frame update");
            write(packed_size);
        }
        check(input.eof(), "LZ4 benchmark source read");
    }
    const size_t footer_size = LZ4F_compressEnd(context, packed.data(), packed.size(), nullptr);
    check(!LZ4F_isError(footer_size), "LZ4 benchmark frame footer");
    write(footer_size);
    LZ4F_freeCompressionContext(context);
    output.close();
    check(output.good(), "LZ4 benchmark target close");
}
static Bytes zero_dictionary_id(Bytes bytes) {
    check((bytes[4] & 1) != 0, "explicit dictionary field");
    const size_t at = 6 + ((bytes[4] & 8) ? 8 : 0);
    std::fill(bytes.begin() + at, bytes.begin() + at + 4, 0);
    bytes[at + 4] = static_cast<unsigned char>(XXH32(bytes.data() + 4, at, 0) >> 8);
    return bytes;
}
static void benchmark(const Bytes &input) {
    const auto packed=frame(input,7,true,true,true,true);
    std::array<double,2> seconds{};
    for(int run=0;run<12;++run) for(int kind=0;kind<2;++kind) {
        const auto start=std::chrono::steady_clock::now();
        for(int iteration=0;iteration<10;++iteration) {
            Memory memory{&packed}; memory.output.reserve(input.size());
            if(kind) {
                sup_lz4_result result{};
                check(sup_lz4_decode(&memory,read_mem,nullptr,write_mem,nullptr,nullptr,&result)==0,"benchmark adapter");
            } else {
                LZ4F_dctx *ctx=nullptr;check(!LZ4F_isError(LZ4F_createDecompressionContext(&ctx,LZ4F_VERSION)),"benchmark context");
                std::array<unsigned char,256*1024> buffer;
                size_t hint=1;
                while(hint) {
                    size_t source=packed.size()-memory.offset, dest=buffer.size();
                    hint=LZ4F_decompress(ctx,buffer.data(),&dest,packed.data()+memory.offset,&source,nullptr);
                    check(!LZ4F_isError(hint),"benchmark direct");memory.offset+=source;
                    write_mem(&memory,buffer.data(),dest);
                }
                LZ4F_freeDecompressionContext(ctx);
            }
            check(memory.output==input,"benchmark content");
        }
        if(run>=2) seconds[kind]+=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    }
    const auto bytes=double(input.size())*100;
    std::cout<<"LZ4 decode+collect: library="<<bytes/seconds[0]/1e9<<" GB/s adapter="<<bytes/seconds[1]/1e9
             <<" GB/s ratio="<<seconds[1]/seconds[0]<<"\n";
}
int wmain(int argc,wchar_t **argv) {
    try {
        if (argc >= 4 && std::wstring(argv[1]) == L"--compress-files") {
            std::vector<std::filesystem::path> sources;
            for (int index = 3; index < argc; ++index) sources.emplace_back(argv[index]);
            compress_files_to_lz4(sources, argv[2]);
            return 0;
        }
        auto root=argc>1?std::filesystem::path(argv[1]):std::filesystem::temp_directory_path()/L"sunpack-lz4-tests";
        root=std::filesystem::absolute(root).make_preferred();
        std::filesystem::create_directories(root);
        Bytes input(5*1024*1024); for(size_t i=0;i<input.size();++i) input[i]=static_cast<unsigned char>((i*13+i/4096)%251);
        save(root/L"expected.raw",input);
        std::filesystem::create_directories(root/L"expected_standard");
        save(root/L"expected_standard"/L"payload",input);
        std::filesystem::create_directories(root/L"expected_tar");
        save(root/L"expected_tar"/L"hello.txt",Bytes{'h','e','l','l','o','\n'});
        unsigned cases=0;
        for(int block=4;block<=7;++block)for(int bits=0;bits<16;++bits) {
            auto packed=frame(input,block,bits&1,bits&2,bits&4,bits&8);
            auto result=decode(packed,input);check(result.frames==1,"one frame");
            const auto name=L"frame_"+std::to_wstring(block)+L"_"+std::to_wstring(bits)+L".lz4";
            save(root/name,packed); ++cases;
        }
        auto standard=frame(input,7,true,true,true,true);
        test_codec(standard, input);
        auto high=frame(input,7,true,true,true,true,nullptr,0,12);
        decode(high,input);save(root/L"high_compression.lz4",high);
        for(size_t chunk:{size_t{1},size_t{7},size_t{31},size_t{4096}})decode(standard,input,chunk);
        Bytes skip; word(skip,0x184d2a5f);word(skip,3);skip.insert(skip.end(),{1,2,3});
        Bytes concatenated=skip;concatenated.insert(concatenated.end(),standard.begin(),standard.end());concatenated.insert(concatenated.end(),skip.begin(),skip.end());
        concatenated.insert(concatenated.end(),standard.begin(),standard.end());concatenated.insert(concatenated.end(),skip.begin(),skip.end());
        Bytes double_input=input;double_input.insert(double_input.end(),input.begin(),input.end());
        std::filesystem::create_directories(root/L"expected_concat");
        save(root/L"expected_concat"/L"payload",double_input);
        auto result=decode(concatenated,double_input,7);check(result.frames==2&&result.skippable_frames==3&&result.content_checked_frames==2,"concatenation receipt");
        save(root/L"concat.bin",concatenated);
        auto old=legacy(input);decode(old,input,31);save(root/L"legacy.lz4",old);
        Bytes legacy_large=input;legacy_large.insert(legacy_large.end(),input.begin(),input.end());
        legacy_large.insert(legacy_large.end(),input.begin(),input.end());decode(legacy(legacy_large),legacy_large,4096);
        auto terminated=old;word(terminated,0);decode(terminated,input,31);save(root/L"legacy_zero.lz4",terminated);
        Bytes mixed=old;mixed.insert(mixed.end(),standard.begin(),standard.end());decode(mixed,double_input,31);save(root/L"mixed.lz4",mixed);
        auto empty=frame({},4,false,true,true,true);decode(empty,{});save(root/L"empty.lz4",empty);
        auto damaged=standard;damaged.back()^=1;decode(damaged,{},4096,nullptr,0,SUP_LZ4_CHECKSUM);save(root/L"bad_content.lz4",damaged);
        auto bad_header=standard;bad_header[14]^=1;decode(bad_header,{},31,nullptr,0,SUP_LZ4_CHECKSUM);save(root/L"bad_header.lz4",bad_header);
        auto bad_block=standard;bad_block[19]^=1;decode(bad_block,{},31,nullptr,0,SUP_LZ4_CHECKSUM);save(root/L"bad_block.lz4",bad_block);
        auto truncated=standard;truncated.pop_back();decode(truncated,{},4096,nullptr,0,SUP_LZ4_TRUNCATED);save(root/L"truncated.lz4",truncated);
        Bytes dictionary(65536);unsigned rng=42;for(auto &b:dictionary){rng=rng*1664525U+1013904223U;b=static_cast<unsigned char>(rng>>24);}
        Bytes dict_input(dictionary.begin()+2000,dictionary.end());dict_input.insert(dict_input.end(),dictionary.begin()+2000,dictionary.end());
        const auto dict_frame=frame(dict_input,4,true,true,true,true,&dictionary,123);
        decode(dict_frame,dict_input,31,&dictionary,123);decode(dict_frame,{},31,nullptr,0,SUP_LZ4_DICTIONARY);
        save(root/L"dict.raw",dictionary);save(root/L"dictionary.lz4",dict_frame);save(root/L"dictionary_expected.raw",dict_input);
        std::filesystem::create_directories(root/L"expected_dictionary");
        save(root/L"expected_dictionary"/L"payload",dict_input);
        save(root/L"dictionary_no_id.lz4",frame(dict_input,4,true,true,true,true,&dictionary,0));
        auto zero_id=zero_dictionary_id(dict_frame);
        decode(zero_id,dict_input,31,&dictionary,0);save(root/L"dictionary_zero_id.lz4",zero_id);
        check(decode(zero_id,{},31,nullptr,0,SUP_LZ4_DICTIONARY).dictionary_id==0,"missing explicit ID zero");
        decode(zero_id,{},31,&dictionary,123,SUP_LZ4_DICTIONARY);
        Memory no_dictionary{&zero_id};sup_lz4_result missing_zero{};
        check(sup_lz4_decode(&no_dictionary,read_mem,nullptr,write_mem,nullptr,nullptr,&missing_zero)==SUP_LZ4_DICTIONARY,
              "ID zero also requires context without a dictionary callback");
        Bytes zero_carrier(1031,0x89);zero_carrier.insert(zero_carrier.end(),zero_id.begin(),zero_id.end());
        zero_carrier.resize(zero_carrier.size()+29,0x88);save(root/L"dictionary_zero_id_carrier.dat",zero_carrier);
        save(root/L"payload_zero_id.tar.lz4",zero_dictionary_id(frame(tar(Bytes{'h','e','l','l','o','\n'}),4,true,true,true,true,&dictionary,123)));
        for(int block=4;block<=7;++block) for(bool linked:{false,true})
            decode(frame(dict_input,block,linked,true,true,true,&dictionary,123),dict_input,31,&dictionary,123);
        Bytes padded_dictionary(256*1024,0x89);padded_dictionary.insert(padded_dictionary.end(),dictionary.begin(),dictionary.end());
        save(root/L"dict_large.raw",padded_dictionary);
        Bytes second_dictionary=dictionary;for(auto &b:second_dictionary)b^=0x9f;
        Bytes second_input(second_dictionary.begin()+2000,second_dictionary.end());
        save(root/L"dict_second.raw",second_dictionary);
        auto switching=dict_frame;
        const auto second_frame=frame(second_input,4,false,true,true,true,&second_dictionary,0xffffffffU);
        switching.insert(switching.end(),second_frame.begin(),second_frame.end());
        switching.insert(switching.end(),dict_frame.begin(),dict_frame.end());
        save(root/L"dictionary_switch.lz4",switching);
        Bytes switching_expected=dict_input;switching_expected.insert(switching_expected.end(),second_input.begin(),second_input.end());
        switching_expected.insert(switching_expected.end(),dict_input.begin(),dict_input.end());
        std::filesystem::create_directories(root/L"expected_switch");save(root/L"expected_switch"/L"payload",switching_expected);
        save(root/L"payload.tar.lz4",frame(tar(Bytes{'h','e','l','l','o','\n'}),4,true,true,true,true));
        save(root/L"skips_only.lz4",skip);decode(skip,{});
        Bytes skip_zstd=skip;
        skip_zstd.insert(skip_zstd.end(),{0x28,0xb5,0x2f,0xfd,0x20,5,0x29,0,0,'h','e','l','l','o'});
        save(root/L"skip_zstd.bin",skip_zstd);
        Bytes pe(1024,0);pe[0]='M';pe[1]='Z';pe[0x3c]=64;
        pe[64]='P';pe[65]='E';pe[70]=1;
        pe[88+17]=2;pe[88+21]=2; // one 512-byte section at file offset 512
        pe.insert(pe.end(),concatenated.begin(),concatenated.end());pe.resize(pe.size()+29,0x88);
        save(root/L"carrier.exe",pe);
        Bytes random(5*1024*1024);unsigned random_state=42;for(auto &b:random){random_state=random_state*1664525U+1013904223U;b=static_cast<unsigned char>(random_state>>24);}
        const auto random_frame=frame(random,7,false,true,true,true);decode(random_frame,random,4096);
        save(root/L"uncompressed_blocks.lz4",random_frame);
        if(argc>2 && std::wstring(argv[2])==L"--benchmark") { benchmark(input); benchmark(random); }
        // A logical 1 GiB skippable payload occupies almost no physical space.
        // Analysis and TAR sampling must jump over it, not decode/read it.
        const auto sparse_path=(root/L"large_skip.tar.lz4").wstring();
        HANDLE sparse=CreateFileW(sparse_path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        check(sparse!=INVALID_HANDLE_VALUE,"sparse fixture open");DWORD processed=0;
        check(DeviceIoControl(sparse,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&processed,nullptr)!=FALSE,"sparse fixture flag");
        Bytes sparse_head;word(sparse_head,0x184d2a50);word(sparse_head,1U<<30);
        check(WriteFile(sparse,sparse_head.data(),8,&processed,nullptr)&&processed==8,"sparse header");
        LARGE_INTEGER position{};position.QuadPart=(1LL<<30)+8;
        check(SetFilePointerEx(sparse,position,nullptr,FILE_BEGIN)!=FALSE,"sparse skip");
        const auto tar_frame=frame(tar(Bytes{'h','e','l','l','o','\n'}),4,true,true,true,true);
        check(WriteFile(sparse,tar_frame.data(),static_cast<DWORD>(tar_frame.size()),&processed,nullptr)&&processed==tar_frame.size(),"sparse frame");CloseHandle(sparse);
        save(root/L"nested.lz4",frame(standard,4,true,true,true,true));
        Bytes carrier(1031,0x89);carrier.insert(carrier.end(),concatenated.begin(),concatenated.end());carrier.resize(carrier.size()+29,0x88);save(root/L"carrier.dat",carrier);
        Bytes uncertain(1031,0x89);uncertain.insert(uncertain.end(),old.begin(),old.end());uncertain.resize(uncertain.size()+29,0x88);save(root/L"legacy_carrier.dat",uncertain);
        Bytes short_tail(1031,0x89);short_tail.insert(short_tail.end(),old.begin(),old.end());
        word(short_tail,128);short_tail.resize(short_tail.size()+29,0x88);save(root/L"legacy_carrier_short_tail.dat",short_tail);
        const auto split=standard.size()/2;save(root/L"split.any.001",Bytes(standard.begin(),standard.begin()+split));save(root/L"split.any.002",Bytes(standard.begin()+split,standard.end()));
        sunpack::sevenzip::Lz4Options options;options.dictionaries.emplace_back(123,(root/L"dict.raw").wstring());
        auto extracted=sunpack::sevenzip::extract_archive_with_parts((root/L"dictionary.lz4").wstring(),{},L"lz4",L"",(root/L"worker_output").wstring(),L"",nullptr,false,{},false,nullptr,0,nullptr,options);
        if (!extracted.command_ok) std::cerr<<"worker: "<<extracted.message<<" kind="<<extracted.failure_kind<<" hr="<<extracted.hresult<<" op="<<extracted.operation_result<<"\n";
        check(extracted.command_ok&&extracted.has_stream_receipt&&extracted.stream_receipt.content_checked_frames==1,"worker dictionary extraction");
        check(extracted.output_trace.items.size()==1&&!extracted.output_trace.items[0].crc_verified,"no fake CRC32");
        const auto &output_item=extracted.output_trace.items[0];
        std::ifstream actual(root/L"worker_output"/output_item.output_path,std::ios::binary);
        Bytes extracted_bytes((std::istreambuf_iterator<char>(actual)),std::istreambuf_iterator<char>());
        check(extracted_bytes==dict_input,"finalized worker output content");
        Memory cancelled{&standard};cancelled.cancel=true;sup_lz4_result cancelled_result{};
        check(sup_lz4_decode(&cancelled,read_mem,nullptr,write_mem,dict_mem,progress_mem,&cancelled_result)==SUP_LZ4_CANCELLED,"cancellation");
        std::cout<<"LZ4: "<<cases<<" frame combinations, fragmentation, dictionaries, concatenation, Legacy, checksums, cancellation and worker passed\n";
        return 0;
    } catch(const std::exception &e) {std::cerr<<e.what()<<"\n";return 1;}
}
