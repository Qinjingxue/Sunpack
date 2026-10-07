#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
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
static Bytes frame(const Bytes &input, int block, bool linked, bool content, bool checksum, bool size, int level=0) {
    LZ4F_preferences_t prefs{};
    prefs.frameInfo.blockSizeID=static_cast<LZ4F_blockSizeID_t>(block);
    prefs.frameInfo.blockMode=linked?LZ4F_blockLinked:LZ4F_blockIndependent;
    prefs.frameInfo.contentChecksumFlag=content?LZ4F_contentChecksumEnabled:LZ4F_noContentChecksum;
    prefs.frameInfo.blockChecksumFlag=checksum?LZ4F_blockChecksumEnabled:LZ4F_noBlockChecksum;
    prefs.frameInfo.contentSize=size?input.size():0;
    prefs.compressionLevel=level;
    Bytes out(LZ4F_compressFrameBound(input.size(), &prefs));
    const size_t n=LZ4F_compressFrame(out.data(),out.size(),input.data(),input.size(),&prefs);
    check(!LZ4F_isError(n),"frame compression"); out.resize(n); return out;
}
struct Memory {
    const Bytes *source; Bytes output; size_t offset=0, chunk=256*1024;
    bool cancel=false;
};
static ptrdiff_t read_mem(void *p,void *dst,size_t n) {
    auto &s=*static_cast<Memory *>(p); n=(std::min)({n,s.chunk,s.source->size()-s.offset});
    std::memcpy(dst,s.source->data()+s.offset,n); s.offset+=n; return n;
}
static int write_mem(void *p,const void *src,size_t n) {
    auto &s=*static_cast<Memory *>(p); const auto *b=static_cast<const unsigned char *>(src);
    s.output.insert(s.output.end(),b,b+n); return 0;
}
static int progress_mem(void *p,uint64_t,uint64_t) { return static_cast<Memory *>(p)->cancel; }
static sup_lz4_result decode(const Bytes &source,const Bytes &expected,size_t chunk=256*1024,int error=0) {
    Memory s{&source,{},0,chunk}; sup_lz4_result result{};
    int rc=sup_lz4_decode(&s,read_mem,nullptr,write_mem,progress_mem,&result);
    check(rc==error,"decoder result");
    if (!rc) {check(s.output==expected,"decoded content"); check(result.input_bytes==source.size(),"input coverage"); check(result.output_bytes==expected.size(),"output coverage");}
    return result;
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
// Construct valid headers with a Dict-ID without adding a dictionary encoder.
// All IDs, including zero, are outside the self-contained decoding contract.
static Bytes with_dict_id(Bytes bytes, unsigned int id) {
    check(!(bytes[4] & 1), "self-contained source header");
    const size_t at = 6 + ((bytes[4] & 8) ? 8 : 0);
    Bytes field; word(field, id);
    bytes.insert(bytes.begin() + at, field.begin(), field.end());
    bytes[4] |= 1;
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
                check(sup_lz4_decode(&memory,read_mem,nullptr,write_mem,nullptr,&result)==0,"benchmark adapter");
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
        auto high=frame(input,7,true,true,true,true,12);
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
        const auto unchecked=frame(input,4,false,false,true,false);
        Bytes partial=standard;partial.insert(partial.end(),unchecked.begin(),unchecked.end());
        check(decode(partial,double_input,31).content_checked_frames==1,"partial content checksum coverage");
        save(root/L"concat_partial.bin",partial);
        Bytes prefix=standard;prefix.resize(prefix.size()+29,0x88);save(root/L"prefix_carrier.dat",prefix);
        auto empty=frame({},4,false,true,true,true);decode(empty,{});save(root/L"empty.lz4",empty);
        auto damaged=standard;damaged.back()^=1;decode(damaged,{},4096,SUP_LZ4_CHECKSUM);save(root/L"bad_content.lz4",damaged);
        auto bad_header=standard;bad_header[14]^=1;decode(bad_header,{},31,SUP_LZ4_CHECKSUM);save(root/L"bad_header.lz4",bad_header);
        auto bad_block=standard;bad_block[19]^=1;decode(bad_block,{},31,SUP_LZ4_CHECKSUM);save(root/L"bad_block.lz4",bad_block);
        auto truncated=standard;truncated.pop_back();decode(truncated,{},4096,SUP_LZ4_TRUNCATED);save(root/L"truncated.lz4",truncated);
        // Unsupported historical magic is never recognized by SunPack.
        const Bytes old{2,0x21,0x4c,0x18,6,0,0,0,0x50,'h','e','l','l','o'};
        decode(old,{},31,SUP_LZ4_DATA);save(root/L"unsupported_legacy.bin",old);
        Bytes old_carrier(1031,0x89);old_carrier.insert(old_carrier.end(),old.begin(),old.end());
        old_carrier.resize(old_carrier.size()+29,0x88);save(root/L"unsupported_legacy_carrier.dat",old_carrier);
        for (unsigned int id : {0U,123U,0xffffffffU}) {
            const auto unsupported=with_dict_id(standard,id);
            decode(unsupported,{},31,SUP_LZ4_UNSUPPORTED);
            CMyComPtr<ICompressCoder> coder;
            check(CreateCoder_Id(EXTERNAL_CODECS_VARS_G 0x04F71104,false,coder)==S_OK && coder,"unsupported codec registered");
            auto *streams=new CodecStreams(unsupported);CMyComPtr<ISequentialInStream> owner=streams;
            const UInt64 packed_size=unsupported.size(), output_size=input.size();
            check(coder->Code(streams,streams,&packed_size,&output_size,streams)==E_NOTIMPL,"codec unsupported status");
            save(root/(L"unsupported_id_"+std::to_wstring(id)+L".lz4"),unsupported);
        }
        auto unsupported_carrier=Bytes(1031,0x89);const auto unsupported=with_dict_id(standard,123);
        unsupported_carrier.insert(unsupported_carrier.end(),unsupported.begin(),unsupported.end());
        unsupported_carrier.resize(unsupported_carrier.size()+29,0x88);save(root/L"unsupported_id_carrier.dat",unsupported_carrier);
        save(root/L"unsupported_id.tar.lz4",with_dict_id(frame(tar(Bytes{'h','e','l','l','o','\n'}),4,true,true,true,true),123));
        // Structurally valid compressed block with an invalid back-reference.
        // No off-band dependency diagnosis: this is an ordinary data error.
        Bytes bad_data=frame({},4,false,false,false,false);
        Bytes bad_block_data;word(bad_block_data,3);bad_block_data.insert(bad_block_data.end(),{0,0,0});
        bad_data.insert(bad_data.begin()+7,bad_block_data.begin(),bad_block_data.end());
        decode(bad_data,{},31,SUP_LZ4_DATA);save(root/L"bad_data.lz4",bad_data);
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
        const auto split=standard.size()/2;save(root/L"split.any.001",Bytes(standard.begin(),standard.begin()+split));save(root/L"split.any.002",Bytes(standard.begin()+split,standard.end()));
        auto extracted=sunpack::sevenzip::extract_archive_with_parts((root/L"frame_7_15.lz4").wstring(),{},L"lz4",L"",(root/L"worker_output").wstring(),L"",nullptr,false);
        if (!extracted.command_ok) std::cerr<<"worker: "<<extracted.message<<" kind="<<extracted.failure_kind<<" hr="<<extracted.hresult<<" op="<<extracted.operation_result<<"\n";
        check(extracted.command_ok&&extracted.has_stream_receipt&&extracted.stream_receipt.content_checked_frames==1,"worker extraction");
        check(extracted.output_trace.items.size()==1&&!extracted.output_trace.items[0].crc_verified,"no fake CRC32");
        const auto &output_item=extracted.output_trace.items[0];
        std::ifstream actual(root/L"worker_output"/output_item.output_path,std::ios::binary);
        Bytes extracted_bytes((std::istreambuf_iterator<char>(actual)),std::istreambuf_iterator<char>());
        check(extracted_bytes==input,"finalized worker output content");
        Memory cancelled{&standard};cancelled.cancel=true;sup_lz4_result cancelled_result{};
        check(sup_lz4_decode(&cancelled,read_mem,nullptr,write_mem,progress_mem,&cancelled_result)==SUP_LZ4_CANCELLED,"cancellation");
        std::cout<<"LZ4: "<<cases<<" frame combinations, fragmentation, concatenation, unsupported inputs, checksums, cancellation and worker passed\n";
        return 0;
    } catch(const std::exception &e) {std::cerr<<e.what()<<"\n";return 1;}
}
