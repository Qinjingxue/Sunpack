#include "range_editor.hpp"
#include <algorithm>
#include <limits>
#include <regex>
#include <cstdio>
#include <cctype>

namespace spg {
namespace {
constexpr uint64_t factors[]={1,1024,1024*1024,1024ull*1024*1024,1024ull*1024*1024*1024};
std::string trim_range(std::string text) {
    auto first=text.find_first_not_of(" \t\r\n");
    return first==std::string::npos?"":text.substr(first,text.find_last_not_of(" \t\r\n")-first+1);
}
uint64_t bytes(const std::string& text,int unit) {
    if(unit<0 || unit>4 || text.empty()) throw std::runtime_error("rangeNumber");
    uint64_t value=0;
    for(auto c:text) {
        if(c<'0'||c>'9'||value>(std::numeric_limits<uint64_t>::max()-(c-'0'))/10) throw std::runtime_error("rangeNumber");
        value=value*10+c-'0';
    }
    if(value>std::numeric_limits<uint64_t>::max()/factors[unit]) throw std::runtime_error("rangeNumber");
    return value*factors[unit];
}
std::string date_value(const std::string& text) {
    SYSTEMTIME value{};
    if(!range_datetime(text,value)) throw std::runtime_error("rangeDate");
    return range_datetime_text(value);
}
}
bool range_datetime(const std::string& text,SYSTEMTIME& value) {
    if(text.size()>16) return false;
    static const std::regex pattern(R"((\d{4})-?(\d{2})-?(\d{2})(?:[ T](\d{2}):(\d{2}))?)");
    std::smatch match;
    if(!std::regex_match(text,match,pattern)) return false;
    value={}; value.wYear=WORD(std::stoi(match[1])); value.wMonth=WORD(std::stoi(match[2])); value.wDay=WORD(std::stoi(match[3]));
    if(match[4].matched) { value.wHour=WORD(std::stoi(match[4])); value.wMinute=WORD(std::stoi(match[5])); }
    if(value.wYear<1601 || value.wYear>9999 || value.wMonth<1 || value.wMonth>12 || value.wHour>23 || value.wMinute>59) return false;
    const int days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap=value.wYear%4==0 && (value.wYear%100!=0 || value.wYear%400==0);
    if(value.wDay<1 || value.wDay>days[value.wMonth-1]+(value.wMonth==2 && leap)) return false;
    return true;
}
std::string range_datetime_text(const SYSTEMTIME& value) {
    char text[32]; std::snprintf(text,sizeof(text),"%04u%02u%02u %02u:%02u",value.wYear,value.wMonth,value.wDay,value.wHour,value.wMinute);
    return text;
}
std::string range_expression(const Json& range,bool datetime) {
    auto lower=trim_range(range.at("lower").get<std::string>()), upper=trim_range(range.at("upper").get<std::string>());
    auto lo=range.at("lowerOp").get<int>(), hi=range.at("upperOp").get<int>();
    if((lo!=0 && lo!=1)||(hi!=0 && hi!=1)) throw std::runtime_error("validation");
    uint64_t low=0,high=0;
    if(datetime) { if(!lower.empty()) lower=date_value(lower); if(!upper.empty()) upper=date_value(upper); }
    else {
        if(!lower.empty()) { low=bytes(lower,range.at("lowerUnit")); lower=std::to_string(low); }
        if(!upper.empty()) { high=bytes(upper,range.at("upperUnit")); upper=std::to_string(high); }
    }
    if(!lower.empty() && !upper.empty()) {
        bool greater=datetime?lower>upper:low>high, equal=datetime?lower==upper:low==high;
        if(greater || (equal && (!lo || !hi))) throw std::runtime_error("rangeOrder");
    }
    std::string variable=datetime?"d":"r", result;
    if(!lower.empty()) result=lower+(lo?" <= ":" < ")+variable;
    if(!upper.empty()) result+=(result.empty()?variable:std::string())+(hi?" <= ":" < ")+upper;
    return result;
}
Json range_editor(const std::string& text,bool datetime) {
    Json result={{"supported",true},{"lower",""},{"upper",""},{"lowerOp",1},{"upperOp",0},{"lowerUnit",0},{"upperUnit",0}};
    try {
        auto input=trim_range(text);
        if(input.empty()) return result;
        // Longer/custom expressions stay in the lossless text editor. Bound
        // the small presentation parser independently of external file size.
        if(input.size()>256) throw std::runtime_error("advanced");
        static const std::regex comparison(R"((<=|>=|==|=|<|>))");
        std::vector<std::string> values,ops;
        size_t at=0;
        for(std::sregex_iterator it(input.begin(),input.end(),comparison),end;it!=end;++it) {
            values.push_back(trim_range(input.substr(at,it->position()-at))); ops.push_back(it->str()); at=it->position()+it->length();
        }
        values.push_back(trim_range(input.substr(at)));
        if(ops.empty() || ops.size()>2) throw std::runtime_error("advanced");
        for(size_t i=0;i<ops.size();++i) {
            auto variable=datetime?"d":"r";
            auto left=values[i],right=values[i+1],op=ops[i];
            std::transform(left.begin(),left.end(),left.begin(),[](unsigned char c){return char(tolower(c));});
            std::transform(right.begin(),right.end(),right.begin(),[](unsigned char c){return char(tolower(c));});
            bool forward=left==variable;
            if(forward==(right==variable) || op=="=" || op=="==") throw std::runtime_error("advanced");
            if(!forward) op[0]=op[0]=='<'?'>':'<';
            std::string side=op[0]=='>'?"lower":"upper",value=forward?values[i+1]:values[i];
            if(result[side]!="") throw std::runtime_error("advanced");
            int unit=0;
            if(datetime) {
                auto date=date_value(value);
                value=date.substr(0,4)+"-"+date.substr(4,2)+"-"+date.substr(6);
            }
            else {
                static const std::regex size(R"(([0-9]+)\s*([a-zA-Z]*))"); std::smatch match;
                if(!std::regex_match(value,match,size)) throw std::runtime_error("advanced");
                auto suffix=match[2].str(); std::transform(suffix.begin(),suffix.end(),suffix.begin(),[](unsigned char c){return char(tolower(c));});
                if(suffix.empty()||suffix=="b"||suffix=="byte"||suffix=="bytes") unit=0;
                else if(suffix=="k"||suffix=="kb"||suffix=="kib") unit=1;
                else if(suffix=="m"||suffix=="mb"||suffix=="mib") unit=2;
                else if(suffix=="g"||suffix=="gb"||suffix=="gib") unit=3;
                else if(suffix=="t"||suffix=="tb"||suffix=="tib") unit=4;
                else throw std::runtime_error("advanced");
                auto count=bytes(match[1],unit);
                if(unit==0 && count) for(int candidate=4;candidate>0;--candidate) if(count%factors[candidate]==0) { unit=candidate; break; }
                value=std::to_string(count/factors[unit]);
            }
            result[side]=value; result[side+"Op"]=op.size()==2?1:0; result[side+"Unit"]=unit;
        }
        range_expression(result,datetime);
    } catch(const std::exception&) { result["supported"]=false; }
    return result;
}
}
