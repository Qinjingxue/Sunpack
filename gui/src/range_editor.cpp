#include "range_editor.hpp"
#include <algorithm>
#include <limits>
#include <cstdio>

namespace spg {
namespace {
constexpr uint64_t factors[]={1,1024,1024*1024,1024ull*1024*1024,1024ull*1024*1024*1024};
std::string trim(std::string text) {
    auto first=text.find_first_not_of(" \t\r\n");
    return first==std::string::npos?"":text.substr(first,text.find_last_not_of(" \t\r\n")-first+1);
}
bool calendar_valid(const SYSTEMTIME& value) {
    if(value.wYear<1 || value.wYear>9999 || value.wMonth<1 || value.wMonth>12 || value.wHour>23 || value.wMinute>59 || value.wSecond>59) return false;
    const int days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap=value.wYear%4==0 && (value.wYear%100!=0 || value.wYear%400==0);
    return value.wDay>=1 && value.wDay<=days[value.wMonth-1]+(value.wMonth==2 && leap);
}
uint64_t integer(const std::string& digits) {
    if(digits.empty()) throw std::runtime_error("rangeNumber");
    uint64_t value=0;
    for(auto c:digits) {
        if(c<'0'||c>'9'||value>(std::numeric_limits<uint64_t>::max()-(c-'0'))/10) throw std::runtime_error("rangeNumber");
        value=value*10+c-'0';
    }
    return value;
}
uint64_t size_value(std::string text,int unit,bool lower) {
    text=trim(text);
    if(unit<0 || unit>4 || text.empty() || text.size()>128) throw std::runtime_error("rangeNumber");
    auto dot=text.find('.'); size_t fractional=dot==std::string::npos?0:text.size()-dot-1;
    if(dot!=std::string::npos) {
        if(dot==0 || !fractional) throw std::runtime_error("rangeNumber");
        text.erase(dot,1);
    }
    if(text.find_first_not_of("0123456789")!=std::string::npos) throw std::runtime_error("rangeNumber");
    // Decimal string arithmetic avoids both JS Number and MSVC double rounding.
    for(int i=0;i<unit;++i) {
        unsigned carry=0;
        for(auto it=text.rbegin();it!=text.rend();++it) { auto n=unsigned(*it-'0')*1024+carry; *it=char('0'+n%10); carry=n/10; }
        while(carry) { text.insert(text.begin(),char('0'+carry%10)); carry/=10; }
    }
    bool remainder=false;
    if(fractional) {
        if(text.size()<=fractional) { remainder=text.find_first_not_of('0')!=std::string::npos; text="0"; }
        else { auto at=text.size()-fractional; remainder=text.find_first_not_of('0',at)!=std::string::npos; text.resize(at); }
    }
    auto value=integer(text);
    if(lower && remainder) { if(value==std::numeric_limits<uint64_t>::max()) throw std::runtime_error("rangeNumber"); ++value; }
    return value;
}
SYSTEMTIME utc_local(const SYSTEMTIME& utc,const DYNAMIC_TIME_ZONE_INFORMATION* zone) {
    SYSTEMTIME local{};
    if(!SystemTimeToTzSpecificLocalTimeEx(zone,&utc,&local)) throw std::runtime_error("rangeDate");
    return local;
}
std::string time_value(const Json& form,const std::string& side,const DYNAMIC_TIME_ZONE_INFORMATION* zone) {
    auto text=trim(form.at(side).get<std::string>());
    if(text==form.value(side+"OriginalLocal",std::string()) && !form.value(side+"Utc",std::string()).empty())
        return form.at(side+"Utc"); // Preserve an untouched bound across a timezone/DST change.
    SYSTEMTIME local{},utc{};
    if(!range_datetime(text,local) || !TzSpecificLocalTimeToSystemTimeEx(zone,&local,&utc)) throw std::runtime_error("rangeDate");
    if(range_datetime_text(utc_local(utc,zone))!=range_datetime_text(local)) throw std::runtime_error("rangeDate");
    return range_utc_text(range_calendar_seconds(utc)/60);
}
}
int64_t range_calendar_seconds(const SYSTEMTIME& value) {
    if(!calendar_valid(value)) throw std::runtime_error("rangeDate");
    int year=value.wYear-(value.wMonth<=2),month=value.wMonth;
    const int era=(year>=0?year:year-399)/400;
    const unsigned yoe=unsigned(year-era*400), doy=(153*(month+(month>2?-3:9))+2)/5+value.wDay-1;
    return (int64_t(era)*146097+yoe*365+yoe/4-yoe/100+doy-719468)*86400+value.wHour*3600+value.wMinute*60+value.wSecond;
}
SYSTEMTIME range_calendar_time(int64_t seconds) {
    int64_t day=seconds/86400,remainder=seconds%86400;
    if(remainder<0) { remainder+=86400; --day; }
    day+=719468;
    const int64_t era=(day>=0?day:day-146096)/146097;
    const unsigned doe=unsigned(day-era*146097),yoe=(doe-doe/1460+doe/36524-doe/146096)/365;
    int year=int(yoe+era*400); const unsigned doy=doe-(365*yoe+yoe/4-yoe/100),mp=(5*doy+2)/153;
    const unsigned d=doy-(153*mp+2)/5+1,m=mp+(mp<10?3:-9); year+=m<=2;
    if(year<1 || year>9999) throw std::runtime_error("rangeDate");
    SYSTEMTIME value{}; value.wYear=WORD(year); value.wMonth=WORD(m); value.wDay=WORD(d);
    value.wHour=WORD(remainder/3600); value.wMinute=WORD(remainder/60%60); value.wSecond=WORD(remainder%60); return value;
}
bool range_datetime(const std::string& text,SYSTEMTIME& value) {
    if(text.size()!=16 || text[4]!='-' || text[7]!='-' || text[10]!=' ' || text[13]!=':') return false;
    for(size_t i=0;i<text.size();++i) if(i!=4 && i!=7 && i!=10 && i!=13 && (text[i]<'0'||text[i]>'9')) return false;
    value={}; value.wYear=WORD(std::stoi(text.substr(0,4))); value.wMonth=WORD(std::stoi(text.substr(5,2))); value.wDay=WORD(std::stoi(text.substr(8,2)));
    value.wHour=WORD(std::stoi(text.substr(11,2))); value.wMinute=WORD(std::stoi(text.substr(14,2))); return calendar_valid(value);
}
std::string range_datetime_text(const SYSTEMTIME& value) {
    char text[32]; std::snprintf(text,sizeof(text),"%04u-%02u-%02u %02u:%02u",value.wYear,value.wMonth,value.wDay,value.wHour,value.wMinute); return text;
}
int64_t range_utc_minutes(const std::string& text) {
    if(text.size()!=17 || text[10]!='T' || text[16]!='Z') throw std::runtime_error("rangeDate");
    auto local=text.substr(0,16); local[10]=' '; SYSTEMTIME value{};
    if(!range_datetime(local,value)) throw std::runtime_error("rangeDate");
    return range_calendar_seconds(value)/60;
}
std::string range_utc_text(int64_t minutes) {
    auto value=range_datetime_text(range_calendar_time(minutes*60)); value[10]='T'; return value+'Z';
}
void validate_range_module(const Json& module,bool datetime) {
    if(!module.is_object() || module.value("name",std::string())!=(datetime?"mtime_range":"size_range")) throw std::runtime_error("validation");
    const std::string low=datetime?"start_utc":"min_bytes", high=datetime?"end_utc":"max_bytes";
    for(auto it=module.begin();it!=module.end();++it)
        if(it.key()!="name" && it.key()!="enabled" && it.key()!=low && it.key()!=high) throw std::runtime_error("rangeFormat");
    if(module.contains("enabled") && !module["enabled"].is_boolean()) throw std::runtime_error("validation");
    Json lower=module.value(low,Json()),upper=module.value(high,Json());
    for(auto& value:{lower,upper}) if(!value.is_null()) {
        if(datetime) { if(!value.is_string()) throw std::runtime_error("rangeDate"); range_utc_minutes(value.get<std::string>()); }
        else if(!value.is_number_unsigned() && !(value.is_number_integer() && value.get<int64_t>()>=0)) throw std::runtime_error("rangeNumber");
    }
    if(!lower.is_null() && !upper.is_null()) {
        if(datetime?(range_utc_minutes(lower.get<std::string>())>=range_utc_minutes(upper.get<std::string>())):lower.get<uint64_t>()>upper.get<uint64_t>()) throw std::runtime_error("rangeOrder");
    }
}
Json range_editor(const Json& module,const DYNAMIC_TIME_ZONE_INFORMATION* zone) {
    bool datetime=module.value("name",std::string())=="mtime_range"; validate_range_module(module,datetime);
    Json result={{"enabled",module.value("enabled",false)},{"lower",""},{"upper",""},{"lowerUnit",0},{"upperUnit",0}};
    for(auto side:{"lower","upper"}) {
        auto value=module.value(datetime?(std::string(side)=="lower"?"start_utc":"end_utc"):(std::string(side)=="lower"?"min_bytes":"max_bytes"),Json());
        if(value.is_null()) continue;
        if(datetime) {
            auto utc=value.get<std::string>(); auto local=range_datetime_text(utc_local(range_calendar_time(range_utc_minutes(utc)*60),zone));
            result[side]=local; result[std::string(side)+"OriginalLocal"]=local; result[std::string(side)+"Utc"]=utc;
        } else {
            auto bytes=value.get<uint64_t>(); int unit=0;
            if(bytes) for(int candidate=4;candidate>0;--candidate) if(bytes%factors[candidate]==0) {unit=candidate;break;}
            result[side]=std::to_string(bytes/factors[unit]); result[std::string(side)+"Unit"]=unit;
        }
    }
    return result;
}
Json range_configuration(const Json& form,bool datetime,const DYNAMIC_TIME_ZONE_INFORMATION* zone) {
    Json result={{"name",datetime?"mtime_range":"size_range"},{"enabled",form.at("enabled")}};
    const std::string low=datetime?"start_utc":"min_bytes",high=datetime?"end_utc":"max_bytes";
    result[low]=Json(); result[high]=Json();
    for(auto side:{"lower","upper"}) {
        if(trim(form.at(side).get<std::string>()).empty()) continue;
        auto key=std::string(side)=="lower"?low:high;
        result[key]=datetime?Json(time_value(form,side,zone)):Json(size_value(form.at(side),form.at(std::string(side)+"Unit"),std::string(side)=="lower"));
    }
    validate_range_module(result,datetime); return result;
}
}
