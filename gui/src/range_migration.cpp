#include "range_migration.hpp"
#include "range_editor.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <limits>
#include <optional>
#include <regex>

namespace spg {
namespace {
std::string trim(std::string s) { auto a=s.find_first_not_of(" \t\r\n"); return a==std::string::npos?"":s.substr(a,s.find_last_not_of(" \t\r\n")-a+1); }
// Only the installer needs signed/unbounded legacy integers. Decimal strings
// avoid narrowing user JSON before intersecting with the native uint64 domain.
struct Integer {
    std::string digits="0"; bool negative=false;
    explicit Integer(std::string text="0") {
        text=trim(text);
        if(!text.empty() && (text[0]=='-'||text[0]=='+')) {negative=text[0]=='-';text.erase(0,1);}
        if(text.empty()) throw std::runtime_error("rangeMigration");
        std::string cleaned;
        for(size_t i=0;i<text.size();++i) {
            if(text[i]=='_' && i && i+1<text.size() && isdigit(static_cast<unsigned char>(text[i-1])) && isdigit(static_cast<unsigned char>(text[i+1]))) continue;
            if(text[i]<'0'||text[i]>'9') throw std::runtime_error("rangeMigration");
            cleaned+=text[i];
        }
        auto at=cleaned.find_first_not_of('0'); digits=at==std::string::npos?"0":cleaned.substr(at); if(digits=="0") negative=false;
    }
    std::string text() const {return (negative?"-":"")+digits;}
    int compare(const Integer& other) const {
        if(negative!=other.negative) return negative?-1:1;
        int c=digits.size()==other.digits.size()?(digits==other.digits?0:digits<other.digits?-1:1):digits.size()<other.digits.size()?-1:1;
        return negative?-c:c;
    }
    void step(int direction) {
        if((direction>0)==!negative) {
            auto i=digits.size(); while(i && digits[i-1]=='9') digits[--i]='0';
            if(i) ++digits[i-1]; else digits.insert(digits.begin(),'1');
        } else if(digits=="0") {digits="1";negative=true;}
        else {
            auto i=digits.size(); while(i && digits[i-1]=='0') digits[--i]='9'; if(i) --digits[i-1];
            auto at=digits.find_first_not_of('0'); digits=at==std::string::npos?"0":digits.substr(at); if(digits=="0") negative=false;
        }
    }
    void multiply(unsigned factor) {
        unsigned carry=0;
        for(auto it=digits.rbegin();it!=digits.rend();++it) {auto n=unsigned(*it-'0')*factor+carry;*it=char('0'+n%10);carry=n/10;}
        while(carry) {digits.insert(digits.begin(),char('0'+carry%10));carry/=10;}
        if(digits=="0") negative=false;
    }
    uint64_t native() const {return std::stoull(digits);}
    uint64_t quotient(uint64_t divisor) const {
        uint64_t result=0,remainder=0;
        for(char c:digits) {remainder=remainder*10+c-'0';result=result*10+remainder/divisor;remainder%=divisor;}
        return result;
    }
};
Integer floating(double value) {
    if(!std::isfinite(value)) throw std::runtime_error("rangeMigration");
    char text[384]; std::snprintf(text,sizeof(text),"%.0f",std::trunc(value)); return Integer(text);
}
Integer size_operand(std::string value) {
    value=trim(value); size_t at=0;
    while(at<value.size() && ((value[at]>='0' && value[at]<='9') || value[at]=='.')) ++at;
    auto number=value.substr(0,at),unit=trim(value.substr(at));
    std::transform(unit.begin(),unit.end(),unit.begin(),[](unsigned char c){return char(tolower(c));});
    int power=-1;
    if(unit.empty()||unit=="b"||unit=="byte"||unit=="bytes") power=0;
    else for(int i=1;i<=4;++i) {std::string c(1,"kmgt"[i-1]);if(unit==c || unit==c+"b" || unit==c+"ib") power=i;}
    if(number.empty() || power<0) return Integer(value); // Python int() fallback.
    if(number.find('.')!=std::string::npos) {
        static const std::regex decimal(R"([0-9]+\.[0-9]+)");
        if(number.size()>128 || !std::regex_match(number,decimal)) throw std::runtime_error("rangeMigration");
        return floating(std::stod(number)*std::pow(1024.0,power));
    }
    Integer result(number); for(int i=0;i<power;++i) result.multiply(1024); return result;
}
Integer date_operand(const std::string& raw) {
    auto text=trim(raw);
    // The legacy parser tries compact dates before integer nanoseconds.
    bool compact=text.size()==8 && text.find_first_not_of("0123456789")==std::string::npos;
    if(!compact) {try {return Integer(text);} catch(const std::exception&) {}}
    if(text.size()>96) throw std::runtime_error("rangeMigration");
    static const std::regex pattern(R"(([0-9]{4})-?([0-9]{2})-?([0-9]{2})(?:[ T]([0-9]{2}):?([0-9]{2})(?::?([0-9]{2})(?:[.,]([0-9]+))?)?)?(Z|[+-][0-9]{2}(?::?[0-9]{2})?)?)");
    std::smatch m;
    try {
        if(!std::regex_match(text,m,pattern)) throw std::runtime_error("rangeMigration");
        SYSTEMTIME value{}; value.wYear=WORD(std::stoi(m[1]));value.wMonth=WORD(std::stoi(m[2]));value.wDay=WORD(std::stoi(m[3]));
        if(m[4].matched) {value.wHour=WORD(std::stoi(m[4]));value.wMinute=WORD(std::stoi(m[5]));}
        if(m[6].matched) value.wSecond=WORD(std::stoi(m[6]));
        auto seconds=range_calendar_seconds(value); auto zone=m[8].str();
        if(zone.empty()) {
            std::tm local{}; local.tm_year=value.wYear-1900;local.tm_mon=value.wMonth-1;local.tm_mday=value.wDay;
            local.tm_hour=value.wHour;local.tm_min=value.wMinute;local.tm_sec=value.wSecond;local.tm_isdst=-1;
            auto native=_mktime64(&local);
            if(native!=-1) seconds=native;
            else {SYSTEMTIME utc{};if(!TzSpecificLocalTimeToSystemTimeEx(nullptr,&value,&utc)) throw std::runtime_error("rangeMigration");seconds=range_calendar_seconds(utc);}
        } else if(zone!="Z") {
            auto offset=zone.substr(1); offset.erase(std::remove(offset.begin(),offset.end(),':'),offset.end());
            int hours=std::stoi(offset.substr(0,2)),minutes=offset.size()>2?std::stoi(offset.substr(2,2)):0;
            if(hours>23 || minutes>59) throw std::runtime_error("rangeMigration");
            seconds+=(zone[0]=='+'?-1:1)*(hours*3600+minutes*60);
        }
        auto fraction=m[7].str(); if(fraction.size()>6) fraction.resize(6); while(fraction.size()<6) fraction+='0';
        return floating((double(seconds)+std::stoi(fraction)/1000000.0)*1000000000.0);
    } catch(const std::exception&) {if(compact) return Integer(text);throw;}
}
using Optional=std::optional<Integer>;
struct Legacy {
    std::array<Optional,5> fields; // gt, gte, lt, lte, eq: keep legacy merge precedence.
    void merge(size_t kind,const Integer& value) {
        auto& old=fields[kind];
        if(!old || kind==4 || (kind<2?value.compare(*old)>0:value.compare(*old)<0)) old=value;
    }
    void expression(const std::string& input,bool datetime) {
        auto text=trim(input); if(text.empty()) return;
        std::vector<std::string> operands,operators;
        size_t start=0,at=0;
        while(at<text.size()) {
            if(text[at]!='<' && text[at]!='>' && text[at]!='=') {++at;continue;}
            operands.push_back(trim(text.substr(start,at-start)));
            auto begin=at++; if(at<text.size() && text[at]=='=') ++at;
            operators.push_back(text.substr(begin,at-begin));start=at;
        }
        operands.push_back(trim(text.substr(start)));
        if(operators.empty()) throw std::runtime_error("rangeMigration");
        for(size_t i=0;i<operators.size();++i) {
            auto variable=[&](std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(tolower(c));});return s==(datetime?"d":"r");};
            bool forward=variable(operands[i]); if(forward==variable(operands[i+1])) throw std::runtime_error("rangeMigration");
            auto op=operators[i]; if(!forward && op[0]!='=') op[0]=op[0]=='<'?'>':'<';
            auto value=datetime?date_operand(forward?operands[i+1]:operands[i]):size_operand(forward?operands[i+1]:operands[i]);
            size_t kind=op==">"?0:op==">="?1:op=="<"?2:op=="<="?3:4;merge(kind,value);
        }
    }
};
const std::array<std::vector<const char*>,5> size_aliases={std::vector<const char*>{"gt","greater_than"},{"gte","greater_than_or_equal","min","minimum"},{"lt","less_than"},{"lte","less_than_or_equal","max","maximum"},{"eq","equal","equals"}};
const std::array<std::vector<const char*>,5> date_aliases={std::vector<const char*>{"gt","greater_than","after"},{"gte","greater_than_or_equal","after_or_equal","since"},{"lt","less_than","before"},{"lte","less_than_or_equal","before_or_equal","until"},{"eq","equal","equals"}};
}
bool migrate_range_module(const Json& old,Json& replacement,const std::function<std::string(const std::string&)>& raw_value) {
    bool datetime=old.at("name")=="mtime_range";
    auto expr=datetime?"date":"range",low=datetime?"start_utc":"min_bytes",high=datetime?"end_utc":"max_bytes";
    auto& aliases=datetime?date_aliases:size_aliases;
    bool legacy=old.contains(expr);
    for(auto& group:aliases) for(auto key:group) legacy=legacy||old.contains(key);
    if(!legacy && (old.contains(low)||old.contains(high)||old.contains("match_none"))) {validate_range_module(old,datetime);return false;}
    Legacy parsed;
    if(old.contains(expr)) {
        const auto& expression=old.at(expr);
        if(!expression.is_null()) parsed.expression(expression.is_string()?expression.get<std::string>():expression.dump(),datetime);
    } else parsed.expression(datetime?"20270101 00:00 > d >= 20240101 00:00":"r > 0 B",datetime);
    for(size_t kind=0;kind<aliases.size();++kind) for(auto key:aliases[kind]) if(old.contains(key)) {
        auto& value=old.at(key);
        if(!value.is_null()) try {
            Integer converted;
            if(value.is_boolean()) converted=Integer(value.get<bool>()?"1":"0");
            else if(value.is_number_float()) converted=floating(value.get<double>());
            else if(value.is_number_integer() || value.is_number_unsigned()) converted=Integer(raw_value(key));
            else if(value.is_string()) converted=datetime?date_operand(value.get<std::string>()):Integer(value.get<std::string>());
            else throw std::runtime_error("rangeMigration");
            parsed.merge(kind,converted);
        } catch(const std::exception&) { /* Invalid explicit legacy values were ignored. */ }
        break; // First present alias wins, even when null/invalid.
    }
    Optional lower,upper; bool configured=false;
    for(size_t kind=0;kind<5;++kind) if(parsed.fields[kind]) {
        configured=true; auto value=*parsed.fields[kind];
        if(kind==0) value.step(1); if(kind==2) value.step(-1);
        if(kind<2 || kind==4) if(!lower || value.compare(*lower)>0) lower=value;
        if(kind==2 || kind==3 || kind==4) if(!upper || value.compare(*upper)<0) upper=value;
    }
    Integer zero,maximum("18446744073709551615");
    bool none=(lower && lower->compare(maximum)>0)||(upper && upper->compare(zero)<0)||(lower && upper && lower->compare(*upper)>0);
    if(lower && lower->compare(zero)<0) lower=zero;
    if(upper && upper->compare(maximum)>0) upper.reset();
    if(configured && !lower && !upper) lower=zero;
    replacement={{"name",datetime?"mtime_range":"size_range"},{"enabled",old.value("enabled",!datetime)},{low,Json()},{high,Json()}};
    if(none) replacement["match_none"]=true;
    else if(datetime) {
        constexpr uint64_t minute=60000000000ull;
        if(lower) replacement[low]=range_utc_text(int64_t(lower->quotient(minute)));
        if(upper) replacement[high]=range_utc_text(int64_t(upper->quotient(minute)+1));
    } else {
        if(lower) replacement[low]=lower->native(); if(upper) replacement[high]=upper->native();
    }
    validate_range_module(replacement,datetime);return true;
}
}
