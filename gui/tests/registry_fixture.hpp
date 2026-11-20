#pragma once
#include <windows.h>
#include <objbase.h>
#include <cassert>
#include <string>
#include <utility>
#include <vector>

inline std::wstring registry_string(const std::wstring& path, const wchar_t* name = nullptr) {
    DWORD bytes=0;
    assert(RegGetValueW(HKEY_CURRENT_USER,path.c_str(),name,RRF_RT_REG_SZ,nullptr,nullptr,&bytes)==ERROR_SUCCESS);
    std::vector<wchar_t> text(bytes/sizeof(wchar_t));
    assert(RegGetValueW(HKEY_CURRENT_USER,path.c_str(),name,RRF_RT_REG_SZ,nullptr,text.data(),&bytes)==ERROR_SUCCESS);
    return text.data();
}

// Redirect HKCU in the test process only. In particular, theme selectors and
// simulated Windows theme changes must never touch the developer's settings.
class RegistryFixture {
    HKEY original_=nullptr, root_=nullptr;
    bool owner_;
public:
    std::wstring path;
    explicit RegistryFixture(std::wstring existing={}) : owner_(existing.empty()), path(std::move(existing)) {
        assert(RegOpenCurrentUser(KEY_ALL_ACCESS,&original_)==ERROR_SUCCESS);
        if(owner_) {
            GUID id{}; assert(SUCCEEDED(CoCreateGuid(&id)));
            wchar_t token[40]; assert(StringFromGUID2(id,token,40));
            path=std::wstring(L"Software\\SunPack.GuiTests.")+token;
            assert(RegCreateKeyExW(original_,path.c_str(),0,nullptr,0,
                KEY_ALL_ACCESS,nullptr,&root_,nullptr)==ERROR_SUCCESS);
        } else assert(RegOpenKeyExW(original_,path.c_str(),0,KEY_ALL_ACCESS,&root_)==ERROR_SUCCESS);
        assert(RegOverridePredefKey(HKEY_CURRENT_USER,root_)==ERROR_SUCCESS);
    }
    ~RegistryFixture() {
        assert(RegOverridePredefKey(HKEY_CURRENT_USER,nullptr)==ERROR_SUCCESS);
        RegCloseKey(root_);
        if(owner_) {
            assert(RegDeleteTreeW(original_,path.c_str())==ERROR_SUCCESS);
        }
        RegCloseKey(original_);
    }
    RegistryFixture(const RegistryFixture&)=delete;
    RegistryFixture& operator=(const RegistryFixture&)=delete;
};
