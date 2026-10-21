#include "platform.hpp"
#include <cassert>
#include <memory>

// Replace SCM imports only in the file-contract executable. Production code
// still calls Win32 directly; no test switches or fake services are installed.
namespace {
struct Registration {
    bool database, open=true;
    SERVICE_NOTIFYW* notification=nullptr;
    DWORD mask=0;
};
struct Delivery {
    SERVICE_NOTIFYW* notification;
    DWORD status, triggered, state;
    bool complete=false;
};
std::vector<std::unique_ptr<Registration>> handles;
std::vector<std::unique_ptr<Delivery>> deliveries;
bool installed=false, deleting=false, in_callback=false, deliver_inside_rpc=false;
DWORD state=SERVICE_STOPPED, next_state=0, query_error=0, subscribe_error=0;
unsigned queries=0;
void CALLBACK deliver(ULONG_PTR parameter) {
    auto& delivery=*reinterpret_cast<Delivery*>(parameter);
    auto* notification=delivery.notification;
    notification->dwNotificationStatus=delivery.status;
    notification->dwNotificationTriggered=delivery.triggered;
    notification->ServiceStatus.dwCurrentState=delivery.state;
    if(delivery.triggered&(SERVICE_NOTIFY_CREATED|SERVICE_NOTIFY_DELETED)) {
        notification->pszServiceNames=static_cast<wchar_t*>(LocalAlloc(LPTR,4*sizeof(wchar_t)));
        assert(notification->pszServiceNames);
    }
    in_callback=true;
    notification->pfnNotifyCallback(notification);
    in_callback=false;
    assert(!notification->pszServiceNames);
    delivery.complete=true;
}
void queue(Registration& handle,DWORD triggered,DWORD error=ERROR_SUCCESS) {
    if(!handle.open || !handle.notification || !(handle.mask&triggered)) return;
    auto delivery=std::make_unique<Delivery>(Delivery{handle.notification,error,triggered,state});
    handle.notification=nullptr;
    assert(QueueUserAPC(deliver,GetCurrentThread(),reinterpret_cast<ULONG_PTR>(delivery.get())));
    deliveries.push_back(std::move(delivery));
}
void transition(DWORD value) {
    state=value;
    for(auto& handle:handles) if(!handle->database) queue(*handle,1u<<(value-1));
}
void database_change(DWORD mask) {
    for(auto& handle:handles) if(handle->database) queue(*handle,mask);
}
Registration& registration(SC_HANDLE handle) {
    assert(!in_callback); // SCM/RPC work must never run inside an APC callback.
    auto& result=*reinterpret_cast<Registration*>(handle); assert(result.open); return result;
}
SC_HANDLE make_handle(bool database) {
    auto handle=std::make_unique<Registration>(); handle->database=database;
    auto result=reinterpret_cast<SC_HANDLE>(handle.get()); handles.push_back(std::move(handle)); return result;
}
SC_HANDLE WINAPI open_manager(LPCWSTR,LPCWSTR,DWORD access) {
    assert(!in_callback && access==(SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE));
    return make_handle(true);
}
SC_HANDLE WINAPI open_service(SC_HANDLE manager,LPCWSTR name,DWORD access) {
    assert(registration(manager).database && std::wstring(name)==L"SunPackWatchBroker" && access==SERVICE_QUERY_STATUS);
    if(!installed || deleting) { SetLastError(deleting?ERROR_SERVICE_MARKED_FOR_DELETE:ERROR_SERVICE_DOES_NOT_EXIST); return nullptr; }
    return make_handle(false);
}
BOOL WINAPI close_service(SC_HANDLE handle) {
    auto& entry=registration(handle); entry.open=false; entry.notification=nullptr; return TRUE;
}
BOOL WINAPI query_status(SC_HANDLE handle,SC_STATUS_TYPE type,LPBYTE buffer,DWORD size,LPDWORD bytes) {
    assert(!registration(handle).database && type==SC_STATUS_PROCESS_INFO && size==sizeof(SERVICE_STATUS_PROCESS));
    ++queries;
    if(query_error) { SetLastError(query_error); query_error=0; return FALSE; }
    auto* status=reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer);
    *status={}; status->dwCurrentState=state; *bytes=sizeof(*status);
    if(next_state) { state=next_state; next_state=0; }
    return TRUE;
}
DWORD WINAPI subscribe(SC_HANDLE handle,DWORD mask,PSERVICE_NOTIFYW notification) {
    auto& entry=registration(handle);
    assert(!entry.notification && notification->dwVersion==SERVICE_NOTIFY_STATUS_CHANGE);
    if(subscribe_error) { auto error=subscribe_error; subscribe_error=0; return error; }
    entry.notification=notification; entry.mask=mask;
    if(!entry.database) queue(entry,1u<<(state-1));
    if(deliver_inside_rpc) SleepEx(0,TRUE);
    return ERROR_SUCCESS;
}
void dispatch(spg::ServiceMonitor& monitor) {
    spg::Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    HANDLE waits[]={stop};
    assert(WaitForMultipleObjectsEx(1,waits,FALSE,10000,TRUE)==WAIT_IO_COMPLETION);
    assert(monitor.changed());
}
unsigned open_handles() {
    unsigned count=0; for(auto& handle:handles) if(handle->open) ++count; return count;
}
}

// MSVC emits indirect calls through these import slots. Defining them in this
// test executable intercepts only the five SCM APIs used by ServiceMonitor.
extern "C" {
decltype(&OpenSCManagerW) __imp_OpenSCManagerW=open_manager;
decltype(&OpenServiceW) __imp_OpenServiceW=open_service;
decltype(&CloseServiceHandle) __imp_CloseServiceHandle=close_service;
decltype(&QueryServiceStatusEx) __imp_QueryServiceStatusEx=query_status;
decltype(&NotifyServiceStatusChangeW) __imp_NotifyServiceStatusChangeW=subscribe;
}

void service_notifications() {
    {
        spg::ServiceMonitor monitor;
        assert(!monitor.running()); // Not installed: database notifications, not retries.
        database_change(SERVICE_NOTIFY_CREATED); dispatch(monitor);
        assert(!monitor.running()); // Another service's creation must not mark ours running.
        installed=true; database_change(SERVICE_NOTIFY_CREATED); dispatch(monitor);
        next_state=SERVICE_RUNNING; deliver_inside_rpc=true;
        assert(!monitor.running()); // State changes between query and subscribe.
        assert(monitor.changed()); // APC was delivered inside the subscribing RPC.
        deliver_inside_rpc=false;
        assert(monitor.running() && !monitor.changed());
        auto before=queries;
        assert(monitor.running() && queries==before); // A live subscription needs no requery.
        transition(SERVICE_STOP_PENDING); dispatch(monitor); assert(!monitor.running());
        transition(SERVICE_STOPPED); dispatch(monitor); assert(!monitor.running());
        transition(SERVICE_RUNNING); dispatch(monitor); assert(monitor.running());

        transition(SERVICE_STOPPED); dispatch(monitor);
        subscribe_error=ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;
        assert(!monitor.running()); // Reconnect once and restore the subscription.
        transition(SERVICE_RUNNING); dispatch(monitor); assert(monitor.running());
        auto opened=handles.size();
        for(auto& handle:handles) if(!handle->database) queue(*handle,SERVICE_NOTIFY_DELETE_PENDING,ERROR_SERVICE_NOTIFY_CLIENT_LAGGING);
        dispatch(monitor); assert(monitor.running() && handles.size()>opened);
        for(auto& handle:handles) if(!handle->database) queue(*handle,SERVICE_NOTIFY_DELETE_PENDING);
        deleting=true; dispatch(monitor); assert(!monitor.running());
        installed=deleting=false; database_change(SERVICE_NOTIFY_DELETED); dispatch(monitor);
        assert(!monitor.running());
        installed=true; database_change(SERVICE_NOTIFY_CREATED); dispatch(monitor);
        assert(monitor.running()); // Reinstallation while the GUI remains open.

        transition(SERVICE_STOPPED); dispatch(monitor); query_error=ERROR_ACCESS_DENIED;
        bool failed=false;
        try { monitor.running(); } catch(const spg::WinError& error) { failed=error.code==ERROR_ACCESS_DENIED; }
        assert(failed && !monitor.changed() && !open_handles());
        assert(!monitor.running()); // An explicit UI action can retry after an error.
        transition(SERVICE_RUNNING); // Exit with an APC already queued.
    }
    assert(!open_handles());
    for(auto& delivery:deliveries) assert(delivery->complete);
    installed=false;
    {
        spg::ServiceMonitor monitor; assert(!monitor.running());
        database_change(SERVICE_NOTIFY_CREATED); // Database callback buffer also outlives cancellation.
    }
    assert(!open_handles());
    for(auto& delivery:deliveries) assert(delivery->complete);
    deliveries.clear(); handles.clear();
}
