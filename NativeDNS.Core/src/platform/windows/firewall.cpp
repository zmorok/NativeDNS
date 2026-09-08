#include <nativedns/firewall.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <netfw.h>
#include <oleauto.h>
#include <string>

namespace nd::detail {
namespace {
constexpr wchar_t rule_name[]=L"NativeDNS TCP Interception";

template<class T> struct ComPtr {
    T* value=nullptr;
    ~ComPtr() { if(value) value->Release(); }
    ComPtr() = default;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept:value(other.value) { other.value=nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept { if(this!=&other) { if(value) value->Release(); value=other.value; other.value=nullptr; } return *this; }
    T** put() { return &value; }
    T* operator->() const { return value; }
};
struct Bstr {
    BSTR value=nullptr;
    explicit Bstr(const wchar_t* text):value(SysAllocString(text)) { if(!value) throw Error("FIREWALL","Cannot allocate firewall string"); }
    explicit Bstr(const std::wstring& text):value(SysAllocStringLen(text.data(),static_cast<UINT>(text.size()))) { if(!value) throw Error("FIREWALL","Cannot allocate firewall string"); }
    ~Bstr() { SysFreeString(value); }
};

void check(HRESULT result,const char* operation) {
    if(FAILED(result)) throw Error("FIREWALL",std::string(operation)+" failed: "+std::to_string(static_cast<uint32_t>(result)));
}

ComPtr<INetFwRules> rules() {
    ComPtr<INetFwPolicy2> policy;
    check(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(policy.put())),"Create firewall policy");
    ComPtr<INetFwRules> result;
    check(policy->get_Rules(result.put()),"Open firewall rules");
    return result;
}

std::wstring executable_path() {
    std::wstring path(32768,L'\0');
    const DWORD length=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!length||length>=path.size()) throw Error("FIREWALL","Cannot locate NativeDNS executable");
    path.resize(length);
    return path;
}
}

FirewallPortRule::FirewallPortRule() {
    const HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(SUCCEEDED(result)) com_initialized_=true;
    else if(result!=RPC_E_CHANGED_MODE) check(result,"Initialize COM for firewall");
}
FirewallPortRule::~FirewallPortRule() {
    disable();
    if(com_initialized_) CoUninitialize();
}

void FirewallPortRule::enable(uint16_t local_port) {
    if(!local_port) throw Error("FIREWALL","Cannot allow TCP port zero");
    disable();
    auto collection=rules();
    Bstr name(rule_name);
    (void)collection->Remove(name.value);
    ComPtr<INetFwRule> rule;
    check(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(rule.put())),"Create firewall rule");
    const auto path=executable_path();
    const auto port=std::to_wstring(local_port);
    Bstr description(L"Allows only the ephemeral NativeDNS reflected TCP listener while transparent DNS interception is running.");
    Bstr application(path),ports(port);
    check(rule->put_Name(name.value),"Set firewall rule name");
    check(rule->put_Description(description.value),"Set firewall rule description");
    check(rule->put_ApplicationName(application.value),"Set firewall application");
    check(rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP),"Set firewall protocol");
    check(rule->put_LocalPorts(ports.value),"Set firewall local port");
    check(rule->put_Direction(NET_FW_RULE_DIR_IN),"Set firewall direction");
    check(rule->put_Action(NET_FW_ACTION_ALLOW),"Set firewall action");
    check(rule->put_Profiles(NET_FW_PROFILE2_ALL),"Set firewall profiles");
    check(rule->put_EdgeTraversal(VARIANT_FALSE),"Disable firewall edge traversal");
    check(rule->put_Enabled(VARIANT_TRUE),"Enable firewall rule");
    check(collection->Add(rule.value),"Add firewall rule");
    enabled_=true;
}

void FirewallPortRule::disable() noexcept {
    if(!enabled_) return;
    try {
        auto collection=rules();
        Bstr name(rule_name);
        (void)collection->Remove(name.value);
    } catch(...) {}
    enabled_=false;
}

}
