// TEST ONLY. Drives the installed credential provider DLL the way LogonUI does -- through its COM interfaces, in
// this process -- to prove the tile code (WeldapProvider.cpp, WeldapCredential.cpp, Dll.cpp, helpers.cpp), which
// otherwise runs only inside LogonUI, survives hostile input, unusual call orders and a long random fuzz without
// crashing, hanging or leaking, and still signs users in. Run as SYSTEM (the pipe accepts SYSTEM only) on a device
// where the WELDAP service is running:
//   TileTest.exe <passwords file: "uun password" lines> [adopt-uun] [provider dll; default: the registered one]
// adopt-uun: a directory user whose local account exists but is not managed (to exercise the consent step).
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>

static const CLSID c_clsid = { 0xe239aaab, 0xfffd, 0x4525, { 0xa8, 0x94, 0x1b, 0x9d, 0x63, 0x14, 0xb1, 0xcb } };
enum { F_TILE = 0, F_LABEL, F_LARGE, F_UUN, F_PASSWORD, F_CONSENT, F_SUBMIT, F_STATUS, F_COUNT };

static int g_pass = 0, g_fail = 0;
static void Check(bool ok, const char *what, const std::wstring &got = L"")
{
    if (ok) { g_pass++; printf("PASS  %s\n", what); }
    else { g_fail++; printf("FAIL  %s   (got: %ls)\n", what, got.c_str()); }
}

// ---- LogonUI stand-ins ----------------------------------------------------------------------------------------
struct FieldView { CREDENTIAL_PROVIDER_FIELD_STATE state = CPFS_HIDDEN; std::wstring text; BOOL checked = FALSE; };

class CredEvents : public ICredentialProviderCredentialEvents
{
public:
    FieldView f[F_COUNT + 8];
    LONG refs = 1;
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents)
        {
            *ppv = static_cast<ICredentialProviderCredentialEvents *>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&refs); }
    IFACEMETHODIMP_(ULONG) Release() { return InterlockedDecrement(&refs); }   // lives on the stack
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential *, DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE s)
    {
        if (id < ARRAYSIZE(f)) f[id].state = s;
        return S_OK;
    }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential *, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) { return S_OK; }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential *, DWORD id, LPCWSTR s)
    {
        if (id < ARRAYSIZE(f)) f[id].text = s ? s : L"(null)";
        return S_OK;
    }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential *, DWORD id, BOOL c, LPCWSTR)
    {
        if (id < ARRAYSIZE(f)) f[id].checked = c;
        return S_OK;
    }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential *, DWORD, HBITMAP) { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential *, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential *, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential *, DWORD, LPCWSTR) { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential *, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND *phwnd) { *phwnd = nullptr; return S_OK; }
};

class ProvEvents : public ICredentialProviderEvents
{
public:
    LONG refs = 1;
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderEvents)
        {
            *ppv = static_cast<ICredentialProviderEvents *>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&refs); }
    IFACEMETHODIMP_(ULONG) Release() { return InterlockedDecrement(&refs); }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR) { return S_OK; }
};

// ---- helpers --------------------------------------------------------------------------------------------------
static std::map<std::wstring, std::wstring> g_passwords;

static void LoadPasswords(PCWSTR path)
{
    FILE *f = nullptr;
    if (_wfopen_s(&f, path, L"r") != 0 || !f) return;
    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        std::string s(line);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        size_t sp = s.find(' ');
        if (sp == std::string::npos) continue;
        g_passwords[std::wstring(s.begin(), s.begin() + sp)] = std::wstring(s.begin() + sp + 1, s.end());
        SecureZeroMemory(line, sizeof(line));
    }
    fclose(f);
}

struct Usage { DWORD handles; SIZE_T privateBytes; DWORD gdi; };
static Usage Measure()
{
    Usage u = {};
    GetProcessHandleCount(GetCurrentProcess(), &u.handles);
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&pmc), sizeof(pmc));
    u.privateBytes = pmc.PrivateUsage;
    u.gdi = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    return u;
}

static std::wstring Str(ICredentialProviderCredential *c, DWORD id)
{
    PWSTR p = nullptr;
    std::wstring s = SUCCEEDED(c->GetStringValue(id, &p)) && p ? p : L"<none>";
    if (p) { SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t)); CoTaskMemFree(p); }
    return s;
}

static void FreeSerialization(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION &s)
{
    if (s.rgbSerialization) { SecureZeroMemory(s.rgbSerialization, s.cbSerialization); CoTaskMemFree(s.rgbSerialization); }
    ZeroMemory(&s, sizeof(s));
}

// The serialization LSA would get: a self-relative KERB_INTERACTIVE_UNLOCK_LOGON for <computer>\<uun>.
static bool SerializationIsFor(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION &s, PCWSTR uun)
{
    if (!s.rgbSerialization || s.cbSerialization < sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) || s.clsidCredentialProvider != c_clsid)
        return false;
    auto *k = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON *>(s.rgbSerialization);
    auto field = [&](const UNICODE_STRING &u, std::wstring *out) {
        size_t off = reinterpret_cast<size_t>(u.Buffer);
        if (u.Length % 2 || off > s.cbSerialization || u.Length > s.cbSerialization - off) return false;
        out->assign(reinterpret_cast<const wchar_t *>(s.rgbSerialization + off), u.Length / 2);
        return true;
    };
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cch = ARRAYSIZE(computer);
    GetComputerNameW(computer, &cch);
    std::wstring user, domain, password;
    bool ok = (k->Logon.MessageType == KerbInteractiveLogon || k->Logon.MessageType == KerbWorkstationUnlockLogon) &&
              field(k->Logon.UserName, &user) && field(k->Logon.LogonDomainName, &domain) &&
              field(k->Logon.Password, &password) && user == uun && _wcsicmp(domain.c_str(), computer) == 0 && !password.empty();
    SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    return ok;
}

struct Attempt { HRESULT hr; CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE r; bool serialized; std::wstring status; CREDENTIAL_PROVIDER_STATUS_ICON icon; };
static Attempt Submit(ICredentialProviderCredential *c, PCWSTR uun, PCWSTR password, bool checkFor = true)
{
    if (uun) c->SetStringValue(F_UUN, uun);
    if (password) c->SetStringValue(F_PASSWORD, password);
    Attempt a = {};
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION s = {};
    PWSTR status = nullptr;
    a.hr = c->GetSerialization(&a.r, &s, &status, &a.icon);
    a.serialized = s.rgbSerialization != nullptr && (!checkFor || SerializationIsFor(s, uun));
    a.status = status ? status : L"";
    if (status) CoTaskMemFree(status);
    FreeSerialization(s);
    return a;
}

static unsigned long long g_rng = 0x9E3779B97F4A7C15ULL;
static unsigned Rand(unsigned n) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return static_cast<unsigned>(g_rng % n); }
static std::wstring RandomString(size_t maxLen)
{
    static const wchar_t c_odd[] = { 0xD800, 0xDC00, 0xFFFF, 0xFEFF, 0x200B, 0x0007, 0x001B, 0x007F, L'\\', L'%', L'"', L'.', L'@' };
    std::wstring s;
    size_t n = Rand(static_cast<unsigned>(maxLen + 1));
    for (size_t i = 0; i < n; i++)
    {
        switch (Rand(4))
        {
        case 0: s += static_cast<wchar_t>(L'a' + Rand(26)); break;
        case 1: s += static_cast<wchar_t>(L'0' + Rand(10)); break;
        case 2: s += c_odd[Rand(ARRAYSIZE(c_odd))]; break;
        default: s += static_cast<wchar_t>(1 + Rand(0xFFFE)); break;
        }
    }
    return s;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) { fwprintf(stderr, L"usage: TileTest <passwords file> [adopt-uun] [provider dll]\n"); return 2; }
    LoadPasswords(argv[1]);
    std::wstring adoptUun = argc >= 3 ? argv[2] : L"";
    std::wstring dll;
    if (argc >= 4) dll = argv[3];
    else
    {
        wchar_t buf[MAX_PATH]; DWORD cb = sizeof(buf);
        if (RegGetValueW(HKEY_CLASSES_ROOT, L"CLSID\\{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}\\InprocServer32", nullptr,
                         RRF_RT_REG_SZ, nullptr, buf, &cb) == ERROR_SUCCESS) dll = buf;
    }
    printf("provider: %ls\n", dll.c_str());
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 2;
    HMODULE h = LoadLibraryW(dll.c_str());
    Check(h != nullptr, "the registered provider DLL loads");
    if (!h) return 1;
    using GetClassObject = HRESULT(STDAPICALLTYPE *)(REFCLSID, REFIID, LPVOID *);
    using CanUnload = HRESULT(STDAPICALLTYPE *)();
    auto pGet = reinterpret_cast<GetClassObject>(GetProcAddress(h, "DllGetClassObject"));
    auto pCanUnload = reinterpret_cast<CanUnload>(GetProcAddress(h, "DllCanUnloadNow"));
    IClassFactory *cf = nullptr;
    Check(pGet && SUCCEEDED(pGet(c_clsid, IID_IClassFactory, reinterpret_cast<void **>(&cf))), "DllGetClassObject gives a class factory");
    Check(pCanUnload() == S_FALSE, "a live class factory keeps the DLL loaded (DllCanUnloadNow = S_FALSE)");
    IClassFactory *bad = nullptr;
    Check(pGet(IID_IUnknown, IID_IClassFactory, reinterpret_cast<void **>(&bad)) == CLASS_E_CLASSNOTAVAILABLE && !bad, "an unknown CLSID is refused");

    // ---- the provider ----
    printf("== provider: scenarios and fields\n");
    ICredentialProvider *prov = nullptr;
    Check(SUCCEEDED(cf->CreateInstance(nullptr, IID_ICredentialProvider, reinterpret_cast<void **>(&prov))), "provider created");
    cf->Release();
    Check(prov->SetUsageScenario(CPUS_CHANGE_PASSWORD, 0) == E_NOTIMPL, "change-password scenario refused");
    Check(prov->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL, "CredUI scenario refused");
    Check(prov->SetSerialization(nullptr) == E_NOTIMPL, "SetSerialization refused");
    Check(SUCCEEDED(prov->SetUsageScenario(CPUS_LOGON, 0)), "logon scenario accepted");
    Check(SUCCEEDED(prov->SetUsageScenario(CPUS_LOGON, 0)), "logon scenario accepted again (LogonUI may repeat it)");
    ProvEvents pe;
    auto okOrNotImpl = [](HRESULT hr) { return hr == S_OK || hr == E_NOTIMPL; };   // the provider raises no events
    Check(okOrNotImpl(prov->Advise(&pe, 1)) && okOrNotImpl(prov->UnAdvise()) && okOrNotImpl(prov->UnAdvise()) && okOrNotImpl(prov->Advise(&pe, 2)),
          "provider Advise/UnAdvise in any order"); 
    DWORD fields = 0;
    Check(SUCCEEDED(prov->GetFieldDescriptorCount(&fields)) && fields == F_COUNT, "8 fields");
    bool allFields = true;
    for (DWORD i = 0; i < fields + 3; i++)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *d = nullptr;
        HRESULT hr = prov->GetFieldDescriptorAt(i, &d);
        allFields = allFields && (i < fields ? SUCCEEDED(hr) && d && d->dwFieldID == i : FAILED(hr) && !d);
        if (d) { CoTaskMemFree(d->pszLabel); CoTaskMemFree(d); }
    }
    Check(allFields, "every field descriptor; out of range refused");
    DWORD count = 0, def = 0; BOOL autoLogon = TRUE;
    Check(SUCCEEDED(prov->GetCredentialCount(&count, &def, &autoLogon)) && count == 1 && !autoLogon, "one credential, no auto-logon");
    ICredentialProviderCredential *c = nullptr, *none = nullptr;
    Check(SUCCEEDED(prov->GetCredentialAt(0, &c)) && c, "credential 0");
    Check(FAILED(prov->GetCredentialAt(1, &none)) && !none, "credential 1 refused");

    // ---- the tile, before LogonUI advises it ----
    printf("== the tile: fields, and use before Advise\n");
    CredEvents ev;
    CREDENTIAL_PROVIDER_FIELD_STATE st; CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE ist;
    Check(SUCCEEDED(c->GetFieldState(F_CONSENT, &st, &ist)) && st == CPFS_HIDDEN, "the Continue box starts hidden");
    Check(FAILED(c->GetFieldState(F_COUNT, &st, &ist)) && FAILED(c->GetFieldState(0xFFFFFFFF, &st, &ist)), "field state: out of range refused");
    HBITMAP bmp = nullptr;
    Check(SUCCEEDED(c->GetBitmapValue(F_TILE, &bmp)) && bmp, "tile bitmap loads");
    BITMAP bm = {};
    Check(bmp && GetObjectW(bmp, sizeof(bm), &bm) && bm.bmWidth == 192 && bm.bmHeight == 192, "tile bitmap is 192x192");
    if (bmp) DeleteObject(bmp);
    HBITMAP none2 = nullptr;
    Check(FAILED(c->GetBitmapValue(F_UUN, &none2)) && !none2, "bitmap of a non-image field refused");
    BOOL chk = TRUE; PWSTR label = nullptr;
    Check(SUCCEEDED(c->GetCheckboxValue(F_CONSENT, &chk, &label)) && !chk && label, "Continue box unticked, labelled");
    if (label) CoTaskMemFree(label);
    label = nullptr;
    Check(FAILED(c->GetCheckboxValue(F_UUN, &chk, &label)) && !label, "checkbox of a non-checkbox field refused");
    Check(FAILED(c->SetCheckboxValue(F_UUN, TRUE)) && FAILED(c->SetCheckboxValue(99, TRUE)), "ticking a non-checkbox field refused");
    Check(FAILED(c->SetStringValue(F_TILE, L"x")) && FAILED(c->SetStringValue(99, L"x")) && FAILED(c->SetStringValue(F_STATUS, L"x")),
          "writing a non-edit field refused");
    DWORD adj = 0;
    Check(SUCCEEDED(c->GetSubmitButtonValue(F_SUBMIT, &adj)) && adj == F_PASSWORD && FAILED(c->GetSubmitButtonValue(F_UUN, &adj)), "submit button beside the password");
    Check(c->Advise(nullptr) == E_INVALIDARG, "Advise(null) refused");
    Attempt a = Submit(c, L"notauser!", L"pw");
    Check(a.hr == S_OK && a.r == CPGSR_NO_CREDENTIAL_FINISHED && !a.serialized && !a.status.empty(), "submit before Advise: refused with a message, no crash", a.status);

    Check(SUCCEEDED(c->Advise(&ev)) && SUCCEEDED(c->Advise(&ev)), "Advise twice (the second replaces the first)");
    BOOL autoLogon2 = TRUE;
    Check(SUCCEEDED(c->SetSelected(&autoLogon2)) && !autoLogon2, "selected, no auto-logon");

    // ---- hostile input ----
    printf("== hostile input in every field\n");
    std::wstring huge(1 << 20, L'a');
    a = Submit(c, huge.c_str(), L"pw");
    Check(a.hr == S_OK && !a.serialized, "1 M-character username: refused with a message", a.status);
    a = Submit(c, L"alice", huge.c_str());
    Check(a.hr == S_OK && !a.serialized && Str(c, F_PASSWORD).empty(), "1 M-character password: refused, field wiped", a.status);
    a = Submit(c, nullptr, nullptr);
    c->SetStringValue(F_UUN, nullptr);
    c->SetStringValue(F_PASSWORD, nullptr);
    a = Submit(c, nullptr, nullptr);
    Check(a.hr == S_OK && !a.serialized, "null strings (empty fields): refused with a message", a.status);
    const wchar_t surrogate[] = { L'a', 0xD800, L'b', 0 }, controls[] = { L'a', 0x1B, L'[', L'2', L'J', L'\r', L'\n', 0 };
    a = Submit(c, surrogate, surrogate);
    Check(a.hr == S_OK && !a.serialized, "unpaired surrogates: refused with a message", a.status);
    a = Submit(c, controls, controls);
    Check(a.hr == S_OK && !a.serialized, "control characters: refused with a message", a.status);
    a = Submit(c, L"   ALICE   ", L"definitely-wrong-password");
    Check(a.hr == S_OK && !a.serialized && a.status.find(L"incorrect") != std::wstring::npos, "padded upper-case name normalised, wrong password refused", a.status);
    Check(Str(c, F_PASSWORD).empty() && ev.f[F_PASSWORD].text.empty(), "password field wiped after every attempt");

    // ---- real sign-ins ----
    printf("== real sign-ins through the service\n");
    a = Submit(c, L"alice", g_passwords[L"alice"].c_str());
    Check(a.hr == S_OK && a.r == CPGSR_RETURN_CREDENTIAL_FINISHED && a.serialized, "alice: a logon serialization for <computer>\\alice", a.status);
    Check(Str(c, F_PASSWORD).empty(), "password field wiped after the sign-in");
    a = Submit(c, L"bob", g_passwords[L"bob"].c_str());
    Check(a.r == CPGSR_RETURN_CREDENTIAL_FINISHED && a.serialized, "bob: signed in", a.status);
    a = Submit(c, L"carol", g_passwords[L"carol"].c_str());
    Check(a.r == CPGSR_NO_CREDENTIAL_FINISHED && !a.serialized && a.icon == CPSI_ERROR, "carol (not a user): refused", a.status);
    a = Submit(c, L"rob", L"whatever");
    Check(!a.serialized && a.status.find(L"standard Windows sign-in") != std::wstring::npos, "rob (excluded): sent to the standard tile", a.status);
    Check(ev.f[F_CONSENT].state == CPFS_HIDDEN, "no Continue box after ordinary replies");

    // ---- the consent step ----
    if (!adoptUun.empty())
    {
        printf("== adoption: the Continue box\n");
        PCWSTR apw = g_passwords[adoptUun].c_str();
        BOOL ticked = TRUE; PWSTR l = nullptr;
        c->SetCheckboxValue(F_CONSENT, TRUE);
        Check(SUCCEEDED(c->GetCheckboxValue(F_CONSENT, &ticked, &l)) && !ticked, "a hidden Continue box cannot be ticked");
        if (l) CoTaskMemFree(l);
        a = Submit(c, adoptUun.c_str(), apw);
        Check(!a.serialized && a.icon == CPSI_WARNING && a.status.find(L"Continue") != std::wstring::npos, "pre-existing account: warning, nothing signed in", a.status);
        Check(ev.f[F_CONSENT].state == CPFS_DISPLAY_IN_SELECTED_TILE && !ev.f[F_CONSENT].checked, "the Continue box is shown, unticked");
        c->SetStringValue(F_UUN, L"someoneelse");
        Check(ev.f[F_CONSENT].state == CPFS_HIDDEN, "changing the name withdraws the offer");
        a = Submit(c, adoptUun.c_str(), apw);
        c->SetCheckboxValue(F_CONSENT, TRUE);
        Check(SUCCEEDED(c->SetDeselected()) && ev.f[F_CONSENT].state == CPFS_HIDDEN, "deselecting the tile withdraws it too");
        a = Submit(c, adoptUun.c_str(), apw);
        Check(ev.f[F_CONSENT].state == CPFS_DISPLAY_IN_SELECTED_TILE, "offered again");
        a = Submit(c, adoptUun.c_str(), L"wrong-password-for-adoption");
        Check(ev.f[F_CONSENT].state == CPFS_HIDDEN && !a.serialized, "a wrong password withdraws the offer");
        a = Submit(c, adoptUun.c_str(), apw);
        c->SetCheckboxValue(F_CONSENT, TRUE);
        a = Submit(c, adoptUun.c_str(), L"");
        l = nullptr;
        Check(!a.serialized && ev.f[F_CONSENT].state == CPFS_DISPLAY_IN_SELECTED_TILE && SUCCEEDED(c->GetCheckboxValue(F_CONSENT, &ticked, &l)) && ticked,
              "a submit the tile refuses itself (no password) keeps the offer, still ticked", a.status);
        if (l) CoTaskMemFree(l);
        a = Submit(c, adoptUun.c_str(), apw);   // sets the same name again first, as LogonUI may
        Check(a.r == CPGSR_RETURN_CREDENTIAL_FINISHED && a.serialized, "ticked and resubmitted (same name set again): adopted and signed in", a.status);
        Check(ev.f[F_CONSENT].state == CPFS_HIDDEN, "the box is gone afterwards");
    }

    // ---- call-order abuse ----
    printf("== call-order abuse\n");
    for (int i = 0; i < 50; i++) { c->SetDeselected(); c->SetSelected(&autoLogon2); }
    Check(SUCCEEDED(c->UnAdvise()) && SUCCEEDED(c->UnAdvise()), "UnAdvise twice");
    a = Submit(c, L"alice", g_passwords[L"alice"].c_str());
    Check(a.r == CPGSR_RETURN_CREDENTIAL_FINISHED && a.serialized, "signs in after UnAdvise (no events sink)", a.status);
    CREDENTIAL_PROVIDER_STATUS_ICON icon; PWSTR rs = nullptr;
    Check(SUCCEEDED(c->ReportResult(static_cast<NTSTATUS>(0xC000006DL), 0, &rs, &icon)) && rs, "ReportResult(logon failure) gives a message");
    if (rs) { printf("      \"%ls\"\n", rs); CoTaskMemFree(rs); }
    rs = nullptr;
    Check(SUCCEEDED(c->ReportResult(static_cast<NTSTATUS>(0xDEADBEEF), 0x12345678, &rs, &icon)), "ReportResult with an unknown status: no crash");
    if (rs) CoTaskMemFree(rs);
    c->Advise(&ev);

    // ---- random fuzz with a leak check ----
    printf("== random fuzz: 20000 calls, then a leak check\n");
    for (int i = 0; i < 300; i++) { Submit(c, RandomString(30).c_str(), RandomString(30).c_str(), false); }   // warm up
    Usage before = Measure();
    int serverCalls = 0;
    for (int i = 0; i < 20000; i++)
    {
        DWORD id = Rand(F_COUNT + 2);
        switch (Rand(10))
        {
        case 0: case 1: c->SetStringValue(id, RandomString(Rand(8) == 0 ? 2000 : 40).c_str()); break;
        case 2: c->SetCheckboxValue(id, Rand(2)); break;
        case 3: if (Rand(2)) c->SetDeselected(); else c->SetSelected(&autoLogon2); break;
        case 4: { PWSTR p = nullptr; if (SUCCEEDED(c->GetStringValue(id, &p)) && p) CoTaskMemFree(p); break; }
        case 5: { BOOL b; PWSTR l = nullptr; if (SUCCEEDED(c->GetCheckboxValue(id, &b, &l)) && l) CoTaskMemFree(l); break; }
        case 6: c->GetFieldState(id, &st, &ist); break;
        case 7: { HBITMAP b = nullptr; if (SUCCEEDED(c->GetBitmapValue(id, &b)) && b) DeleteObject(b); break; }
        case 8: if (Rand(2)) c->UnAdvise(); else c->Advise(&ev); break;
        default:
            // Mostly names the tile refuses before the pipe; now and then one that reaches the service.
            if (Rand(40) == 0) { serverCalls++; Submit(c, L"zfuzzuser", RandomString(20).c_str(), false); }
            else Submit(c, (RandomString(10) + L"!").c_str(), RandomString(20).c_str(), false);
            break;
        }
    }
    c->Advise(&ev);
    a = Submit(c, L"alice", g_passwords[L"alice"].c_str());
    Check(a.r == CPGSR_RETURN_CREDENTIAL_FINISHED && a.serialized, "after the fuzz: still signs alice in", a.status);
    Usage after = Measure();
    printf("      fuzz reached the service %d times; handles %lu->%lu, private %zu->%zu KB, GDI %lu->%lu\n", serverCalls,
           before.handles, after.handles, before.privateBytes / 1024, after.privateBytes / 1024, before.gdi, after.gdi);
    Check(after.handles <= before.handles + 20, "no handle leak");
    Check(after.privateBytes <= before.privateBytes + 4 * 1024 * 1024, "no memory leak (< 4 MB over 20000 calls)");
    Check(after.gdi <= before.gdi + 2, "no GDI leak");

    // ---- teardown in the awkward order ----
    printf("== teardown: provider released before its credential\n");
    prov->UnAdvise();
    prov->Release();
    a = Submit(c, L"alice", g_passwords[L"alice"].c_str());
    Check(a.r == CPGSR_RETURN_CREDENTIAL_FINISHED, "the credential outlives its provider and still works", a.status);
    Check(pCanUnload() == S_FALSE, "DLL stays loaded while the credential lives");
    c->UnAdvise();
    c->Release();
    Check(pCanUnload() == S_OK, "everything released: DllCanUnloadNow = S_OK");
    FreeLibrary(h);
    CoUninitialize();
    for (auto &kv : g_passwords) SecureZeroMemory(&kv.second[0], kv.second.size() * sizeof(wchar_t));
    printf("tile checks: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
