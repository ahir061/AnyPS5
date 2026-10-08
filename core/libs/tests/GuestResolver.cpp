#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include "prx/libc/include/general/VabiMacros.hpp"
#include "prx/libScePosixForWebKit/GuestResolver.hpp"
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <source_location>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

extern "C" {
int APS5_VABI getaddrinfo_nid_postfix(const char*, const char*, const GuestResolver::AddressInfo*, GuestResolver::AddressInfo**);
void APS5_VABI freeaddrinfo_nid_postfix(GuestResolver::AddressInfo*);
int APS5_VABI getnameinfo_nid_postfix(const void*, std::uint32_t, char*, std::uint32_t, char*, std::uint32_t, int);
const char* APS5_VABI gai_strerror_nid_postfix(int);
GuestResolver::HostEntry* APS5_VABI gethostbyname_nid_postfix(const char*);
}
void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "Resolver check failed at line %u\n", location.line());
        std::abort();
    }
}

bool Holds(const GuestResolver::HostEntry* entry, const char* name, GuestResolver::Ipv4Address address) {
    return entry && std::strcmp(entry->name, name) == 0 && entry->aliases && !entry->aliases[0] &&
        entry->addressType == 2 && entry->addressLength == 4 && entry->addresses && entry->addresses[0] &&
        std::memcmp(entry->addresses[0], address.data(), address.size()) == 0 && !entry->addresses[1];
}

void NumericNames() {
    const std::array<std::pair<const char*, GuestResolver::Ipv4Address>, 9> cases{{
        {"127.0.0.1", {127, 0, 0, 1}}, {"127.1", {127, 0, 0, 1}}, {"0x7f.1", {127, 0, 0, 1}},
        {"0X7F.0.0.0x1", {127, 0, 0, 1}}, {"017700000001", {127, 0, 0, 1}}, {"2130706433", {127, 0, 0, 1}},
        {"10.1.2", {10, 1, 0, 2}}, {"1.2.3.4\tsuffix", {1, 2, 3, 4}}, {"4294967297", {0, 0, 0, 1}},
    }};
    for (const auto& [name, address] : cases) Require(Holds(gethostbyname_nid_postfix(name), name, address));
    const std::string padded = "127.0.0.1" + std::string(2000, ' ');
    const auto* entry = gethostbyname_nid_postfix(padded.c_str());
    Require(entry && std::strlen(entry->name) == 1025 && padded.compare(0, 1025, entry->name) == 0);
    for (const auto* name : {"", " 127.0.0.1", "x", "-1", "1.", ".1", "1..2", "08", "0x", "1.0x", "256.0.0.1",
             "1.2.3.256", "1.16777216", "1.2.65536", "1.2.3.4.5", "1.2.3.4x"})
        Require(!GuestResolver::ParseIpv4(name));
}

void FailuresWithoutLookup() {
    Require(!gethostbyname_nid_postfix(""));
    Require(!gethostbyname_nid_postfix("::1"));
    Require(!gethostbyname_nid_postfix("::ffff:127.0.0.1"));
    Require(!gethostbyname_nid_postfix(std::string(256, 'a').c_str()));
    bool rejected = false;
    try {
        gethostbyname_nid_postfix(nullptr);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    Require(rejected);
}

void RepeatedCalls() {
    auto* first = gethostbyname_nid_postfix("10.0.0.1");
    Require(Holds(first, "10.0.0.1", {10, 0, 0, 1}));
    auto* second = gethostbyname_nid_postfix("10.0.0.2");
    Require(second == first && Holds(first, "10.0.0.2", {10, 0, 0, 2}));
}

void ThreadIsolation() {
    const auto* mine = gethostbyname_nid_postfix("192.0.2.1");
    std::atomic<bool> start{false};
    std::atomic<int> finished{0};
    const auto resolve = [&](const char* name, GuestResolver::Ipv4Address address, std::uintptr_t& own) {
        while (!start.load()) std::this_thread::yield();
        for (int round = 0; round < 1000; ++round) {
            const auto* entry = gethostbyname_nid_postfix(name);
            const auto location = reinterpret_cast<std::uintptr_t>(entry);
            Require(Holds(entry, name, address) && (own == 0 || location == own));
            own = location;
        }
        finished.fetch_add(1);
        while (finished.load() < 2) std::this_thread::yield();
    };
    std::uintptr_t left = 0;
    std::uintptr_t right = 0;
    std::thread first([&] { resolve("192.0.2.2", {192, 0, 2, 2}, left); });
    std::thread second([&] { resolve("192.0.2.3", {192, 0, 2, 3}, right); });
    start.store(true);
    first.join();
    second.join();
    const auto original = reinterpret_cast<std::uintptr_t>(mine);
    Require(left && right && left != right && left != original && right != original);
    Require(Holds(mine, "192.0.2.1", {192, 0, 2, 1}));
}

void NativeResults() {
    GuestResolver::HostEntryStorage storage;
    char name[] = "canonical.example";
    char firstAlias[] = "first.example";
    char secondAlias[] = "second.example";
    char* aliases[] = {firstAlias, secondAlias, nullptr};
    char bytes[3][4] = {{'\xc0', 0, 2, 1}, {'\xc0', 0, 2, 2}, {'\xc0', 0, 2, 3}};
    char* addresses[] = {bytes[0], bytes[1], bytes[2], nullptr};
    hostent native{};
    native.h_name = name;
    native.h_aliases = aliases;
    native.h_addrtype = AF_INET;
    native.h_length = 4;
    native.h_addr_list = addresses;
    auto* entry = storage.StoreNative(native, AF_INET);
    name[0] = 'X';
    firstAlias[0] = 'X';
    bytes[0][3] = 9;
    const auto copied = [&entry] {
        if (!entry || std::strcmp(entry->name, "canonical.example") != 0 || entry->addressType != 2 || entry->addressLength != 4) return false;
        if (std::strcmp(entry->aliases[0], "first.example") != 0 || std::strcmp(entry->aliases[1], "second.example") != 0 || entry->aliases[2]) return false;
        for (std::uint8_t index = 0; index < 3; ++index) {
            const GuestResolver::Ipv4Address expected{192, 0, 2, static_cast<std::uint8_t>(index + 1)};
            if (std::memcmp(entry->addresses[index], expected.data(), expected.size()) != 0) return false;
        }
        return !entry->addresses[3];
    };
    Require(copied());
    native.h_addrtype = AF_INET6;
    Require(!storage.StoreNative(native, AF_INET));
    native.h_addrtype = AF_INET;
    native.h_length = 16;
    Require(!storage.StoreNative(native, AF_INET));
    native.h_length = 4;
    char* none[] = {nullptr};
    native.h_addr_list = none;
    Require(!storage.StoreNative(native, AF_INET));
    native.h_addr_list = addresses;
    native.h_name = nullptr;
    Require(!storage.StoreNative(native, AF_INET));
    Require(copied());
    native.h_name = name;
    native.h_aliases = nullptr;
    auto* plain = storage.StoreNative(native, AF_INET);
    Require(plain == entry && std::strcmp(plain->name, "Xanonical.example") == 0 && plain->aliases && !plain->aliases[0]);
    Require(std::memcmp(plain->addresses[0], bytes[0], 4) == 0 && plain->addresses[2] && !plain->addresses[3]);
}

int main() {
    std::array<unsigned char, 16> v4{16, 2, 0x6d, 0x06, 127, 0, 0, 1};
    char host[128]{}, service[32]{};
    Require(getnameinfo_nid_postfix(v4.data(), v4.size(), host, sizeof(host), service, sizeof(service), 10) == 0);
    Require(std::strcmp(host, "127.0.0.1") == 0 && std::strcmp(service, "27910") == 0);
    std::array<unsigned char, 28> v6{28, 28};
    v6[23] = 1;
    Require(getnameinfo_nid_postfix(v6.data(), v6.size(), host, sizeof(host), nullptr, 0, 10) == 0);
    Require(std::strcmp(host, "::1") == 0);
    Require(getnameinfo_nid_postfix(v4.data(), 2, host, sizeof(host), nullptr, 0, 10) == 5);
    Require(getnameinfo_nid_postfix(v4.data(), v4.size(), host, sizeof(host), nullptr, 0, 32) == 3);
    Require(getnameinfo_nid_postfix(v4.data(), v4.size(), host, 1, nullptr, 0, 10) == 14);
    Require(std::strlen(gai_strerror_nid_postfix(14)) > 0);
    Require(std::strstr(gai_strerror_nid_postfix(-1), "Unknown") != nullptr);
    GuestResolver::AddressInfo hints{};
    hints.flags = 12; // numeric host and service: no external DNS dependency
    hints.socketType = 1;
    for (const auto* numeric : {"127.0.0.1", "::1"}) {
        GuestResolver::AddressInfo* result = nullptr;
        Require(getaddrinfo_nid_postfix(numeric, "27910", &hints, &result) == 0);
        Require(result != nullptr);
        for (auto* entry = result; entry; entry = entry->next) {
            Require(entry->family == 2 || entry->family == 28);
            Require(entry->socketType == 1);
            Require(getnameinfo_nid_postfix(entry->address, entry->addressLength,
                host, sizeof(host), service, sizeof(service), 10) == 0);
            Require(std::strcmp(host, numeric) == 0 && std::strcmp(service, "27910") == 0);
        }
        freeaddrinfo_nid_postfix(result);
    }
    GuestResolver::AddressInfo* result = reinterpret_cast<GuestResolver::AddressInfo*>(1);
    hints.family = 1234;
    Require(getaddrinfo_nid_postfix("127.0.0.1", "1", &hints, &result) == 5 && !result);
    hints.family = 0;
    hints.flags = 0x200;
    Require(getaddrinfo_nid_postfix("127.0.0.1", "1", &hints, &result) == 3 && !result);
    hints.flags = 12;
    Require(getaddrinfo_nid_postfix("invalid-numeric-address", "1", &hints, &result) == 8 && !result);
    freeaddrinfo_nid_postfix(nullptr);
    NumericNames();
    FailuresWithoutLookup();
    RepeatedCalls();
    ThreadIsolation();
    NativeResults();
}
