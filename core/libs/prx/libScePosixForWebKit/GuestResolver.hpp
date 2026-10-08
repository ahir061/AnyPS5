#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace GuestResolver {
struct AddressInfo {
    std::int32_t flags;
    std::int32_t family;
    std::int32_t socketType;
    std::int32_t protocol;
    std::uint32_t addressLength;
    char* canonicalName;
    void* address;
    AddressInfo* next;
};
static_assert(sizeof(AddressInfo) == 48);
static_assert(offsetof(AddressInfo, canonicalName) == 24);
static_assert(offsetof(AddressInfo, address) == 32);

struct HostEntry {
    char* name;
    char** aliases;
    std::int32_t addressType;
    std::int32_t addressLength;
    char** addresses;
};
static_assert(sizeof(HostEntry) == 32);
static_assert(offsetof(HostEntry, aliases) == 8);
static_assert(offsetof(HostEntry, addressType) == 16);
static_assert(offsetof(HostEntry, addressLength) == 20);
static_assert(offsetof(HostEntry, addresses) == 24);

using Ipv4Address = std::array<std::uint8_t, 4>;

inline std::optional<Ipv4Address> ParseIpv4(const char* text) {
    const auto decimal = [](char c) { return c >= '0' && c <= '9'; };
    const auto hexadecimal = [](char c) { return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
    const auto space = [](char c) { return c == ' ' || (c >= '\t' && c <= '\r'); };
    std::array<std::uint8_t, 3> parts{};
    std::size_t count = 0;
    std::uint64_t value = 0;
    bool digit = false;
    char c = *text;
    for (;;) {
        if (!decimal(c)) return std::nullopt;
        value = 0;
        std::uint64_t base = 10;
        digit = false;
        if (c == '0') {
            c = *++text;
            if (c == 'x' || c == 'X') {
                base = 16;
                c = *++text;
            } else {
                base = 8;
                digit = true;
            }
        }
        for (;;) {
            if (decimal(c)) {
                if (base == 8 && (c == '8' || c == '9')) return std::nullopt;
                value = value * base + static_cast<std::uint64_t>(c - '0');
            } else if (base == 16 && hexadecimal(c)) {
                value = (value << 4) | static_cast<std::uint64_t>(c + 10 - (c >= 'a' ? 'a' : 'A'));
            } else {
                break;
            }
            c = *++text;
            digit = true;
        }
        if (c != '.') break;
        if (count == parts.size() || value > 0xff) return std::nullopt;
        parts[count++] = static_cast<std::uint8_t>(value);
        c = *++text;
    }
    if ((c != '\0' && !space(c)) || !digit) return std::nullopt;
    if (count != 0 && value > (0xffffffffu >> (8 * count))) return std::nullopt;
    for (std::size_t index = 0; index < count; ++index)
        value |= static_cast<std::uint64_t>(parts[index]) << (24 - 8 * index);
    const auto address = static_cast<std::uint32_t>(value);
    return Ipv4Address{static_cast<std::uint8_t>(address >> 24), static_cast<std::uint8_t>(address >> 16),
        static_cast<std::uint8_t>(address >> 8), static_cast<std::uint8_t>(address)};
}

class HostEntryStorage {
public:
    HostEntryStorage() = default;
    HostEntryStorage(const HostEntryStorage&) = delete;
    HostEntryStorage& operator=(const HostEntryStorage&) = delete;

    HostEntry* Store(std::string name, std::vector<std::string> aliases, std::vector<Ipv4Address> addresses) {
        std::vector<char*> newAliasPointers;
        newAliasPointers.reserve(aliases.size() + 1);
        for (auto& alias : aliases) newAliasPointers.push_back(alias.data());
        newAliasPointers.push_back(nullptr);
        std::vector<char*> newAddressPointers;
        newAddressPointers.reserve(addresses.size() + 1);
        for (auto& address : addresses) newAddressPointers.push_back(reinterpret_cast<char*>(address.data()));
        newAddressPointers.push_back(nullptr);
        hostName = std::move(name);
        aliasNames = std::move(aliases);
        addressBytes = std::move(addresses);
        aliasPointers = std::move(newAliasPointers);
        addressPointers = std::move(newAddressPointers);
        entry = HostEntry{hostName.data(), aliasPointers.data(), 2, 4, addressPointers.data()};
        return &entry;
    }

    template <class TNative>
    HostEntry* StoreNative(const TNative& native, int inetFamily) {
        if (native.h_addrtype != inetFamily || native.h_length != 4 || !native.h_name || !native.h_addr_list ||
            !native.h_addr_list[0]) return nullptr;
        std::vector<std::string> aliases;
        for (char* const* alias = native.h_aliases; alias && *alias; ++alias) aliases.emplace_back(*alias);
        std::vector<Ipv4Address> addresses;
        for (char* const* address = native.h_addr_list; *address; ++address) {
            Ipv4Address bytes{};
            std::memcpy(bytes.data(), *address, bytes.size());
            addresses.push_back(bytes);
        }
        return Store(native.h_name, std::move(aliases), std::move(addresses));
    }

private:
    std::string hostName;
    std::vector<std::string> aliasNames;
    std::vector<Ipv4Address> addressBytes;
    std::vector<char*> aliasPointers;
    std::vector<char*> addressPointers;
    HostEntry entry{};
};
}
