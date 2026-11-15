#include <3ds.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <mpqfs/mpqfs.h>
#include "items_catalog.h"

namespace devil_codec {

constexpr size_t BlockSize = 16;
constexpr size_t SHA1HashSize = 5;
constexpr size_t BlockSizeBytes = BlockSize * sizeof(uint32_t);
constexpr size_t SignatureSize = 8;

struct SHA1Context {
    std::array<uint32_t, SHA1HashSize> state = {{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }};
    std::array<uint32_t, BlockSize> buffer {};
};

inline uint32_t LoadLE32Ptr(const uint8_t* p) {
    return uint32_t(*(p + 0)) | (uint32_t(*(p + 1)) << 8) | (uint32_t(*(p + 2)) << 16) | (uint32_t(*(p + 3)) << 24);
}

uint32_t SHA1CircularShift(uint32_t word, size_t bits) {
    if ((word & (1U << 31)) != 0) return (0xFFFFFFFFU << bits) | (word >> (32 - bits));
    return (word << bits) | (word >> (32 - bits));
}

void SHA1ProcessMessageBlock(SHA1Context& context) {
    std::array<uint32_t, 80> w {};
    std::memcpy(w.data(), context.buffer.data(), BlockSize * sizeof(uint32_t));
    for (int i = 16; i < 80; i++)
        w.at(i) = w.at(i - 16) ^ w.at(i - 14) ^ w.at(i - 8) ^ w.at(i - 3);

    uint32_t a = context.state.at(0), b = context.state.at(1), c = context.state.at(2), d = context.state.at(3), e = context.state.at(4);
    for (int i = 0; i < 20; i++) {
        const uint32_t temp = SHA1CircularShift(a, 5) + ((b & c) | ((~b) & d)) + e + w.at(i) + 0x5A827999U;
        e = d; d = c; c = SHA1CircularShift(b, 30); b = a; a = temp;
    }
    for (int i = 20; i < 40; i++) {
        const uint32_t temp = SHA1CircularShift(a, 5) + (b ^ c ^ d) + e + w.at(i) + 0x6ED9EBA1U;
        e = d; d = c; c = SHA1CircularShift(b, 30); b = a; a = temp;
    }
    for (int i = 40; i < 60; i++) {
        const uint32_t temp = SHA1CircularShift(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w.at(i) + 0x8F1BBCDCU;
        e = d; d = c; c = SHA1CircularShift(b, 30); b = a; a = temp;
    }
    for (int i = 60; i < 80; i++) {
        const uint32_t temp = SHA1CircularShift(a, 5) + (b ^ c ^ d) + e + w.at(i) + 0xCA62C1D6U;
        e = d; d = c; c = SHA1CircularShift(b, 30); b = a; a = temp;
    }
    context.state.at(0) += a; context.state.at(1) += b; context.state.at(2) += c; context.state.at(3) += d; context.state.at(4) += e;
}

void SHA1Result(const SHA1Context& context, std::array<uint32_t, SHA1HashSize>& messageDigest) { messageDigest = context.state; }
void SHA1Calculate(SHA1Context& context, const std::array<uint32_t, BlockSize>& data) { context.buffer = data; SHA1ProcessMessageBlock(context); }

struct CodecSignature { uint32_t checksum; uint8_t error; uint8_t lastChunkSize; };

SHA1Context CodecInitKey(const char* pszPassword) {
    std::array<uint32_t, BlockSize> pw {};
    std::size_t j = 0;
    for (uint32_t& value : pw) {
        if (*(pszPassword + j) == '\0') j = 0;
        value = LoadLE32Ptr(reinterpret_cast<const uint8_t*>(pszPassword + j));
        j += sizeof(uint32_t);
    }
    std::array<uint32_t, SHA1HashSize> digest {};
    { SHA1Context context; SHA1Calculate(context, pw); SHA1Result(context, digest); }

    std::array<uint32_t, BlockSize> key = {{
        2908958655U, 4146550480U, 658981742U, 1113311088U, 3927878744U, 679301322U, 1760465731U, 3305370375U,
        2269115995U, 3928541685U, 580724401U, 2607446661U, 2233092279U, 2416822349U, 4106933702U, 3046442503U
    }};
    for (unsigned i = 0; i < BlockSize; ++i) key.at(i) ^= digest.at((i + 3) % SHA1HashSize);

    SHA1Context context;
    SHA1Calculate(context, key);
    return context;
}

CodecSignature GetCodecSignature(const uint8_t* src) {
    CodecSignature result {};
    result.checksum = LoadLE32Ptr(src); src += 4;
    result.error = *src++;
    result.lastChunkSize = *src;
    return result;
}

void SetCodecSignature(uint8_t* dst, CodecSignature sig) {
    *dst++ = uint8_t(sig.checksum); *dst++ = uint8_t(sig.checksum >> 8);
    *dst++ = uint8_t(sig.checksum >> 16); *dst++ = uint8_t(sig.checksum >> 24);
    *dst++ = sig.error; *dst++ = sig.lastChunkSize; *dst++ = 0; *dst++ = 0;
}

void XorBlock(const std::array<uint32_t, SHA1HashSize>& shaResult, std::array<uint32_t, BlockSize>& out) {
    for (unsigned i = 0; i < BlockSize; ++i) out.at(i) ^= shaResult.at(i % SHA1HashSize);
}

std::size_t codec_decode(uint8_t* pbSrcDst, std::size_t size, const char* pszPassword) {
    std::array<uint32_t, BlockSize> buf {};
    std::array<uint32_t, SHA1HashSize> dst {};
    SHA1Context context = CodecInitKey(pszPassword);
    if (size <= SignatureSize) return 0;
    size -= SignatureSize;
    if (size % BlockSize != 0) return 0;

    for (size_t i = 0; i < size; pbSrcDst += BlockSizeBytes, i += BlockSizeBytes) {
        std::memcpy(buf.data(), pbSrcDst, BlockSizeBytes);
        SHA1Result(context, dst);
        XorBlock(dst, buf);
        SHA1Calculate(context, buf);
        std::memcpy(pbSrcDst, buf.data(), BlockSizeBytes);
    }
    const CodecSignature sig = GetCodecSignature(pbSrcDst);
    if (sig.error > 0) return 0;
    SHA1Result(context, dst);
    if (sig.checksum != dst.at(0)) return 0;
    return size + sig.lastChunkSize - BlockSizeBytes;
}

std::size_t codec_get_encoded_len(std::size_t dwSrcBytes) {
    if (dwSrcBytes % BlockSizeBytes != 0) dwSrcBytes += BlockSizeBytes - (dwSrcBytes % BlockSizeBytes);
    return dwSrcBytes + SignatureSize;
}

void codec_encode(uint8_t* pbSrcDst, std::size_t size, std::size_t size64, const char* pszPassword) {
    std::array<uint32_t, BlockSize> buf {};
    std::array<uint32_t, SHA1HashSize> tmp {};
    std::array<uint32_t, SHA1HashSize> dst {};
    if (size64 != codec_get_encoded_len(size)) return;
    SHA1Context context = CodecInitKey(pszPassword);
    size_t lastChunk = 0;
    while (size != 0) {
        const size_t chunk = std::min(size, BlockSizeBytes);
        buf.fill(0);
        std::memcpy(buf.data(), pbSrcDst, chunk);
        SHA1Result(context, dst);
        SHA1Calculate(context, buf);
        XorBlock(dst, buf);
        std::memcpy(pbSrcDst, buf.data(), BlockSizeBytes);
        pbSrcDst += BlockSizeBytes; lastChunk = chunk; size -= chunk;
    }
    SHA1Result(context, tmp);
    SetCodecSignature(pbSrcDst, CodecSignature { tmp.at(0), 0, uint8_t(lastChunk) });
}

} // namespace devil_codec

#pragma pack(push, 1)
struct ItemPack {
    uint32_t iSeed; uint16_t iCreateInfo; uint16_t idx;
    uint8_t bId; uint8_t bDur; uint8_t bMDur; uint8_t bCh; uint8_t bMCh;
    uint16_t wValue; uint32_t dwBuff;
};

struct PlayerPack {
    uint32_t dwLowDateTime; uint32_t dwHighDateTime;
    int8_t destAction; int8_t destParam1; int8_t destParam2;
    uint8_t plrlevel; uint8_t px; uint8_t py; uint8_t targx; uint8_t targy;
    std::array<char, 32> pName;
    uint8_t pClass; uint8_t pBaseStr; uint8_t pBaseMag; uint8_t pBaseDex; uint8_t pBaseVit;
    uint8_t pLevel; uint8_t pStatPts; uint32_t pExperience; int32_t pGold;
    int32_t pHPBase; int32_t pMaxHPBase; int32_t pManaBase; int32_t pMaxManaBase;
    std::array<uint8_t, 37> pSplLvl;
    uint64_t pMemSpells;
    std::array<ItemPack, 7> InvBody;
    std::array<ItemPack, 40> InvList;
    std::array<int8_t, 40> InvGrid;
    uint8_t _pNumInv;
    std::array<ItemPack, 8> SpdList;
    int8_t pTownWarps; int8_t pDungMsgs; int8_t pLvlLoad;
    uint8_t pBattleNet; uint8_t pManaShield; uint8_t pDungMsgs2;
    int8_t bIsHellfire; uint8_t reserved; uint16_t wReflections;
    std::array<uint8_t, 2> reserved2;
    std::array<uint8_t, 10> pSplLvl2;
    int16_t wReserved8; uint32_t pDiabloKillLevel; uint32_t pDifficulty; uint32_t pDamAcFlags;
    std::array<uint8_t, 20> reserved3;
};
#pragma pack(pop)

constexpr const char* PASSWORD_SINGLE = "xrgyrkj1";
constexpr const char* PASSWORD_MULTI = "szqnlsk1";
constexpr int NUM_SPELLS = 41;
constexpr int NUM_ACTIONS = 11;
constexpr int NUM_STATS = 5;
constexpr int NUM_MENU_ROWS = 15;

struct SpellEntry { int id; const char* name; bool hellfireOnly; };

constexpr std::array<SpellEntry, 41> ALL_SPELLS = {{
    { 1,  "Firebolt", false }, { 2,  "Healing", false }, { 3,  "Lightning", false },
    { 4,  "Flash", false }, { 6,  "Fire Wall", false }, { 7,  "Town Portal", false },
    { 8,  "Stone Curse", false }, { 9,  "Infravision", false }, { 10, "Phasing", false },
    { 11, "Mana Shield", false }, { 12, "Fireball", false }, { 13, "Guardian", false },
    { 14, "Chain Lightning", false }, { 15, "Flame Wave", false }, { 16, "Doom Serpents", false },
    { 17, "Blood Ritual", false }, { 18, "Nova", false }, { 19, "Invisibility", false },
    { 20, "Inferno", false }, { 21, "Golem", false }, { 22, "Blood Boil", false },
    { 23, "Teleport", false }, { 24, "Apocalypse", false }, { 25, "Etherealize", false },
    { 29, "Elemental", false }, { 30, "Charged Bolt", false }, { 31, "Holy Bolt", false },
    { 32, "Resurrect", false }, { 33, "Telekinesis", false }, { 34, "Heal Other", false },
    { 35, "Blood Star", false }, { 36, "Bone Spirit", false },
    { 37, "Mana (Hellfire)", true }, { 38, "Magi (Hellfire)", true }, { 39, "Jester (Hellfire)", true },
    { 40, "Lightning Wall (HF)", true }, { 41, "Immolation (HF)", true }, { 42, "Warp (HF)", true },
    { 43, "Reflect (HF)", true }, { 44, "Berserk (HF)", true }, { 45, "Ring of Fire (HF)", true }
}};

struct MenuState {
    int cursor = 0, dirMode = 0, saveSlot = 0, actionChoice = 0;
    int spellIndex = 1, weaponIndex = 0, armorIndex = 0, specialIndex = 0, potionIndex = 0, scrollIndex = 0, statIndex = 0;
    bool isHellfire = false;
    bool isMultiplayer = false;
};

bool FileExists(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f) { std::fclose(f); return true; }
    return false;
}

const char* GetActivePassword(const MenuState& state) {
    return state.isMultiplayer ? PASSWORD_MULTI : PASSWORD_SINGLE;
}

const char* GetStashEntryName(const MenuState& state) {
    return state.isMultiplayer ? "mpstashitems" : "spstashitems";
}

std::string ResolveDir(const MenuState& state) {
    if (state.dirMode == 1) return "sdmc:/3ds/devil3ds";
    if (state.dirMode == 2) return "sdmc:/3ds/devilutionx";
    const char* prefix = state.isMultiplayer ? "multi" : "single";
    const char* ext = state.isHellfire ? "hsv" : "sv";
    std::array<char, 96> p {};
    std::snprintf(p.data(), p.size(), "sdmc:/3ds/devil3ds/%s_%d.%s", prefix, state.saveSlot, ext);
    if (FileExists(p.data())) return "sdmc:/3ds/devil3ds";
    std::snprintf(p.data(), p.size(), "sdmc:/3ds/devilutionx/%s_%d.%s", prefix, state.saveSlot, ext);
    if (FileExists(p.data())) return "sdmc:/3ds/devilutionx";
    return "sdmc:/3ds/devil3ds";
}

std::string ResolveSavePath(const MenuState& state, bool backup = false) {
    std::array<char, 128> p {};
    std::snprintf(p.data(), p.size(), "%s/%s_%d.%s%s", ResolveDir(state).c_str(),
                  state.isMultiplayer ? "multi" : "single", state.saveSlot,
                  state.isHellfire ? "hsv" : "sv", backup ? ".bak" : "");
    return std::string(p.data());
}

std::string ResolveStashPath(const MenuState& state, bool backup = false) {
    std::array<char, 128> p {};
    std::snprintf(p.data(), p.size(), "%s/stash.%s%s", ResolveDir(state).c_str(),
                  state.isHellfire ? "hsv" : "sv", backup ? ".bak" : "");
    return std::string(p.data());
}

bool BackupFile(const char* src, const char* dst) {
    FILE* in = std::fopen(src, "rb");
    if (!in) return false;
    FILE* out = std::fopen(dst, "wb");
    if (!out) { std::fclose(in); return false; }
    std::array<char, 4096> buf {};
    size_t n = 0;
    while ((n = std::fread(buf.data(), 1, buf.size(), in)) > 0) std::fwrite(buf.data(), 1, n, out);
    std::fclose(in); std::fclose(out);
    return true;
}

void WriteLE32(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    out.at(off + 0) = uint8_t(v); out.at(off + 1) = uint8_t(v >> 8);
    out.at(off + 2) = uint8_t(v >> 16); out.at(off + 3) = uint8_t(v >> 24);
}
void WriteLE16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out.at(off + 0) = uint8_t(v); out.at(off + 1) = uint8_t(v >> 8);
}

// Builds an exact 368-byte (Diablo) or 372-byte (Hellfire) SaveItem record for Stash
std::vector<uint8_t> BuildSerializedItem(const CatalogItem& cat, bool isHellfire, bool magicStaff, uint32_t seed, int posX = 0, int posY = 0) {
    const size_t sz = isHellfire ? 372 : 368;
    std::vector<uint8_t> b(sz, 0);
    uint16_t cinfo = (cat.magical == 2) ? 0x0200 : (magicStaff ? (0x0040 | 30) : 0);
    WriteLE32(b, 0, (cat.magical == 2) ? uint32_t(cat.uid) : seed);
    WriteLE16(b, 4, cinfo);
    WriteLE32(b, 8, uint32_t(cat.itype));
    WriteLE32(b, 12, uint32_t(posX));
    WriteLE32(b, 16, uint32_t(posY));
    WriteLE32(b, 28, 1);   // numberOfFrames = 1
    WriteLE32(b, 32, 1);   // currentFrame + 1 = 1
    WriteLE32(b, 36, 96);  // ItemAnimWidth = 96
    WriteLE32(b, 40, 48);  // CenterX = 48
    WriteLE32(b, 56, 1);   // _iIdentified = true
    b.at(60) = uint8_t(magicStaff && cat.magical == 0 ? 1 : cat.magical);

    std::string dispName = magicStaff ? (std::string("Arcane ") + cat.name) : std::string(cat.name);
    std::strncpy(reinterpret_cast<char*>(b.data() + 61), dispName.c_str(), 63);
    std::strncpy(reinterpret_cast<char*>(b.data() + 125), dispName.c_str(), 63);

    b.at(189) = uint8_t(cat.iloc);
    b.at(190) = uint8_t(cat.iclass);
    WriteLE32(b, 192, uint32_t(cat.curs));
    WriteLE32(b, 196, uint32_t(cat.val));
    WriteLE32(b, 200, uint32_t(cat.val));
    WriteLE32(b, 204, uint32_t(cat.minDam));
    WriteLE32(b, 208, uint32_t(cat.maxDam));
    WriteLE32(b, 212, uint32_t(cat.ac));
    WriteLE32(b, 216, cat.flags);
    WriteLE32(b, 220, uint32_t(cat.imisc));
    WriteLE32(b, 224, uint32_t(cat.spell));
    int charges = (cat.charges > 0) ? cat.charges : ((cat.itype == 10) ? 40 : 0);
    WriteLE32(b, 228, uint32_t(charges));
    WriteLE32(b, 232, uint32_t(charges));
    int dur = (cat.dur > 0) ? cat.dur : ((cat.iclass == 1 || cat.iclass == 2) ? 100 : 0);
    WriteLE32(b, 236, uint32_t(dur));
    WriteLE32(b, 240, uint32_t(dur));

    WriteLE32(b, 244, uint32_t(cat.plDam + (magicStaff ? 50 : 0)));
    WriteLE32(b, 248, uint32_t(cat.plToHit + (magicStaff ? 25 : 0)));
    WriteLE32(b, 252, uint32_t(cat.plAC));
    WriteLE32(b, 256, uint32_t(cat.plStr));
    WriteLE32(b, 260, uint32_t(cat.plMag + (magicStaff ? 20 : 0)));
    WriteLE32(b, 264, uint32_t(cat.plDex));
    WriteLE32(b, 268, uint32_t(cat.plVit));
    WriteLE32(b, 272, uint32_t(cat.plFR));
    WriteLE32(b, 276, uint32_t(cat.plLR));
    WriteLE32(b, 280, uint32_t(cat.plMR));
    WriteLE32(b, 284, uint32_t(cat.plMana + (magicStaff ? 50 : 0)));
    WriteLE32(b, 288, uint32_t(cat.plHP));
    WriteLE32(b, 292, uint32_t(cat.plDamMod));
    WriteLE32(b, 296, uint32_t(cat.plGetHit));
    WriteLE32(b, 300, uint32_t(cat.plLight));
    b.at(304) = uint8_t(cat.splLvlAdd);

    WriteLE32(b, 308, uint32_t(cat.uid));
    WriteLE32(b, 312, uint32_t(cat.fMin));
    WriteLE32(b, 316, uint32_t(cat.fMax));
    WriteLE32(b, 320, uint32_t(cat.lMin));
    WriteLE32(b, 324, uint32_t(cat.lMax));
    WriteLE32(b, 328, uint32_t(cat.plEnAc));

    b.at(332) = 0xFF;
    b.at(333) = 0xFF;
    if (magicStaff) {
        b.at(332) = 0;
        b.at(333) = 2;
        WriteLE32(b, 336, 25);
        WriteLE32(b, 344, 50);
    }

    b.at(352) = uint8_t(cat.minStr);
    b.at(353) = uint8_t(cat.minMag);
    b.at(354) = uint8_t(cat.minDex);
    WriteLE32(b, 356, 1);
    WriteLE32(b, 360, uint32_t(cat.idx));
    WriteLE32(b, 364, isHellfire ? 1U : 0U);
    if (isHellfire) WriteLE32(b, 368, cat.hfFlags);
    return b;
}

// Adds gold or items directly into sdmc:/3ds/devil3ds/stash.sv (or .hsv)
bool AddToSharedStash(const MenuState& state, uint32_t addGold, const CatalogItem* cat, int count, bool magicStaff, std::string& outErr) {
    std::string stashPath = ResolveStashPath(state, false);
    std::string stashBak = ResolveStashPath(state, true);
    const char* entryName = GetStashEntryName(state);
    const char* otherEntry = state.isMultiplayer ? "spstashitems" : "mpstashitems";
    const size_t itemSize = state.isHellfire ? 372 : 368;

    uint32_t gold = 0, currentPage = 0;
    std::vector<uint32_t> pageIds;
    std::vector<std::array<uint16_t, 100>> pageGrids;
    std::vector<uint8_t> itemsBlob;
    std::vector<uint8_t> otherBlob;
    uint32_t itemCount = 0;

    if (FileExists(stashPath)) {
        BackupFile(stashPath.c_str(), stashBak.c_str());
        mpqfs_archive_t* arc = nullptr;
        if (mpqfs_open(stashBak.c_str(), &arc) == MPQFS_OK && arc != nullptr) {
            void* rawOther = nullptr;
            size_t otherSize = 0;
            if (mpqfs_read_file(arc, otherEntry, &rawOther, &otherSize) == MPQFS_OK && rawOther != nullptr) {
                otherBlob.resize(otherSize);
                std::memcpy(otherBlob.data(), rawOther, otherSize);
                std::free(rawOther);
            }
            void* raw = nullptr;
            size_t encSize = 0;
            if (mpqfs_read_file(arc, entryName, &raw, &encSize) == MPQFS_OK && raw != nullptr) {
                std::vector<uint8_t> buf(encSize);
                std::memcpy(buf.data(), raw, encSize);
                std::free(raw);
                size_t decSize = devil_codec::codec_decode(buf.data(), encSize, PASSWORD_SINGLE);
                if (decSize >= 13 && buf.at(0) == 0) {
                    size_t pos = 1;
                    gold = devil_codec::LoadLE32Ptr(buf.data() + pos); pos += 4;
                    uint32_t numPages = devil_codec::LoadLE32Ptr(buf.data() + pos); pos += 4;
                    for (uint32_t p = 0; p < numPages && pos + 204 <= decSize; ++p) {
                        uint32_t pid = devil_codec::LoadLE32Ptr(buf.data() + pos); pos += 4;
                        std::array<uint16_t, 100> grid {};
                        for (int c = 0; c < 100; ++c) {
                            grid.at(c) = uint16_t(buf.at(pos) | (buf.at(pos + 1) << 8));
                            pos += 2;
                        }
                        pageIds.push_back(pid);
                        pageGrids.push_back(grid);
                    }
                    if (pos + 4 <= decSize) {
                        itemCount = devil_codec::LoadLE32Ptr(buf.data() + pos); pos += 4;
                        size_t bytes = size_t(itemCount) * itemSize;
                        if (pos + bytes <= decSize) {
                            itemsBlob.assign(buf.begin() + pos, buf.begin() + pos + bytes);
                            pos += bytes;
                        }
                    }
                    if (pos + 4 <= decSize) currentPage = devil_codec::LoadLE32Ptr(buf.data() + pos);
                }
            }
            mpqfs_close(arc);
        }
    }

    gold += addGold;

    if (cat != nullptr && count > 0) {
        const int w = std::max(1, int(cat->w));
        const int h = std::max(1, int(cat->h));
        int placed = 0;
        for (int n = 0; n < count; ++n) {
            bool done = false;
            for (unsigned pg = 0; pg < 20 && !done; ++pg) {
                auto it = std::find(pageIds.begin(), pageIds.end(), pg);
                size_t idxPg = 0;
                if (it == pageIds.end()) {
                    pageIds.push_back(pg);
                    pageGrids.push_back(std::array<uint16_t, 100> {});
                    idxPg = pageIds.size() - 1;
                } else {
                    idxPg = size_t(it - pageIds.begin());
                }
                auto& grid = pageGrids.at(idxPg);
                for (int r = 0; r <= 10 - h && !done; ++r) {
                    for (int c = 0; c <= 10 - w; ++c) {
                        bool ok = true;
                        for (int dy = 0; dy < h && ok; ++dy)
                            for (int dx = 0; dx < w; ++dx)
                                if (grid.at((c + dx) * 10 + (r + dy)) != 0) ok = false;
                        if (!ok) continue;

                        itemCount++;
                        uint16_t cellVal = uint16_t(itemCount);
                        for (int dy = 0; dy < h; ++dy)
                            for (int dx = 0; dx < w; ++dx)
                                grid.at((c + dx) * 10 + (r + dy)) = cellVal;

                        uint32_t seed = 0x51A7F00D ^ (itemCount * 0x9E3779B9U) ^ (pg * 97U);
                        std::vector<uint8_t> ser = BuildSerializedItem(*cat, state.isHellfire, magicStaff, seed, c, r + h - 1);
                        itemsBlob.insert(itemsBlob.end(), ser.begin(), ser.end());
                        currentPage = pg;
                        placed++;
                        done = true;
                        break;
                    }
                }
            }
        }
        if (placed == 0) { outErr = "ERROR: Stash is full!"; return false; }
    }

    std::vector<uint8_t> plain;
    plain.push_back(0);
    auto push32 = [&plain](uint32_t v) {
        plain.push_back(uint8_t(v)); plain.push_back(uint8_t(v >> 8));
        plain.push_back(uint8_t(v >> 16)); plain.push_back(uint8_t(v >> 24));
    };
    auto push16 = [&plain](uint16_t v) { plain.push_back(uint8_t(v)); plain.push_back(uint8_t(v >> 8)); };

    push32(gold);
    push32(uint32_t(pageIds.size()));
    for (size_t i = 0; i < pageIds.size(); ++i) {
        push32(pageIds.at(i));
        for (int c = 0; c < 100; ++c) push16(pageGrids.at(i).at(c));
    }
    push32(itemCount);
    plain.insert(plain.end(), itemsBlob.begin(), itemsBlob.end());
    push32(currentPage);

    size_t rawLen = plain.size();
    size_t encLen = devil_codec::codec_get_encoded_len(rawLen);
    plain.resize(encLen, 0);
    devil_codec::codec_encode(plain.data(), rawLen, encLen, PASSWORD_SINGLE);

    mpqfs_writer_t* w = nullptr;
    if (mpqfs_writer_create(stashPath.c_str(), 16, &w) != MPQFS_OK || w == nullptr) {
        outErr = "ERROR: Could not write stash!"; return false;
    }
    if (!otherBlob.empty()) {
        (void)mpqfs_writer_add_file(w, otherEntry, otherBlob.data(), otherBlob.size());
    }
    if (mpqfs_writer_add_file(w, entryName, plain.data(), encLen) != MPQFS_OK) {
        mpqfs_writer_discard(w); outErr = "ERROR: Failed to add stash items!"; return false;
    }
    if (mpqfs_writer_close(w) != MPQFS_OK) { outErr = "ERROR: Failed to close stash!"; return false; }
    return true;
}

void UnlockSpell(PlayerPack& hero, int spellId, uint8_t level) {
    if (spellId < 1 || spellId > 46) return;
    hero.pMemSpells |= (1ULL << (spellId - 1));
    if (spellId <= 36) {
        if (hero.pSplLvl.at(spellId) < level) hero.pSplLvl.at(spellId) = level;
    } else {
        int hfIdx = spellId - 37;
        if (hfIdx >= 0 && hfIdx < 10 && hero.pSplLvl2.at(hfIdx) < level) hero.pSplLvl2.at(hfIdx) = level;
    }
}

void ApplyStatBoost(PlayerPack& hero, int statIndex) {
    auto addCap = [](uint8_t& val, int add) { int next = int(val) + add; val = uint8_t(next > 255 ? 255 : next); };
    const int hpPerVit = (hero.pClass == 0 || hero.pClass == 5) ? 2 : 1;
    const int manaPerMag = (hero.pClass == 2) ? 2 : 1;
    if (statIndex == 0) addCap(hero.pBaseStr, 25);
    else if (statIndex == 1) {
        int oldMag = hero.pBaseMag; addCap(hero.pBaseMag, 25);
        int delta = (int(hero.pBaseMag) - oldMag) * manaPerMag * 64;
        hero.pMaxManaBase += delta; hero.pManaBase += delta;
    } else if (statIndex == 2) addCap(hero.pBaseDex, 25);
    else if (statIndex == 3) {
        int oldVit = hero.pBaseVit; addCap(hero.pBaseVit, 25);
        int delta = (int(hero.pBaseVit) - oldVit) * hpPerVit * 64;
        hero.pMaxHPBase += delta; hero.pHPBase += delta;
    } else {
        int oldMag = hero.pBaseMag, oldVit = hero.pBaseVit;
        hero.pBaseStr = 255; hero.pBaseMag = 255; hero.pBaseDex = 255; hero.pBaseVit = 255;
        int dMana = (255 - oldMag) * manaPerMag * 64;
        int dHP = (255 - oldVit) * hpPerVit * 64;
        hero.pMaxManaBase += dMana; hero.pManaBase += dMana;
        hero.pMaxHPBase += dHP; hero.pHPBase += dHP;
    }
}

int MapRowToAction(int cursor) {
    switch (cursor) {
    case 4:  return 0;  // Gold (+100,000)
    case 5:  return 7;  // Selected Spell
    case 6:  return 8;  // Learn All 41 Spells
    case 7:  return 1;  // Base Weapon
    case 8:  return 2;  // Magic Weapon / Staff
    case 9:  return 3;  // Base Armor
    case 10: return 4;  // Unique / Special Item
    case 11: return 5;  // Potion (x5)
    case 12: return 6;  // Scroll (x5)
    case 13: return 9;  // Base Stat Boost
    case 14: return 10; // Enable Test Classes (Bard/Barbarian)
    default: return 0;
    }
}

void DrawUI(const MenuState& state, const std::string& statusMsg) {
    consoleClear();
    printf("==================================================\n");
    printf("          Devil-3DS Save Editor (v1.0)          \n");
    printf("==================================================\n");
    const std::array<const char*, 3> dirNames = { "Auto-Detect", "devil3ds", "devilutionx" };
    const std::array<const char*, NUM_ACTIONS> actionNames = {
        "Add +100,000 Gold to Stash", "Add Weapon to Stash", "Add Magic Weapon/Staff to Stash",
        "Add Armor to Stash", "Add Unique / Special to Stash", "Add 5x Potion to Stash",
        "Add 5x Scroll to Stash", "Learn Selected Spell (Lv.15)",
        "Learn All 41 Spells (Lv.15)", "Apply Base Stat Boost",
        "Enable Test Classes (Bard/Barb)"
    };
    const std::array<const char*, NUM_STATS> statNames = {
        "Strength (+25)", "Magic (+25)", "Dexterity (+25)", "Vitality (+25)", "All Base Stats = 255"
    };

    std::string resolvedPath = ResolveSavePath(state, false);
    std::string iniPath = ResolveDir(state) + "/diablo.ini";
    const char* wpnName = ALL_WEAPONS.empty() ? "None" : ALL_WEAPONS.at(state.weaponIndex).name;
    const char* armName = ALL_ARMOR.empty() ? "None" : ALL_ARMOR.at(state.armorIndex).name;
    const char* spcName = ALL_SPECIALS.empty() ? "None" : ALL_SPECIALS.at(state.specialIndex).name;
    const char* potName = ALL_POTIONS.empty() ? "None" : ALL_POTIONS.at(state.potionIndex).name;
    const char* scrName = ALL_SCROLLS.empty() ? "None" : ALL_SCROLLS.at(state.scrollIndex).name;

    auto printRow = [&](int rowIdx, const char* label, const std::string& val) {
        if (state.cursor == rowIdx) {
            printf("\x1b[30;46m>> %-7s: %-37.37s\x1b[0m\n", label, val.c_str());
        } else {
            printf("   %-7s: %-37.37s\n", label, val.c_str());
        }
    };

    std::array<char, 128> buf {};
    printRow(0, "Dir", dirNames.at(state.dirMode));
    std::snprintf(buf.data(), buf.size(), "%s_%d", state.isMultiplayer ? "multi" : "single", state.saveSlot);
    printRow(1, "Slot", buf.data());
    printRow(2, "Type", state.isMultiplayer ? "Multiplayer" : "Single Player");
    printRow(3, "Mode", state.isHellfire ? "Hellfire (.hsv)" : "Diablo (.sv)");
    printf(" Save : %-31.31s [%s]\n", resolvedPath.c_str(), FileExists(resolvedPath) ? "OK" : "MISSING");
    printf(" INI  : %-31.31s [%s]\n", iniPath.c_str(), FileExists(iniPath) ? "OK" : "MISSING");
    printf("--------------------------------------------------\n");

    const char* activeDesc = (state.cursor < 4) ? "Change Dir / Slot / Type / Mode" : actionNames.at(MapRowToAction(state.cursor));
    printf("\x1b[33m Action : %-39.39s\x1b[0m\n", activeDesc);
    printf("--------------------------------------------------\n");

    printRow(4, "Gold", "+100,000 Gold -> Stash");
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.spellIndex + 1, NUM_SPELLS, ALL_SPELLS.at(state.spellIndex).name);
    printRow(5, "Spell", buf.data());
    printRow(6, "AllSpl", "Learn All 41 Spells (Lv.15)");
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.weaponIndex + 1, int(ALL_WEAPONS.size()), wpnName);
    printRow(7, "Weapon", buf.data());
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) Arcane %s", state.weaponIndex + 1, int(ALL_WEAPONS.size()), wpnName);
    printRow(8, "MagicWp", buf.data());
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.armorIndex + 1, int(ALL_ARMOR.size()), armName);
    printRow(9, "Armor", buf.data());
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.specialIndex + 1, int(ALL_SPECIALS.size()), spcName);
    printRow(10, "Special", buf.data());
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.potionIndex + 1, int(ALL_POTIONS.size()), potName);
    printRow(11, "Potion", buf.data());
    std::snprintf(buf.data(), buf.size(), "(%02d/%02d) %s", state.scrollIndex + 1, int(ALL_SCROLLS.size()), scrName);
    printRow(12, "Scroll", buf.data());
    printRow(13, "Stat", statNames.at(state.statIndex));
    printRow(14, "Classes", "Enable Bard & Barbarian (diablo.ini)");

    printf("--------------------------------------------------\n");
    printf(" Result : %-39.39s\n", statusMsg.empty() ? "Ready." : statusMsg.c_str());
    printf("--------------------------------------------------\n");
    printf("     Up/Dn: Row | L/R: Change | L/R Btn: +/-5\n");
    printf("        A: Apply | B: Undo | Start: Exit\n");
}

bool WriteTestClassesToIni(const std::string& dir) {
    std::string iniPath = dir + "/diablo.ini";
    std::string iniBak = dir + "/diablo.ini.bak";

    std::vector<std::string> lines;
    if (FileExists(iniPath)) {
        BackupFile(iniPath.c_str(), iniBak.c_str());
        FILE* f = std::fopen(iniPath.c_str(), "r");
        if (f) {
            std::array<char, 512> lineBuf {};
            while (std::fgets(lineBuf.data(), lineBuf.size(), f)) {
                std::string s(lineBuf.data());
                while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
                lines.push_back(s);
            }
            std::fclose(f);
        }
    }

    bool inHellfire = false;
    bool foundHellfire = false;
    bool setBard = false;
    bool setBarb = false;
    std::vector<std::string> outLines;

    for (const auto& line : lines) {
        if (!line.empty() && line.front() == '[' && line.back() == ']') {
            if (inHellfire) {
                if (!setBard) { outLines.push_back("Test Bard=1"); setBard = true; }
                if (!setBarb) { outLines.push_back("Test Barbarian=1"); setBarb = true; }
            }
            inHellfire = (line == "[Hellfire]");
            if (inHellfire) foundHellfire = true;
            outLines.push_back(line);
            continue;
        }
        if (inHellfire) {
            if (line.rfind("Test Bard=", 0) == 0) {
                outLines.push_back("Test Bard=1");
                setBard = true;
                continue;
            }
            if (line.rfind("Test Barbarian=", 0) == 0) {
                outLines.push_back("Test Barbarian=1");
                setBarb = true;
                continue;
            }
        }
        outLines.push_back(line);
    }

    if (inHellfire) {
        if (!setBard) outLines.push_back("Test Bard=1");
        if (!setBarb) outLines.push_back("Test Barbarian=1");
    } else if (!foundHellfire) {
        if (!outLines.empty() && !outLines.back().empty()) outLines.push_back("");
        outLines.push_back("[Hellfire]");
        outLines.push_back("Test Bard=1");
        outLines.push_back("Test Barbarian=1");
    }

    FILE* out = std::fopen(iniPath.c_str(), "w");
    if (!out) return false;
    for (const auto& l : outLines) std::fprintf(out, "%s\n", l.c_str());
    std::fclose(out);
    return true;
}

std::vector<std::string> GetTargetIniDirs(const MenuState& state) {
    if (state.dirMode == 1) return { "sdmc:/3ds/devil3ds" };
    if (state.dirMode == 2) return { "sdmc:/3ds/devilutionx" };

    std::vector<std::string> dirs;
    const std::array<const char*, 2> candidates = { "sdmc:/3ds/devil3ds", "sdmc:/3ds/devilutionx" };
    for (const char* d : candidates) {
        bool hasAny = FileExists(std::string(d) + "/diablo.ini");
        for (int s = 0; s < 4 && !hasAny; ++s) {
            std::array<char, 128> buf {};
            std::snprintf(buf.data(), buf.size(), "%s/single_%d.sv", d, s);
            if (FileExists(buf.data())) hasAny = true;
            std::snprintf(buf.data(), buf.size(), "%s/single_%d.hsv", d, s);
            if (FileExists(buf.data())) hasAny = true;
        }
        if (hasAny) dirs.push_back(d);
    }
    if (dirs.empty()) dirs.push_back("sdmc:/3ds/devil3ds");
    return dirs;
}

std::string EnableTestClassesIni(const MenuState& state) {
    std::vector<std::string> dirs = GetTargetIniDirs(state);
    int updated = 0;
    for (const auto& d : dirs) {
        if (WriteTestClassesToIni(d)) updated++;
    }
    if (updated == 0) return "ERROR: Could not write diablo.ini!";
    if (dirs.size() > 1 && updated > 1)
        return "SUCCESS: Enabled Bard/Barb in both folders!";
    return "SUCCESS: Enabled Bard & Barbarian in diablo.ini!";
}

std::string UndoLastAction(const MenuState& state, int lastTarget) {
    // lastTarget: 1 = stash, 2 = character save, 0 = auto-check both
    std::string stashPath = ResolveStashPath(state, false);
    std::string stashBak = ResolveStashPath(state, true);
    std::string savePath = ResolveSavePath(state, false);
    std::string saveBak = ResolveSavePath(state, true);

    if (lastTarget == 1 && FileExists(stashBak)) {
        if (BackupFile(stashBak.c_str(), stashPath.c_str()))
            return "UNDO: Restored previous Stash!";
    }
    if (lastTarget == 2 && FileExists(saveBak)) {
        if (BackupFile(saveBak.c_str(), savePath.c_str()))
            return "UNDO: Restored previous Character Save!";
    }
    if (lastTarget == 3) {
        bool restoredIni = false;
        for (const auto& d : GetTargetIniDirs(state)) {
            std::string iniPath = d + "/diablo.ini";
            std::string iniBak = d + "/diablo.ini.bak";
            if (FileExists(iniBak) && BackupFile(iniBak.c_str(), iniPath.c_str()))
                restoredIni = true;
        }
        if (restoredIni) return "UNDO: Restored previous diablo.ini!";
    }
    bool restoredAny = false;
    if (FileExists(stashBak) && BackupFile(stashBak.c_str(), stashPath.c_str())) restoredAny = true;
    if (FileExists(saveBak) && BackupFile(saveBak.c_str(), savePath.c_str())) restoredAny = true;
    if (restoredAny) return "UNDO: Restored backup save/stash!";
    return "UNDO: No backup (.bak) found for this slot.";
}

std::string ExecuteSaveEdit(const MenuState& state) {
    std::array<char, 160> msg {};
    std::string err;

    // Actions 0..6 write directly into Stash (stash.sv / stash.hsv)
    if (state.actionChoice == 0) {
        if (!AddToSharedStash(state, 100000, nullptr, 0, false, err)) return err;
        return "SUCCESS: Added +100,000 Gold to Stash!";
    } else if (state.actionChoice == 1 && !ALL_WEAPONS.empty()) {
        const CatalogItem& w = ALL_WEAPONS.at(state.weaponIndex);
        if (!AddToSharedStash(state, 0, &w, 1, false, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added %s to Stash!", w.name);
        return std::string(msg.data());
    } else if (state.actionChoice == 2 && !ALL_WEAPONS.empty()) {
        const CatalogItem& w = ALL_WEAPONS.at(state.weaponIndex);
        if (!AddToSharedStash(state, 0, &w, 1, true, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added Arcane %s to Stash!", w.name);
        return std::string(msg.data());
    } else if (state.actionChoice == 3 && !ALL_ARMOR.empty()) {
        const CatalogItem& a = ALL_ARMOR.at(state.armorIndex);
        if (!AddToSharedStash(state, 0, &a, 1, false, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added %s to Stash!", a.name);
        return std::string(msg.data());
    } else if (state.actionChoice == 4 && !ALL_SPECIALS.empty()) {
        const CatalogItem& spc = ALL_SPECIALS.at(state.specialIndex);
        if (!AddToSharedStash(state, 0, &spc, 1, false, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added %s to Stash!", spc.name);
        return std::string(msg.data());
    } else if (state.actionChoice == 5 && !ALL_POTIONS.empty()) {
        const CatalogItem& p = ALL_POTIONS.at(state.potionIndex);
        if (!AddToSharedStash(state, 0, &p, 5, false, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added 5x %s to Stash!", p.name);
        return std::string(msg.data());
    } else if (state.actionChoice == 6 && !ALL_SCROLLS.empty()) {
        const CatalogItem& s = ALL_SCROLLS.at(state.scrollIndex);
        if (!AddToSharedStash(state, 0, &s, 5, false, err)) return err;
        std::snprintf(msg.data(), msg.size(), "SUCCESS: Added 5x %s to Stash!", s.name);
        return std::string(msg.data());
    }

    if (state.actionChoice == 10) {
        return EnableTestClassesIni(state);
    }

    // Actions 7..9 update character Spells & Base Stats in both "hero" and active "game"
    std::string savePath = ResolveSavePath(state, false), backupPath = ResolveSavePath(state, true);
    if (!BackupFile(savePath.c_str(), backupPath.c_str())) return "ERROR: Save file not found!";

    mpqfs_archive_t* oldArchive = nullptr;
    if (mpqfs_open(backupPath.c_str(), &oldArchive) != MPQFS_OK || oldArchive == nullptr) return "ERROR: Failed to open MPQ.";

    void* rawHero = nullptr;
    size_t fileSize = 0;
    if (mpqfs_read_file(oldArchive, "hero", &rawHero, &fileSize) != MPQFS_OK || rawHero == nullptr) {
        mpqfs_close(oldArchive); return "ERROR: 'hero' missing.";
    }

    const size_t expectedEncodedSize = devil_codec::codec_get_encoded_len(sizeof(PlayerPack));
    if (fileSize != expectedEncodedSize) {
        std::free(rawHero); mpqfs_close(oldArchive); return "ERROR: Encoded size mismatch!";
    }

    std::array<uint8_t, 1288> encodedBuf {};
    std::memcpy(encodedBuf.data(), rawHero, expectedEncodedSize);
    std::free(rawHero);

    if (devil_codec::codec_decode(encodedBuf.data(), expectedEncodedSize, GetActivePassword(state)) != sizeof(PlayerPack)) {
        mpqfs_close(oldArchive); return "ERROR: Codec decode failed!";
    }

    PlayerPack hero {};
    std::memcpy(&hero, encodedBuf.data(), sizeof(PlayerPack));
    hero.pName.at(31) = '\0';

    if (state.actionChoice == 7) {
        const SpellEntry& sp = ALL_SPELLS.at(state.spellIndex);
        UnlockSpell(hero, sp.id, 15);
        std::snprintf(msg.data(), msg.size(), "SUCCESS (%s): Learned %s Lv.15!", hero.pName.data(), sp.name);
    } else if (state.actionChoice == 8) {
        for (int i = 0; i < NUM_SPELLS; ++i)
            if (!ALL_SPELLS.at(i).hellfireOnly || state.isHellfire) UnlockSpell(hero, ALL_SPELLS.at(i).id, 15);
        std::snprintf(msg.data(), msg.size(), "SUCCESS (%s): Learned All 41 Spells!", hero.pName.data());
    } else {
        ApplyStatBoost(hero, state.statIndex);
        std::snprintf(msg.data(), msg.size(), "SUCCESS (%s): STR:%u MAG:%u DEX:%u VIT:%u",
                      hero.pName.data(), hero.pBaseStr, hero.pBaseMag, hero.pBaseDex, hero.pBaseVit);
    }

    std::array<uint8_t, 1288> outBuf {};
    std::memcpy(outBuf.data(), &hero, sizeof(PlayerPack));
    devil_codec::codec_encode(outBuf.data(), sizeof(PlayerPack), expectedEncodedSize, GetActivePassword(state));

    mpqfs_writer_t* writer = nullptr;
    if (mpqfs_writer_create(savePath.c_str(), 2048, &writer) != MPQFS_OK || writer == nullptr) {
        mpqfs_close(oldArchive); return "ERROR: Failed to create MPQ writer.";
    }

    (void)mpqfs_writer_carry_forward_all(writer, oldArchive);
    mpqfs_close(oldArchive);

    // Also patch active "game" snapshot if present so Continue / Load Game works immediately
    mpqfs_archive_t* gameArc = nullptr;
    if (mpqfs_open(backupPath.c_str(), &gameArc) == MPQFS_OK && gameArc != nullptr) {
        void* rawGame = nullptr;
        size_t gameEncSize = 0;
        if (mpqfs_read_file(gameArc, "game", &rawGame, &gameEncSize) == MPQFS_OK && rawGame != nullptr && gameEncSize > 256) {
            std::vector<uint8_t> gBuf(gameEncSize);
            std::memcpy(gBuf.data(), rawGame, gameEncSize);
            std::free(rawGame);
            size_t gDecSize = devil_codec::codec_decode(gBuf.data(), gameEncSize, GetActivePassword(state));
            if (gDecSize > 512) {
                for (size_t off = 128; off + 136 < gDecSize; ++off) {
                    if (std::memcmp(gBuf.data() + off, hero.pName.data(), 32) == 0 &&
                        gBuf.at(off + 32) == hero.pClass &&
                        gBuf.at(off + 120) == hero.pLevel) {
                        // Sync _pSplLvl[1..45] and _pMemSpells
                        for (int s = 1; s <= 36; ++s) gBuf.at(off - 127 + s) = hero.pSplLvl.at(s);
                        for (int s = 37; s <= 45; ++s) gBuf.at(off - 127 + s) = hero.pSplLvl2.at(s - 37);
                        for (int b = 0; b < 8; ++b) gBuf.at(off - 56 + b) = uint8_t(hero.pMemSpells >> (b * 8));
                        // Sync Base & Current Stats + HP/Mana
                        WriteLE32(gBuf, off + 36, hero.pBaseStr); WriteLE32(gBuf, off + 40, hero.pBaseStr);
                        WriteLE32(gBuf, off + 44, hero.pBaseMag); WriteLE32(gBuf, off + 48, hero.pBaseMag);
                        WriteLE32(gBuf, off + 52, hero.pBaseDex); WriteLE32(gBuf, off + 56, hero.pBaseDex);
                        WriteLE32(gBuf, off + 60, hero.pBaseVit); WriteLE32(gBuf, off + 64, hero.pBaseVit);
                        WriteLE32(gBuf, off + 80, uint32_t(hero.pHPBase)); WriteLE32(gBuf, off + 84, uint32_t(hero.pMaxHPBase));
                        WriteLE32(gBuf, off + 88, uint32_t(hero.pHPBase)); WriteLE32(gBuf, off + 92, uint32_t(hero.pMaxHPBase));
                        WriteLE32(gBuf, off + 100, uint32_t(hero.pManaBase)); WriteLE32(gBuf, off + 104, uint32_t(hero.pMaxManaBase));
                        WriteLE32(gBuf, off + 108, uint32_t(hero.pManaBase)); WriteLE32(gBuf, off + 112, uint32_t(hero.pMaxManaBase));
                        size_t gNewEnc = devil_codec::codec_get_encoded_len(gDecSize);
                        gBuf.resize(gNewEnc, 0);
                        devil_codec::codec_encode(gBuf.data(), gDecSize, gNewEnc, GetActivePassword(state));
                        (void)mpqfs_writer_remove_file(writer, "game");
                        (void)mpqfs_writer_add_file(writer, "game", gBuf.data(), gNewEnc);
                        break;
                    }
                }
            }
        }
        mpqfs_close(gameArc);
    }

    (void)mpqfs_writer_remove_file(writer, "hero");
    if (mpqfs_writer_add_file(writer, "hero", outBuf.data(), expectedEncodedSize) != MPQFS_OK) {
        mpqfs_writer_discard(writer); return "ERROR: Failed to write hero.";
    }
    if (mpqfs_writer_close(writer) != MPQFS_OK) return "ERROR: Failed to close MPQ.";

    return std::string(msg.data());
}

int main(int argc, char* argv[]) {
    gfxInitDefault();
    consoleInit(GFX_TOP, nullptr);
    MenuState state;
    std::string statusMsg = "Ready.";
    int lastEditTarget = 0;
    bool needsRedraw = true;

    auto stepIndex = [](int& idx, int total, int delta) {
        if (total <= 0) return;
        idx = ((idx + delta) % total + total) % total;
    };

    while (aptMainLoop()) {
        hidScanInput();
        u32 kDown = hidKeysDown();
        if (kDown & KEY_START) break;

        if (kDown & KEY_UP) { state.cursor = (state.cursor + NUM_MENU_ROWS - 1) % NUM_MENU_ROWS; needsRedraw = true; }
        if (kDown & KEY_DOWN) { state.cursor = (state.cursor + 1) % NUM_MENU_ROWS; needsRedraw = true; }

        int step = 0;
        if (kDown & KEY_LEFT) step = -1;
        else if (kDown & KEY_RIGHT) step = 1;
        else if (kDown & KEY_L) step = -5;
        else if (kDown & KEY_R) step = 5;

        if (step != 0) {
            if (state.cursor == 0) stepIndex(state.dirMode, 3, step > 0 ? 1 : -1);
            else if (state.cursor == 1) stepIndex(state.saveSlot, 4, step > 0 ? 1 : -1);
            else if (state.cursor == 2) state.isMultiplayer = !state.isMultiplayer;
            else if (state.cursor == 3) state.isHellfire = !state.isHellfire;
            else if (state.cursor == 5) stepIndex(state.spellIndex, NUM_SPELLS, step);
            else if (state.cursor == 7 || state.cursor == 8) stepIndex(state.weaponIndex, int(ALL_WEAPONS.size()), step);
            else if (state.cursor == 9) stepIndex(state.armorIndex, int(ALL_ARMOR.size()), step);
            else if (state.cursor == 10) stepIndex(state.specialIndex, int(ALL_SPECIALS.size()), step);
            else if (state.cursor == 11) stepIndex(state.potionIndex, int(ALL_POTIONS.size()), step);
            else if (state.cursor == 12) stepIndex(state.scrollIndex, int(ALL_SCROLLS.size()), step);
            else if (state.cursor == 13) stepIndex(state.statIndex, NUM_STATS, step > 0 ? 1 : -1);
            needsRedraw = true;
        }

        if (kDown & KEY_A) {
            if (state.cursor == 0) stepIndex(state.dirMode, 3, 1);
            else if (state.cursor == 1) stepIndex(state.saveSlot, 4, 1);
            else if (state.cursor == 2) state.isMultiplayer = !state.isMultiplayer;
            else if (state.cursor == 3) state.isHellfire = !state.isHellfire;
            else {
                state.actionChoice = MapRowToAction(state.cursor);
                lastEditTarget = (state.actionChoice <= 6) ? 1 : ((state.actionChoice == 10) ? 3 : 2);
                statusMsg = ExecuteSaveEdit(state);
            }
            needsRedraw = true;
        }

        if (kDown & KEY_B) {
            statusMsg = UndoLastAction(state, lastEditTarget);
            needsRedraw = true;
        }

        if (needsRedraw) { DrawUI(state, statusMsg); needsRedraw = false; }gfxFlushBuffers(); gfxSwapBuffers(); gspWaitForVBlank();
}
gfxExit();
return 0;
}
