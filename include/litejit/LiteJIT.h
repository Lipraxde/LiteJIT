#ifndef LITEJIT_LITEJIT_H
#define LITEJIT_LITEJIT_H

#include "litejit-config.h"

#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <elf.h>
#include <errno.h>

#if defined(__x86_64__) || defined(__amd64__) ||                               \
    (defined(__riscv) && (__riscv_xlen == 64))
#define ELF_WORD_SIZE 64
#else
#error Unknown ELF_WORD_SIZE
#endif

#define __CAT1(a, b)           a##b
#define __CAT(a, b)            __CAT1(a, b)
#define __ElfN(prefix, suffix) __CAT(__CAT(prefix, ELF_WORD_SIZE), suffix)

#define Elf_Ehdr                 __ElfN(Elf, _Ehdr)
#define Elf_Shdr                 __ElfN(Elf, _Shdr)
#define Elf_Rel                  __ElfN(Elf, _Rel)
#define Elf_Rela                 __ElfN(Elf, _Rela)
#define Elf_Sym                  __ElfN(Elf, _Sym)
#define ELF_R_TYPE(info)         __ElfN(ELF, _R_TYPE)(info)
#define ELF_R_SYM(info)          __ElfN(ELF, _R_SYM)(info)
#define ELF_ST_BIND(info)        __ElfN(ELF, _ST_BIND)(info)
#define ELF_ST_VISIBILITY(other) __ElfN(ELF, _ST_VISIBILITY)(other)
#define ELF_ST_BIND(info)        __ElfN(ELF, _ST_BIND)(info)
#define ELF_ST_TYPE(info)        __ElfN(ELF, _ST_TYPE)(info)
#define uint_t                   __ElfN(uint, _t)

namespace litejit {

class LiteJIT {
public:
  using AllocatedSecTy = std::pair<uint_t, char *>; // {n, addr}
  using AllocatedSecsTy = std::vector<AllocatedSecTy>;
  using SymbolFinderTy = void *(*)(const char *);
  using RegisterSymbolEventTy = bool (*)(const char *, void *);
  using DeleteSymbolEventTy = void (*)(const char *);

private:
  using SymbolMapTy = std::map<std::string, uintptr_t>;
  using InitFTy = void (*)();
  using FiniFTy = void (*)();

  const unsigned MemSize;
  char *const base;
  char *text;
  uintptr_t *got;
  AllocatedSecsTy SecMemTmp; // Temporary record {sec_number, allocated_addr}
#if !LITEJIT_DISABLE_LOOKUP
  SymbolMapTy SymbolMap; // Aka. defined symbol map (map[name] = &sym)
#endif
  SymbolMapTy GOTSymbolMap; // Aka. declared symbol map (map[name] = &got[sym])
  std::vector<FiniFTy> fini;
  std::vector<void *> eh_frame;
  SymbolFinderTy SymbolFinder = defaultSymbolFinder;
  std::vector<std::string> HasDeleteEventSymbol;
  RegisterSymbolEventTy RegisterSymbolEvent = nullptr;
  DeleteSymbolEventTy DeleteSymbolEvent = nullptr;

  LiteJIT(unsigned MemSize, char *base);

  // Return: {err, ptr}
  std::pair<int, char *> allocateText(size_t size, uint64_t align = 1) {
    char *orig_text = text;
    char *ret = (char *)(((uintptr_t)text + align - 1) / align * align);
    text = ret + size;
    if (text > (char *)got) {
      text = orig_text;
      return std::make_pair(ENOMEM, nullptr);
    }
    return std::make_pair(0, ret);
  }

  uintptr_t *allocateGOT(const std::string &name) {
    if (text <= (char *)(--got)) {
      GOTSymbolMap.insert({name, (uintptr_t)got});
      *got = 0;
      return got;
    } else {
      ++got;
      return nullptr;
    }
  }

  uintptr_t *getOrAllocateGOT(const std::string &name) {
    auto IT = GOTSymbolMap.find(name);
    if (IT != GOTSymbolMap.end())
      return (uintptr_t *)IT->second;
    return allocateGOT(name);
  }

  uintptr_t *placeGOT(const std::string &name, uintptr_t val) {
    uintptr_t *_got = getOrAllocateGOT(name);
    if (_got != nullptr)
      *_got = val;
    return _got;
  }

  int allocate(Elf_Ehdr *);
  int relocate(Elf_Ehdr *);

  int do_elf_relc(Elf_Ehdr *elf, Elf_Shdr *, uint32_t symtab, Elf_Rel *rel,
                  char *base);
  int do_elf_relca(Elf_Ehdr *elf, Elf_Shdr *, uint32_t symtab, Elf_Rela *rel,
                   char *base);

public:
  // MemSize: nKB
  static std::unique_ptr<LiteJIT> createLiteJIT(unsigned MemSize = 64,
                                                void *memory = nullptr);
  ~LiteJIT();

  // Only support the relocatable file (For the shared object, why not just use
  // dlopen and dlclose?). Also, the relocatable file should not compiled with
  // -fno-PIC flag. Because the base is allocated by mmap, the distance between
  // the position (where to be relocated) and the symbol may be out of bound.
  // The safe compilation command: cc -fPIC -c foo.c
  // TODO: support -fno-PIC (leverage main program? or change mcmodel?)
  // TODO: support relx
  int addElf(char *elf);
  int addElf(int fd);
  int addElf(const char *Path);
  int addC(const char *c);

  void clear();

  // The symbol finder is used to find the undefined symbol
  void setSymbolFinder(SymbolFinderTy finder) { SymbolFinder = finder; }

  // The handler return true for the symbol has delete event
  void setRegisterSymbolEvent(RegisterSymbolEventTy handler) {
    RegisterSymbolEvent = handler;
  }

  void setDeleteSymbolEvent(DeleteSymbolEventTy handler) {
    DeleteSymbolEvent = handler;
  }

  // Aka. dlsym(nullptr, name)
  static void *defaultSymbolFinder(const char *);

#if !LITEJIT_DISABLE_LOOKUP
  void *lookup(const std::string &name) const {
    auto IT = SymbolMap.find(name);
    if (IT != SymbolMap.end())
      return (void *)IT->second;
    return nullptr;
  }

  void *lookup(const char *name) const { return lookup(std::string(name)); }
#endif

  void dump(std::ostream &, bool detail = false) const;

  // For internal usage
  static char *find_allocated_base(uint_t, const AllocatedSecsTy &);
  // For internal usage
  char *find_allocated_base(uint_t i) const {
    return find_allocated_base(i, SecMemTmp);
  }
};

} // namespace litejit

#endif // LITEJIT_LITEJIT_H
