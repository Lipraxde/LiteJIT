#ifndef LITEJIT_LITEJIT_H
#define LITEJIT_LITEJIT_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <elf.h>
#include <errno.h>

#if defined(__x86_64__) || defined(__amd64__)
#define ELF_WORD_SIZE 64
#else
#define ELF_WORD_SIZE 32
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

private:
  using SymbolMapTy = std::map<std::string, uintptr_t>;
  using InitFTy = void (*)();
  using FiniFTy = void (*)();

  const unsigned MemSize;
  char *base;
  char *text;
  uintptr_t *got;
  AllocatedSecsTy SecMemTmp; // Temporary record {sec_number, allocated_addr}
  SymbolMapTy SymbolMap;     // Aka. defined symbol map (map[name] = &sym)
  SymbolMapTy GOTSymbolMap;  // Aka. declared symbol map (map[name] = &got[sym])
  std::vector<FiniFTy> fini;

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

  // Return: {err, ptr}
  std::pair<int, uintptr_t *> allocateGOT(const std::string &name) {
    if (text <= (char *)got) {
      GOTSymbolMap.insert({name, (uintptr_t)got});
      return std::make_pair(0, got--);
    } else
      return std::make_pair(ENOMEM, nullptr);
  }

  // Return: {err, ptr}
  std::pair<int, uintptr_t *> getOrAllocateGOT(const std::string &name) {
    auto IT = GOTSymbolMap.find(name);
    if (IT != GOTSymbolMap.end())
      return {0, (uintptr_t *)IT->second};
    return allocateGOT(name);
  }

  // Return: {err, ptr}
  std::pair<int, uintptr_t *> placeGOT(const std::string &name, uintptr_t val) {
    auto [err, _got] = getOrAllocateGOT(name);
    if (err)
      return {err, nullptr};
    *_got = val;
    return {err, _got};
  }

  int allocate(Elf_Ehdr *);
  int relocate(Elf_Ehdr *);

  int do_elf_relc(Elf_Ehdr *elf, uint32_t symtab, Elf_Rel *rel, char *base);
  int do_elf_relca(Elf_Ehdr *elf, uint32_t symtab, Elf_Rela *rel, char *base);

public:
  // MemSize: nKB
  static std::unique_ptr<LiteJIT> createLiteJIT(unsigned MemSize = 64);
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

  void *lookup(const std::string &name) const {
    auto IT = SymbolMap.find(name);
    if (IT != SymbolMap.end())
      return (void *)IT->second;
    return nullptr;
  }

  void *lookup(const char *name) const { return lookup(std::string(name)); }

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