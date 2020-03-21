#include "litejit/LiteJIT.h"

#include <algorithm>
#include <functional>
#include <utility>
#include <vector>

#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

#if LITEJIT_IGNORE_ERR
#define error_ret(val)                                                         \
  do {                                                                         \
    return val;                                                                \
  } while (0)
#else
#if defined(NDEBUG)
#define error_ret(val)                                                         \
  do {                                                                         \
    abort();                                                                   \
  } while (0)
#else
#define error_ret(val)                                                         \
  do {                                                                         \
    assert(false);                                                             \
    return val;                                                                \
  } while (0)
#endif
#endif

#define ASSERT_WORD32(v)                                                       \
  assert((int64_t)(v) < INT32_MAX && (int64_t)(v) > INT32_MIN);

#define write8(loc, val)    *(uint8_t *)(loc) = (val);
#define write16(loc, val)   *(uint16_t *)(loc) = (val);
#define write32(loc, val)   *(uint32_t *)(loc) = (val);
#define write64(loc, val)   *(uint64_t *)(loc) = (val);
#define write8le(loc, val)  write8(loc, val)
#define write16le(loc, val) write16(loc, val)
#define write32le(loc, val) write32(loc, val)
#define write64le(loc, val) write64(loc, val)
#define read8(loc)          *(uint8_t *)(loc)
#define read16(loc)         *(uint16_t *)(loc)
#define read32(loc)         *(uint32_t *)(loc)
#define read64(loc)         *(uint64_t *)(loc)
#define read8le(loc)        read8(loc)
#define read16le(loc)       read16(loc)
#define read32le(loc)       read32(loc)
#define read64le(loc)       read64(loc)

// Extract bits V[Begin:End], where range is inclusive, and Begin must be < 63.
[[maybe_unused]] static uint64_t extractBits(uint64_t v, uint32_t begin,
                                             uint32_t end) {
  return (v & ((1ULL << (begin + 1)) - 1)) >> end;
}

[[maybe_unused]] static int64_t SignExtend64(uint64_t X, unsigned B) {
  assert(B > 0 && "Bit width can't be 0.");
  assert(B <= 64 && "Bit width out of range.");
  return int64_t(X << (64 - B)) >> (64 - B);
}

// Make sure that V can be represented as an N bit signed integer.
#define checkInt(v, n)                                                         \
  do {                                                                         \
    if ((int64_t)(v) != SignExtend64((int64_t)(v), (n)))                       \
      error_ret(-1);                                                           \
  } while (0)

// Make sure that V can be represented as an N bit unsigned integer.
#define checkUInt(v, n)                                                        \
  do {                                                                         \
    if (((uint64_t)(v) >> (n)) != 0)                                           \
      error_ret(-1);                                                           \
  } while (0)

// Make sure that V can be represented as an N bit signed or unsigned integer.
#define checkIntUInt(v, n)                                                     \
  do {                                                                         \
    if (((int64_t)(v) != SignExtend64((int64_t)(v), (n))) &&                   \
        (((uint64_t)(v) >> (n)) != 0))                                         \
      error_ret(-1);                                                           \
  } while (0)

#define checkAlignment(v, n)                                                   \
  do {                                                                         \
    if (((uint64_t)(v) & (n - 1)) != 0)                                        \
      error_ret(-1);                                                           \
  } while (0)

/* [llvm] RTDyldMemoryManager.cpp */
// Determine whether we can register EH tables.
#if (defined(__GNUC__) && !defined(__ARM_EABI__) && !defined(__ia64__) &&      \
     !(defined(_AIX) && defined(__ibmxl__)) && !defined(__SEH__) &&            \
     !defined(__USING_SJLJ_EXCEPTIONS__))
extern "C" void __register_frame(void *);
extern "C" void __deregister_frame(void *);
#else
#error Sorry, not supported
#endif
/**********************************/

using namespace litejit;

static Elf_Shdr *elf_get_shdr(Elf_Ehdr *elf, uint_t i) {
  return (Elf_Shdr *)((char *)elf + elf->e_shoff) + i;
}

static const char *elf_get_name_from_tab(Elf_Ehdr *elf, Elf_Shdr *strtab,
                                         uint32_t st_name) {
  return (const char *)elf + strtab->sh_offset + st_name;
}

static const char *elf_get_name_from_tab(Elf_Ehdr *elf, uint32_t strndx,
                                         uint32_t st_name) {
  return elf_get_name_from_tab(elf, elf_get_shdr(elf, strndx), st_name);
}

static const char *elf_get_sec_name(Elf_Ehdr *elf, Elf_Shdr *shdr) {
  uint32_t strndx = 0;
  if (elf->e_shstrndx < SHN_LORESERVE)
    strndx = elf->e_shstrndx;
  else if (elf->e_shstrndx == SHN_XINDEX)
    strndx = elf_get_shdr(elf, 0)->sh_link;
  else
    return nullptr;

  return elf_get_name_from_tab(elf, strndx, shdr->sh_name);
}

static Elf_Sym *elf_find_sym(Elf_Ehdr *elf, Elf_Shdr *symtab, uint_t idx) {
  uint_t symtab_entries = symtab->sh_size / sizeof(Elf_Sym);
  assert(symtab->sh_entsize == sizeof(Elf_Sym));
  if (idx >= symtab_entries)
    error_ret(nullptr);

  return (Elf_Sym *)((char *)elf + symtab->sh_offset) + idx;
}

// Undefined symbol     : return -1
// Undefined weak symbol: return 0
// Otherwise            : return symval
// FIXME: Symbol resolve is very hard. QwQ
static uintptr_t elf_resolve_symval(Elf_Ehdr *elf, Elf_Shdr *symtab,
                                    Elf_Sym *symbol, const char *symname,
                                    const LiteJIT::AllocatedSecsTy &SecMem,
                                    LiteJIT::SymbolFinderTy &SymbolFinder) {
  if (symbol->st_shndx == SHN_UNDEF) {
    // External symbol, lookup value
    uintptr_t target = (uintptr_t)SymbolFinder(symname);
    if (target == (uintptr_t) nullptr) {
      if (ELF_ST_BIND(symbol->st_info) & STB_WEAK) {
        // Weak symbol initialized as 0
        return (uintptr_t) nullptr;
      } else
        error_ret((uintptr_t)-1);
    }
    return target;
  } else if (symbol->st_shndx == SHN_ABS) {
    // Absolute symbol
    return symbol->st_value;
  } else if (symbol->st_shndx < SHN_LORESERVE) {
    // Internally defined symbol
    return (uintptr_t)LiteJIT::find_allocated_base(symbol->st_shndx, SecMem) +
           symbol->st_value;
  }
  error_ret((uintptr_t)-1);
}

struct Foreach {
  static int ElfShdr(Elf_Ehdr *elf,
                     std::function<int(uint_t i, Elf_Shdr *)> method) {
    Elf_Shdr *shdr = elf_get_shdr(elf, 0);
    uint_t shnum = elf->e_shnum;
    if (shnum >= SHN_LORESERVE)
      shnum = shdr->sh_size;
    for (uint_t i = 0; i < shnum; ++i) {
      int err = method(i, shdr + i);
      if (err != 0)
        error_ret(err);
    }
    return 0;
  }
};

#if defined(__x86_64__) || defined(__amd64__)
static const char ELF_IDENT[EI_NIDENT] = {ELFMAG0,    ELFMAG1,      ELFMAG2,
                                          ELFMAG3,    ELFCLASS64,   ELFDATA2LSB,
                                          EV_CURRENT, ELFOSABI_SYSV};
static const int pseudo_plt_entsize = 6;
static bool check_elf(Elf_Ehdr *elf) { return elf->e_machine == EM_X86_64; }

static int emit_pseudo_plt(char *plt, uintptr_t got) {
  // jmpq *(got - base)(%rip)
  // binary: ff 25 00 00 00 00
  uintptr_t tmp = got - (uintptr_t)plt - 0x6;
  ASSERT_WORD32(tmp);
  *plt++ = 0xff;
  *plt++ = 0x25;
  *(uint32_t *)plt = tmp;
  return 0;
}

int LiteJIT::do_elf_relc(Elf_Ehdr *elf, Elf_Shdr *relshdr, uint32_t _symtab,
                         Elf_Rel *rel, char *base) {
  error_ret(-1);
}

int LiteJIT::do_elf_relca(Elf_Ehdr *elf, Elf_Shdr *relshdr, uint32_t _symtab,
                          Elf_Rela *rel, char *base) {
  uintptr_t *got = nullptr;
  Elf_Shdr *symtab = nullptr;
  Elf_Sym *sym = nullptr;
  uintptr_t symval = 0;
  const char *symname = nullptr;
  base += rel->r_offset;

  // If this relocation type requires the symval (S), find symtab, sym, symval.
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_X86_64_32:
  case R_X86_64_32S:
  case R_X86_64_64:
  case R_X86_64_PC32:
  case R_X86_64_PC64:
  case R_X86_64_PLT32:
  case R_X86_64_GOTPCREL:
  case R_X86_64_GOTPCRELX:
  case R_X86_64_REX_GOTPCRELX: {
    uint_t idx = ELF_R_SYM(rel->r_info);
    if (_symtab == SHN_UNDEF || idx == STN_UNDEF)
      error_ret(-1);
    symtab = elf_get_shdr(elf, _symtab);
    sym = elf_find_sym(elf, symtab, idx);
    if (sym == nullptr) // Why?
      error_ret(-1);
    symname = elf_get_name_from_tab(elf, symtab->sh_link, sym->st_name);
    symval =
        elf_resolve_symval(elf, symtab, sym, symname, SecMemTmp, SymbolFinder);
    if (symval == (uintptr_t)-1)
      error_ret(-1);
  }
  }

  // If this relocation type requires a got, allocate it.
  // And bind symbol to got.
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_X86_64_PLT32:
  case R_X86_64_GOTPCREL:
  case R_X86_64_GOTPCRELX:
  case R_X86_64_REX_GOTPCRELX: {
    // Get/Allocate and bind
    got = placeGOT(symname, symval);
    if (got == nullptr)
      error_ret(ENOMEM);
  }
  }

  // Do relocation
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_X86_64_32:
  case R_X86_64_32S: {
    // Word32
    // S + A
    uint64_t tmp = symval + rel->r_addend;
    ASSERT_WORD32(tmp);
    *(uint32_t *)base = tmp;
    return 0;
  }
  case R_X86_64_64:
    // Word64
    // S + A
    *(uint64_t *)base = symval + rel->r_addend;
    return 0;
  case R_X86_64_PC32: {
    // Word32
    // S + A - P
    uintptr_t tmp = symval + rel->r_addend - (uintptr_t)base;
    ASSERT_WORD32(tmp);
    *(uint32_t *)base = tmp;
    return 0;
  }
  case R_X86_64_PC64:
    // Word64
    // S + A - P
    *(uint64_t *)base = symval + rel->r_addend - (uintptr_t)base;
    return 0;
  case R_X86_64_PLT32: {
    // Word32
    // L + A - P
    auto [err, plt] = allocateText(pseudo_plt_entsize);
    if (err)
      error_ret(err);
    err = emit_pseudo_plt(plt, (uintptr_t)got);
    if (err)
      error_ret(err);
    uintptr_t tmp = (uintptr_t)plt + rel->r_addend - (uintptr_t)base;
    ASSERT_WORD32(tmp);
    *(uint32_t *)base = tmp;
    return 0;
  }
  case R_X86_64_GOTPCREL:
  case R_X86_64_GOTPCRELX:
  case R_X86_64_REX_GOTPCRELX: {
    // Word32
    // G + GOT + A - P
    // G + GOT = got
    uintptr_t tmp = (uintptr_t)got + rel->r_addend - (uintptr_t)base;
    ASSERT_WORD32(tmp);
    *(uint32_t *)base = tmp;
    return 0;
  }
  default:
    std::cout << ELF_R_TYPE(rel->r_info) << " : rrr\n";
    error_ret(-1);
  }
}
#elif defined(__riscv)
#include "RISCV.inc"
#else
#error Sorry, not implemented
#endif

void *LiteJIT::defaultSymbolFinder(const char *symname) {
  return dlsym(nullptr, symname);
}

LiteJIT::LiteJIT(unsigned MemSize, char *base)
    : MemSize(MemSize), base(base), text(base),
      got((uintptr_t *)(base + MemSize * 1024)) {}

std::unique_ptr<LiteJIT> LiteJIT::createLiteJIT(unsigned MemSize) {
  void *base = mmap(nullptr, MemSize * 1024, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (base == MAP_FAILED)
    error_ret(nullptr);
  return std::unique_ptr<LiteJIT>(new LiteJIT(MemSize, (char *)base));
}

LiteJIT::~LiteJIT() {
  // Run the termination code
  for (auto f : fini)
    f();
  // Deregister eh_frame
  for (auto p : eh_frame)
    __deregister_frame(p);
  if (DeleteSymbolEvent != nullptr) {
    for (const auto &name : HasDeleteEventSymbol)
      DeleteSymbolEvent(name.c_str());
  }
  munmap(base, MemSize * 1024);
}

char *LiteJIT::find_allocated_base(uint_t i, const AllocatedSecsTy &SecMem) {
  auto range = std::equal_range(
      SecMem.begin(), SecMem.end(), AllocatedSecTy{i, nullptr},
      [&](const AllocatedSecTy &a, const AllocatedSecTy &b) -> bool {
        return a.first < b.first;
      });
  if (range.first != SecMem.end())
    return range.first->second;
  return nullptr;
}

int LiteJIT::allocate(Elf_Ehdr *elf) {
  return Foreach::ElfShdr(elf, [&](uint_t i, Elf_Shdr *shdr) -> int {
    if (shdr->sh_flags & SHF_ALLOC) {
      auto [err, ptr] = this->allocateText(shdr->sh_size, shdr->sh_addralign);
      if (err != 0)
        error_ret(err);
      if (shdr->sh_type != SHT_NOBITS)
        memcpy(ptr, (char *)elf + shdr->sh_offset, shdr->sh_size);
      else
        memset(ptr, 0, shdr->sh_size);
      SecMemTmp.push_back({i, ptr});
    }
    return 0;
  });
}

int LiteJIT::relocate(Elf_Ehdr *elf) {
  return Foreach::ElfShdr(elf, [&](uint_t i, Elf_Shdr *shdr) -> int {
    if (shdr->sh_type == SHT_REL) {
      char *allocated_base = find_allocated_base(shdr->sh_info);
      assert(shdr->sh_entsize == sizeof(Elf_Rel));
      for (uint_t i = 0; i < shdr->sh_size / sizeof(Elf_Rel); ++i) {
        int err = do_elf_relc(elf, shdr, shdr->sh_link,
                              (Elf_Rel *)((char *)elf + shdr->sh_offset) + i,
                              allocated_base);
        if (err)
          error_ret(err);
      }
    } else if (shdr->sh_type == SHT_RELA) {
      char *allocated_base = find_allocated_base(shdr->sh_info);
      assert(shdr->sh_entsize == sizeof(Elf_Rela));
      for (uint_t i = 0; i < shdr->sh_size / sizeof(Elf_Rela); ++i) {
        int err = do_elf_relca(elf, shdr, shdr->sh_link,
                               (Elf_Rela *)((char *)elf + shdr->sh_offset) + i,
                               allocated_base);
        if (err)
          error_ret(err);
      }
    }
    return 0;
  });
}

int LiteJIT::addElf(char *_elf) {
  Elf_Ehdr *elf = (Elf_Ehdr *)_elf;
  int err = 0;

  if (elf->e_type != ET_REL || !check_elf(elf))
    error_ret(ENOEXEC);

  // Copy text/data to memory and initialize bss on memory
  SecMemTmp.clear();
  char *orig_text = text;
  err = allocate(elf);
  if (err != 0)
    goto stage_1;

  // FIXME: Properly restore status when an error occurs in the following steps

  // Relocation
  err = relocate(elf);
  if (err != 0)
    goto stage_1;

  err = Foreach::ElfShdr(elf, [&](uint_t shdr_idx, Elf_Shdr *shdr) -> int {
    if (shdr->sh_type == SHT_SYMTAB) {
      // Register symbols
      assert(shdr->sh_entsize == sizeof(Elf_Sym));
      for (uint_t i = 0; i < shdr->sh_size / sizeof(Elf_Sym); ++i) {
        Elf_Sym *sym = (Elf_Sym *)((char *)elf + shdr->sh_offset) + i;
        uint8_t stv = ELF_ST_VISIBILITY(sym->st_other);
        if (stv == STV_DEFAULT || stv == STV_PROTECTED) {
          uint8_t stb = ELF_ST_BIND(sym->st_info);
          if (stb == STB_GLOBAL || stb == STB_WEAK) {
            uint8_t stt = ELF_ST_TYPE(sym->st_info);
            if (stt == STT_OBJECT || stt == STT_FUNC) {
              uintptr_t symval =
                  (uintptr_t)find_allocated_base(sym->st_shndx) + sym->st_value;
              const char *name =
                  elf_get_name_from_tab(elf, shdr->sh_link, sym->st_name);
              if (RegisterSymbolEvent != nullptr) {
                if (RegisterSymbolEvent(name, (void *)symval))
                  HasDeleteEventSymbol.push_back(name);
              }
              SymbolMap[name] = symval;
            }
          }
        }
      }
    } else if (shdr->sh_type == SHT_INIT_ARRAY) {
      // Run the initialization code in init array
      // The sh_entsize of the elf which is compiled by clang is 0 (why?)
      // assert(shdr->sh_entsize == sizeof(InitFTy *));
      InitFTy *f = (InitFTy *)find_allocated_base(shdr_idx);
      for (uint_t i = 0; i < shdr->sh_size / sizeof(InitFTy); ++i)
        (f[i])();
    } else if (shdr->sh_type == SHT_FINI_ARRAY) {
      // Record the fini array
      // The sh_entsize of the elf which is compiled by clang is 0 (why?)
      // assert(shdr->sh_entsize == sizeof(FiniFTy));
      FiniFTy *f = ((FiniFTy *)find_allocated_base(shdr_idx));
      for (uint_t i = 0; i < shdr->sh_size / sizeof(FiniFTy); ++i)
        fini.push_back(f[i]);
    } else if ((shdr->sh_type == SHT_PROGBITS || shdr->sh_type >= SHT_LOOS) &&
               (strncmp(elf_get_sec_name(elf, shdr), ".eh_frame", 10) == 0) &&
               (shdr->sh_size > 0)) {
      void *frame = find_allocated_base(shdr_idx);
      if (frame != nullptr) {
        // Register eh_frame
        __register_frame(frame);
        eh_frame.push_back(frame);
      }
    }
    return 0;
  });

  return 0;
stage_1:
  text = orig_text;
  return err;
}

int LiteJIT::addElf(int fd) {
  off_t filesize;
  void *ptr;

  char buf[EI_NIDENT];
  if (read(fd, buf, EI_NIDENT) == -1)
    error_ret(errno);

  for (int i = 0; i < EI_NIDENT; ++i)
    if (buf[i] != ELF_IDENT[i])
      error_ret(ENOEXEC);

  filesize = lseek(fd, 0, SEEK_END);
  if (filesize == -1)
    error_ret(errno);

  ptr = mmap(0, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ptr == MAP_FAILED)
    error_ret(errno);

  int err = addElf((char *)ptr);

  munmap(ptr, filesize);
  return err;
}

int LiteJIT::addElf(const char *Path) {
  int fd = open(Path, O_RDONLY);
  if (fd == -1)
    return errno;
  int err = addElf(fd);
  close(fd);
  return err;
}

int LiteJIT::addC(const char *c) {
  int cfd[2];
  if (pipe(cfd) == -1)
    error_ret(errno);
  // Cannot use pipe output object
  // gcc:
  //   {standard input}: Fatal error: can't write 42 bytes to section .comment
  //                     of /dev/stdout: 'Illegal seek'
  //   Fatal error: can't close /dev/stdout: Illegal seek
  // Answer: https://stackoverflow.com/questions/47181017/
  FILE *ofile = tmpfile();
  // FILE *ofile = fopen("test.o", "w+");
  int ofd = fileno(ofile);

  pid_t pid = fork();
  if (pid == -1) {
    close(cfd[0]);
    close(cfd[1]);
    error_ret(-1);
  } else if (pid == 0) {
    dup2(cfd[0], STDIN_FILENO);
    close(cfd[0]);
    close(cfd[1]);
    dup2(ofd, STDOUT_FILENO);
    execlp("cc", "cc", "-fPIC", "-fno-asynchronous-unwind-tables", "-fno-plt",
           "-xc", "-", "-o", "/dev/stdout", "-c", "-pipe", nullptr);
    _exit(-1);
  } else {
    int status;
    int corpse;
    int err = 0;
    if (c != nullptr) {
      if (write(cfd[1], c, strlen(c)) == -1)
        error_ret(errno);
      fsync(cfd[1]);
    } else {
      char input[256];
      ssize_t rsize;
      while ((rsize = read(STDIN_FILENO, input, 256)) != 0) {
        if (write(cfd[1], input, rsize) == -1)
          error_ret(errno);
      }
      static bool once = false;
      if (once == true)
        error_ret(-1);
      once = true;
    }
    close(cfd[0]);
    close(cfd[1]);
    while ((corpse = waitpid(pid, &status, 0))) {
      if (corpse == pid) {
        if (WIFEXITED(status)) {
          err = WEXITSTATUS(status);
          break;
        } else if (WIFSIGNALED(status)) {
          err = -1;
          break;
        }
      }
    }
    if (err)
      error_ret(err);
    err = addElf(ofd);
    fclose(ofile);
    return err;
  }
}

void LiteJIT::dump(std::ostream &out, bool detail) const {
  out << "[LiteJIT Object Status]\n"
      << "  Object Address: " << this << '\n'
      << "  Memory Address: " << (void *)base << '\n'
      << "  Memory Size: " << MemSize << "KB\n"
      << "  Text Size: " << text - base << "B\n"
      << "  GOT Size: " << (uintptr_t *)(base + MemSize * 1024) - got << '\n'
      << "  Free Space: " << ((text <= (char *)got) ? ((char *)got) - text : 0)
      << "B\n";

  if (detail == false)
    return;

  if (SymbolMap.size()) {
    out << "[Symbol Map]\n";
    for (auto &[Name, Addr] : SymbolMap)
      out << "  " << Name << ": " << (void *)Addr << '\n';
  }
  if (GOTSymbolMap.size()) {
    out << "[GOT Symbol Map]\n";
    for (auto &[Name, Addr] : GOTSymbolMap)
      out << "  " << Name << ": " << *(void **)Addr << '\n';
  }
  out << "--------------------\n";
}
