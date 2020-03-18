#define DTPOffset 0x800ULL

static const char ELF_IDENT[EI_NIDENT] = {ELFMAG0,    ELFMAG1,      ELFMAG2,
                                          ELFMAG3,    ELFCLASS64,   ELFDATA2LSB,
                                          EV_CURRENT, ELFOSABI_SYSV};
static const int pseudo_plt_entsize = 12;
static bool check_elf(Elf_Ehdr *elf) { return elf->e_machine == EM_RISCV; }

static int do_relocation(uint_t type, uint8_t *loc, uint64_t val);

static int emit_pseudo_plt(char *plt, uintptr_t got) {
  // instructions:
  //   auipc  t3,n1
  //   l[w|d] t3,-n2(t3)
  //   jr     t3
  //
  // binary:
  //   0x00000e17
  //   0x000e2e03(w) 0x000e3e03(d)
  //   0x000e0067
  uintptr_t tmp = got - (uintptr_t)plt;
  write32le(plt + 0, 0x00000e17 | ((tmp + 0x800) & ~0xFFF));
  write32le(plt + 4, ((ELF_WORD_SIZE == 32) ? 0x000e2e03 : 0x000e3e03) |
                         ((tmp & 0xFFF) << 20));
  write32le(plt + 8, 0x000e0067);
  return 0;
}

static int do_relocation(uint_t type, uint8_t *loc, uint64_t val) {
  /* [lld] ELF/Arch/RISCV.cpp */
  switch (type) {
  case R_RISCV_32:
    write32le(loc, val);
    break;
  case R_RISCV_64:
    write64le(loc, val);
    break;

  case R_RISCV_RVC_BRANCH: {
    checkInt(static_cast<int64_t>(val) >> 1, 8);
    checkAlignment(val, 2);
    uint16_t insn = read16le(loc) & 0xE383;
    uint16_t imm8 = extractBits(val, 8, 8) << 12;
    uint16_t imm4_3 = extractBits(val, 4, 3) << 10;
    uint16_t imm7_6 = extractBits(val, 7, 6) << 5;
    uint16_t imm2_1 = extractBits(val, 2, 1) << 3;
    uint16_t imm5 = extractBits(val, 5, 5) << 2;
    insn |= imm8 | imm4_3 | imm7_6 | imm2_1 | imm5;

    write16le(loc, insn);
    break;
  }

  case R_RISCV_RVC_JUMP: {
    checkInt(static_cast<int64_t>(val) >> 1, 11);
    checkAlignment(val, 2);
    uint16_t insn = read16le(loc) & 0xE003;
    uint16_t imm11 = extractBits(val, 11, 11) << 12;
    uint16_t imm4 = extractBits(val, 4, 4) << 11;
    uint16_t imm9_8 = extractBits(val, 9, 8) << 9;
    uint16_t imm10 = extractBits(val, 10, 10) << 8;
    uint16_t imm6 = extractBits(val, 6, 6) << 7;
    uint16_t imm7 = extractBits(val, 7, 7) << 6;
    uint16_t imm3_1 = extractBits(val, 3, 1) << 3;
    uint16_t imm5 = extractBits(val, 5, 5) << 2;
    insn |= imm11 | imm4 | imm9_8 | imm10 | imm6 | imm7 | imm3_1 | imm5;

    write16le(loc, insn);
    break;
  }

  case R_RISCV_RVC_LUI: {
    int64_t imm = SignExtend64(val + 0x800, ELF_WORD_SIZE) >> 12;
    checkInt(imm, 6);
    if (imm == 0) { // `c.lui rd, 0` is illegal, convert to `c.li rd, 0`
      write16le(loc, (read16le(loc) & 0x0F83) | 0x4000);
    } else {
      uint16_t imm17 = extractBits(val + 0x800, 17, 17) << 12;
      uint16_t imm16_12 = extractBits(val + 0x800, 16, 12) << 2;
      write16le(loc, (read16le(loc) & 0xEF83) | imm17 | imm16_12);
    }
    break;
  }

  case R_RISCV_JAL: {
    checkInt(static_cast<int64_t>(val) >> 1, 20);
    checkAlignment(val, 2);

    uint32_t insn = read32le(loc) & 0xFFF;
    uint32_t imm20 = extractBits(val, 20, 20) << 31;
    uint32_t imm10_1 = extractBits(val, 10, 1) << 21;
    uint32_t imm11 = extractBits(val, 11, 11) << 20;
    uint32_t imm19_12 = extractBits(val, 19, 12) << 12;
    insn |= imm20 | imm10_1 | imm11 | imm19_12;

    write32le(loc, insn);
    break;
  }

  case R_RISCV_BRANCH: {
    checkInt(static_cast<int64_t>(val) >> 1, 12);
    checkAlignment(val, 2);

    uint32_t insn = read32le(loc) & 0x1FFF07F;
    uint32_t imm12 = extractBits(val, 12, 12) << 31;
    uint32_t imm10_5 = extractBits(val, 10, 5) << 25;
    uint32_t imm4_1 = extractBits(val, 4, 1) << 8;
    uint32_t imm11 = extractBits(val, 11, 11) << 7;
    insn |= imm12 | imm10_5 | imm4_1 | imm11;

    write32le(loc, insn);
    break;
  }

  // auipc + jalr pair
  case R_RISCV_CALL:
  case R_RISCV_CALL_PLT: {
    int64_t hi = SignExtend64(val + 0x800, ELF_WORD_SIZE) >> 12;
    checkInt(hi, 20);
    do_relocation(R_RISCV_PCREL_HI20, loc, val);
    do_relocation(R_RISCV_PCREL_LO12_I, loc + 4, val);
    break;
  }

  case R_RISCV_GOT_HI20:
  case R_RISCV_PCREL_HI20:
  case R_RISCV_TLS_GD_HI20:
  case R_RISCV_TLS_GOT_HI20:
  case R_RISCV_TPREL_HI20:
  case R_RISCV_HI20: {
    uint64_t hi = val + 0x800;
    checkInt(SignExtend64(hi, ELF_WORD_SIZE) >> 12, 20);
    write32le(loc, (read32le(loc) & 0xFFF) | (hi & 0xFFFFF000));
    break;
  }

  case R_RISCV_PCREL_LO12_I:
  case R_RISCV_TPREL_LO12_I:
  case R_RISCV_LO12_I: {
    uint64_t hi = (val + 0x800) >> 12;
    uint64_t lo = val - (hi << 12);
    write32le(loc, (read32le(loc) & 0xFFFFF) | ((lo & 0xFFF) << 20));
    break;
  }

  case R_RISCV_PCREL_LO12_S:
  case R_RISCV_TPREL_LO12_S:
  case R_RISCV_LO12_S: {
    uint64_t hi = (val + 0x800) >> 12;
    uint64_t lo = val - (hi << 12);
    uint32_t imm11_5 = extractBits(lo, 11, 5) << 25;
    uint32_t imm4_0 = extractBits(lo, 4, 0) << 7;
    write32le(loc, (read32le(loc) & 0x1FFF07F) | imm11_5 | imm4_0);
    break;
  }

  case R_RISCV_ADD8:
    *loc += val;
    break;
  case R_RISCV_ADD16:
    write16le(loc, read16le(loc) + val);
    break;
  case R_RISCV_ADD32:
    write32le(loc, read32le(loc) + val);
    break;
  case R_RISCV_ADD64:
    write64le(loc, read64le(loc) + val);
    break;
  case R_RISCV_SUB6:
    *loc = (*loc & 0xc0) | (((*loc & 0x3f) - val) & 0x3f);
    break;
  case R_RISCV_SUB8:
    *loc -= val;
    break;
  case R_RISCV_SUB16:
    write16le(loc, read16le(loc) - val);
    break;
  case R_RISCV_SUB32:
    write32le(loc, read32le(loc) - val);
    break;
  case R_RISCV_SUB64:
    write64le(loc, read64le(loc) - val);
    break;
  case R_RISCV_SET6:
    *loc = (*loc & 0xc0) | (val & 0x3f);
    break;
  case R_RISCV_SET8:
    *loc = val;
    break;
  case R_RISCV_SET16:
    write16le(loc, val);
    break;
  case R_RISCV_SET32:
  case R_RISCV_32_PCREL:
    write32le(loc, val);
    break;

  case R_RISCV_TLS_DTPREL32:
    write32le(loc, val - DTPOffset);
    break;
  case R_RISCV_TLS_DTPREL64:
    write64le(loc, val - DTPOffset);
    break;

  // Ignored (for now)
  case R_RISCV_ALIGN:
  case R_RISCV_RELAX:
    break;
  // Do nothing
  case R_RISCV_NONE:
    break;

  // These are handled by the dynamic linker
  case R_RISCV_RELATIVE:
  case R_RISCV_COPY:
  case R_RISCV_JUMP_SLOT:
  // GP-relative relocations are only produced after relaxation, which
  // we don't support for now
  case R_RISCV_GPREL_I:
  case R_RISCV_GPREL_S:
  default:
    std::cout << "[LiteJIT] Unsupported RISCV relocation type: " << type
              << '\n';
    error_ret(-1);
  }
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
  uintptr_t position = (uintptr_t)base + rel->r_offset;

  auto resolve_symval =
      [&](Elf_Ehdr *elf, uint32_t _symtab, uint_t symidx,
          const LiteJIT::AllocatedSecsTy &SecMem) -> uintptr_t {
    if (_symtab == SHN_UNDEF || symidx == STN_UNDEF)
      error_ret(-1);
    symtab = elf_get_shdr(elf, _symtab);
    sym = elf_find_sym(elf, symtab, symidx);
    if (sym == nullptr) // Why?
      error_ret(-1);
    return elf_resolve_symval(elf, symtab, sym, SecMem);
  };

  // If this relocation type requires the symval (S), find symtab, sym, symval.
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_RISCV_32:
  case R_RISCV_64:
  case R_RISCV_BRANCH:
  case R_RISCV_JAL:
  case R_RISCV_CALL:
  case R_RISCV_CALL_PLT:
  case R_RISCV_GOT_HI20:
  case R_RISCV_PCREL_HI20:
  case R_RISCV_PCREL_LO12_I:
  case R_RISCV_PCREL_LO12_S:
  case R_RISCV_RVC_BRANCH:
  case R_RISCV_RVC_JUMP:
  case R_RISCV_RVC_LUI:
    symval = resolve_symval(elf, _symtab, ELF_R_SYM(rel->r_info), SecMemTmp);
    if (symval == (uintptr_t)-1)

      error_ret(-1);
  }

  // If this relocation type requires a got, allocate it.
  // And bind symbol to got.
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_RISCV_CALL:
  case R_RISCV_CALL_PLT:
  case R_RISCV_GOT_HI20: {
    // Find symbol in got
    const char *name =
        elf_get_name_from_tab(elf, symtab->sh_link, sym->st_name);
    // Get/Allocate and bind
    got = placeGOT(name, symval);
    if (got == nullptr)
      error_ret(ENOMEM);
  }
  }

  uintptr_t tmp = 0;
  // Do calculation
  switch (ELF_R_TYPE(rel->r_info)) {
  case R_RISCV_32:
  case R_RISCV_64:
  case R_RISCV_HI20:
  case R_RISCV_LO12_I:
  case R_RISCV_LO12_S:
  case R_RISCV_RVC_LUI:
    // R_ABS
  case R_RISCV_ADD8:
  case R_RISCV_ADD16:
  case R_RISCV_ADD32:
  case R_RISCV_ADD64:
  case R_RISCV_SET6:
  case R_RISCV_SET8:
  case R_RISCV_SET16:
  case R_RISCV_SET32:
  case R_RISCV_SUB6:
  case R_RISCV_SUB8:
  case R_RISCV_SUB16:
  case R_RISCV_SUB32:
  case R_RISCV_SUB64:
    // R_RISCV_ADD
    tmp = symval + rel->r_addend;
    break;
  case R_RISCV_JAL:
  case R_RISCV_BRANCH:
  case R_RISCV_PCREL_HI20:
  case R_RISCV_RVC_BRANCH:
  case R_RISCV_RVC_JUMP:
  case R_RISCV_32_PCREL:
    // R_PC
    tmp = symval + rel->r_addend - position;
    break;
  case R_RISCV_CALL:
  case R_RISCV_CALL_PLT: {
    // R_PLT_PC
    auto [err, plt] = allocateText(pseudo_plt_entsize, 2);
    if (err)
      error_ret(err);
    err = emit_pseudo_plt(plt, (uintptr_t)got);
    if (err)
      error_ret(err);
    tmp = (uintptr_t)plt + rel->r_addend - position;
    break;
  }
  case R_RISCV_GOT_HI20:
    // R_GOT_PC
    tmp = (uintptr_t)got + rel->r_addend - position;
    break;
  case R_RISCV_PCREL_LO12_I:
  case R_RISCV_PCREL_LO12_S: {
    // R_RISCV_PC_INDIRECT
    Elf_Rela r;
    // Assume that the allocated text base is same as the symbol base
    r.r_offset = symval - (uintptr_t)base;
    Elf_Rela *begin = (Elf_Rela *)((char *)elf + relshdr->sh_offset);
    Elf_Rela *end = begin + relshdr->sh_size / sizeof(Elf_Rela);

    auto range = std::equal_range(begin, end, r,
                                  [](const Elf_Rela &lhs, const Elf_Rela &rhs) {
                                    return lhs.r_offset < rhs.r_offset;
                                  });
    for (auto IT = range.first; IT != range.second; ++IT) {
      uint32_t rtype = ELF_R_TYPE(IT->r_info);
      if (rtype == R_RISCV_PCREL_HI20) {
        // Replace symbol
        symval = resolve_symval(elf, _symtab, ELF_R_SYM(IT->r_info), SecMemTmp);
        tmp = symval + IT->r_addend - ((uintptr_t)base + IT->r_offset);
        break;
      } else if (rtype == R_RISCV_GOT_HI20) {
        // Replace symbol
        symval = resolve_symval(elf, _symtab, ELF_R_SYM(IT->r_info), SecMemTmp);
        // Find symbol in got
        const char *name =
            elf_get_name_from_tab(elf, symtab->sh_link, sym->st_name);
        // Get/Allocate
        uintptr_t *_got = getOrAllocateGOT(name);
        if (_got == nullptr)
          error_ret(ENOMEM);
        got = _got;
        tmp = (uintptr_t)got + IT->r_addend - ((uintptr_t)base + IT->r_offset);
        break;
      }
      // R_RISCV_TLS_GD_HI20 and R_RISCV_TLS_GOT_HI20
    }
    if (tmp == 0)
      error_ret(-1);
    break;
  }
  case R_RISCV_NONE:
    // R_NONE
  case R_RISCV_TLS_GD_HI20:
    // R_TLSGD_PC
  case R_RISCV_TLS_GOT_HI20:
    // R_GOT_PC
  case R_RISCV_TPREL_HI20:
  case R_RISCV_TPREL_LO12_I:
  case R_RISCV_TPREL_LO12_S:
    // R_TLS
    std::cerr << "[LiteJIT] Unsupported RISCV calculation\n";
    abort();
  }

  // Do relocation
  return do_relocation(ELF_R_TYPE(rel->r_info), (uint8_t *)position, tmp);
}
