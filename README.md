# LiteJIT
A lightweight jit

LiteJIT uses "cc" to compile the C program into an object file.
Then relocate the object file to get the executable code.
Since using LLVM OrcJIT in dynamic binary translation is overkill.
I start this project.

# Basic API

Static member function `createLiteJIT` is used to create a `LiteJIT` object.
The first argument `MemSize` is used to specify the code cache size in the created `LiteJIT` object.
The second argument `memory` is used to specify the external code cache address.
The size of the external memory should be larger than the specified `MemSize` and align to page size.

```cpp
// MemSize: nKB
static std::unique_ptr<LiteJIT> createLiteJIT(unsigned MemSize = 64,
                                              void *memory = nullptr);
```

The following four member functions in `LiteJIT` are used to add C/ELF to code cache:

```cpp
// The pointer elf points to the loaded ELF file
int addElf(char *elf);
// The file descriptor is an opened ELF file
int addElf(int fd);
// The path is the path of the ELF file
int addElf(const char *Path);
// The string is a C program
int addC(const char *c);
```

For example, Add a C program to `LiteJIT` via `LiteJIT->addC(prog)`,
`LJIT` will create a file, then call "cc" to compile the C program (`fork` and `execlp`),
then call `LiteJIT->addElf(fd)` to add the compiled ELF file,
then call `LiteJIT->addElf(elf)`.

After adding C/ELF, we can use `lookup` to get the address of the symbol in code cache (if `LITEJIT_DISABLE_LOOKUP` is disabled).

```cpp
void *lookup(const std::string &name) const;
void *lookup(const char *name) const;
```

`LITEJIT_DISABLE_LOOKUP` is used to reduce the footprint of `LiteJIT`.
Enable `LITEJIT_DISABLE_LOOKUP` will strip the symbol map (`SymbolMap`) in `LiteJIT`.
But the `lookup` functions become unavailable.

Instead, you can register `RegisterSymbolEvent` and `DeleteSymbolEvent`.
The `RegisterSymbolEvent` will be called when a symbol is registered.
And the `DeleteSymbolEvent` will be called when a symbol is deleted if the symbol has delete event.

```cpp
using RegisterSymbolEventTy = bool (*)(const char *, void *); // symbol name, addr
using DeleteSymbolEventTy = void (*)(const char *);           // symbol name

// If the symbol has a delete event, the register symbol event handler must return true
void setRegisterSymbolEvent(RegisterSymbolEventTy handler);
void setDeleteSymbolEvent(DeleteSymbolEventTy handler);
```
