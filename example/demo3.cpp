#include <litejit/LiteJIT.h>

#include <cstring>
#include <iostream>

#include <assert.h>
#include <sys/mman.h>

static const char c[] = R"(
#include <stdio.h>

void hello() {
  printf("[JIT] Hello! I am located at code cache!\n");
}
)";

static void (*hello)() = nullptr;
static bool RegisterEvent(const char *name, void *symbol) {
  if (strcmp(name, "hello") == 0)
    hello = (typeof hello)symbol;
  return false;
}

int main(int argc, char **argv) {
  void *code_cache = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (code_cache == MAP_FAILED) {
    std::cerr << "Fail to allocate code cache\n";
    return 0;
  }

  auto LJIT = litejit::LiteJIT::createLiteJIT(4, code_cache);
  if (LJIT == nullptr) {
    std::cerr << "Fail to create LiteJIT\n";
    return 0;
  }
  LJIT->setRegisterSymbolEvent(RegisterEvent);

  int err = LJIT->addC(c);

  if (err == 0) {
    std::cout << "Success!\n";
    assert(hello != nullptr);
    hello();
    std::cout << "Before clear LJIT\n";
    LJIT->dump(std::cout);
    std::cout << "After clear LJIT\n";
    LJIT->clear();
    LJIT->dump(std::cout);
  } else
    std::cerr << "Fail! " << std::strerror(err) << '\n';
}
