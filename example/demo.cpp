#include <litejit/LiteJIT.h>

#include <cstring>
#include <iostream>

#include <assert.h>

static const char c[] = R"(
#include <stdio.h>

void hello() {
  printf("[JIT] Hello!\n");
}
)";

static void (*hello)() = nullptr;
static bool RegisterEvent(const char *name, void *symbol) {
  if (strcmp(name, "hello") == 0)
    hello = (typeof hello)symbol;
  return false;
}

int main(int argc, char **argv) {
  auto LJIT = litejit::LiteJIT::createLiteJIT();
  if (LJIT == nullptr) {
    std::cerr << "Fail to create LiteJIT\n";
    return 0;
  }
  LJIT->setRegisterSymbolEvent(RegisterEvent);

  int err = LJIT->addC(c);
  LJIT->dump(std::cout, true);

  if (err == 0) {
    std::cout << "Success!\n";
#if !LITEJIT_DISABLE_LOOKUP
    hello = (void (*)())LJIT->lookup("hello");
#endif
    assert(hello != nullptr);
    hello();
  } else
    std::cerr << "Fail! " << std::strerror(err) << '\n';
}
