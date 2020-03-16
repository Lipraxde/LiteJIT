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

int main(int argc, char **argv) {
  auto LJIT = litejit::LiteJIT::createLiteJIT();
  if (LJIT == nullptr) {
    std::cerr << "Fail to create LiteJIT\n";
    return 0;
  }

  int err = LJIT->addC(c);
  LJIT->dump(std::cout, true);

  if (err == 0) {
    std::cout << "Success!\n";
    auto hello = (void (*)())LJIT->lookup("hello");
    assert(hello != nullptr);
    hello();
  } else
    std::cerr << "Fail! " << std::strerror(err) << '\n';
}
