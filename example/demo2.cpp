#include <litejit/LiteJIT.h>

#include <cstring>
#include <iostream>

#include <assert.h>

extern "C" {
int a = 123;
}

int main(int argc, char **argv) {
  auto LJIT = litejit::LiteJIT::createLiteJIT();
  if (LJIT == nullptr) {
    std::cerr << "Fail to create LiteJIT\n";
    return 0;
  }

  int err = LJIT->addElf("foo.o");
  LJIT->dump(std::cout);

  if (err == 0) {
    std::cout << "Success!\n";
    auto f = (void (*)())LJIT->lookup("foo");
    assert(f != nullptr);
    a = 456;
    f();
    a = 789;
    std::cout << "Test sort\n";
    int array[] = {5, 32, 777, 2, 6868, 88, 7};
    auto sort = (void (*)(int *, size_t))LJIT->lookup("sort");
    assert(sort != nullptr);
    sort(array, sizeof(array) / sizeof(int));
    for (int i : array)
      std::cout << " " << i;
    std::cout << '\n';
  } else
    std::cerr << "Fail! " << std::strerror(err) << '\n';
}
