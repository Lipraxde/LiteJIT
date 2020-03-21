#include <litejit/LiteJIT.h>

#include <cstring>
#include <iostream>

#include <assert.h>
#include <dlfcn.h>

static int a = 123;

static void *SymbolFinder(const char *name) {
  if (strcmp(name, "a") == 0)
    return (void *)&a;
  return dlsym(nullptr, name);
}

static void (*foo)() = nullptr;
static void (*sort)(int *, size_t) = nullptr;
static bool RegisterEvent(const char *name, void *symbol) {
  if (strcmp(name, "foo") == 0)
    foo = (typeof foo)symbol;
  else if (strcmp(name, "sort") == 0)
    sort = (typeof sort)symbol;
  return false;
}

int main(int argc, char **argv) {
  auto LJIT = litejit::LiteJIT::createLiteJIT();
  if (LJIT == nullptr) {
    std::cerr << "Fail to create LiteJIT\n";
    return 0;
  }
  LJIT->setSymbolFinder(SymbolFinder);
  LJIT->setRegisterSymbolEvent(RegisterEvent);

  int err = LJIT->addElf("foo.o");
  LJIT->dump(std::cout);

  if (err == 0) {
    std::cout << "Success!\n";
#if !LITEJIT_DISABLE_LOOKUP
    foo = (void (*)())LJIT->lookup("foo");
    sort = (void (*)(int *, size_t))LJIT->lookup("sort");
#endif
    assert(foo != nullptr);
    a = 456;
    foo();
    a = 789;
    std::cout << "Test sort\n";
    int array[] = {5, 32, 777, 2, 6868, 88, 7};
    assert(sort != nullptr);
    sort(array, sizeof(array) / sizeof(int));
    for (int i : array)
      std::cout << " " << i;
    std::cout << '\n';
  } else
    std::cerr << "Fail! " << std::strerror(err) << '\n';
}
