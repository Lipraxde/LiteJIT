// cc -fPIC -c foo.c -o foo.o

#include <stdio.h>

extern int a;

void foo() { printf("[foo.c] a %d\n", a); }

void sort(int *array, size_t size) {
  for (size_t i = 0; i < size - 1; ++i)
    for (size_t j = 0; j < size - i - 1; ++j)
      if (array[j] > array[j + 1]) {
        int tmp = array[j];
        array[j] = array[j + 1];
        array[j + 1] = tmp;
      }
}

__attribute__((constructor)) void ctor(void) {
  foo();
  puts("[foo.c] CTOR");
}
__attribute__((destructor)) void dtor(void) {
  foo();
  puts("[foo.c] DTOR");
}
