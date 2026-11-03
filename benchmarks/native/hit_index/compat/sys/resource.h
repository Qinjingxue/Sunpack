#pragma once
#include "time.h"
#include <ctime>
#define RUSAGE_SELF 0
struct rusage {
  timeval ru_utime;
};
inline int getrusage(int, rusage *r) {
  auto t = std::clock();
  r->ru_utime.tv_sec = t / CLOCKS_PER_SEC;
  r->ru_utime.tv_usec = (t % CLOCKS_PER_SEC) * 1000000 / CLOCKS_PER_SEC;
  return 0;
}
