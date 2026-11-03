#pragma once
#include <chrono>
#include <winsock.h>
inline int gettimeofday(timeval *t, void *) {
  auto n = std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch())
               .count();
  t->tv_sec = n / 1000000;
  t->tv_usec = n % 1000000;
  return 0;
}
