#pragma once
namespace boost {
namespace lambda {
template <class F, class T> auto bind(F f, T v) {
  return [f, v]() { f(v); };
}
} // namespace lambda
} // namespace boost
