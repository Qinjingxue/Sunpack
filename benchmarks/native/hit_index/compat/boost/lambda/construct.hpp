#pragma once
namespace boost {
namespace lambda {
struct delete_array {
  template <class T> void operator()(T *p) const { delete[] p; }
};
struct delete_ptr {
  template <class T> void operator()(T *p) const { delete p; }
};
} // namespace lambda
} // namespace boost
