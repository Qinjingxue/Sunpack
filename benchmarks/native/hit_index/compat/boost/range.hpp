#pragma once
#include <iterator>
namespace boost {
using std::begin;
using std::end;
using std::size;
template <class R> struct range_const_iterator {
  using type = decltype(std::begin(std::declval<const R &>()));
};
} // namespace boost
