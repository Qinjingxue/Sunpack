#pragma once
#include <iterator>
namespace boost {
using forward_traversal_tag = std::forward_iterator_tag;
class iterator_core_access {
public:
  template <class D> static void increment(D &d) { d.increment(); }
  template <class D> static bool equal(const D &a, const D &b) {
    return a.equal(b);
  }
  template <class D> static const auto &dereference(const D &d) {
    return d.dereference();
  }
};
template <class D, class V, class C> class iterator_facade {
public:
  using value_type = V;
  using iterator_category = C;
  using difference_type = std::ptrdiff_t;
  using pointer = V *;
  using reference = V &;
  const auto &operator*() const {
    return iterator_core_access::dereference(static_cast<const D &>(*this));
  }
  D &operator++() {
    auto &d = static_cast<D &>(*this);
    iterator_core_access::increment(d);
    return d;
  }
  bool operator==(const D &b) const {
    return iterator_core_access::equal(static_cast<const D &>(*this), b);
  }
  bool operator!=(const D &b) const { return !(*this == b); }
};
} // namespace boost
