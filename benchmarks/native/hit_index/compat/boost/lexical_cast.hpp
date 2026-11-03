#pragma once
#include <sstream>
#include <stdexcept>
// Only upstream configuration environment parsing uses this compatibility shim.
namespace boost {
template <class T, class U> T lexical_cast(const U &v) {
  std::stringstream s;
  s << v;
  T out;
  if (!(s >> out))
    throw std::runtime_error("invalid upstream configuration value");
  return out;
}
} // namespace boost
