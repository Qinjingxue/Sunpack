#pragma once
#define NOMINMAX
#include <stdexcept>
#include <string>
#include <windows.h>
namespace boost {
namespace iostreams {
// Only succinct's unused text-reader utility needs this type. Algorithms use
// their original in-memory bit_vector; this adapter also works for real files.
class mapped_file_source {
  HANDLE file_ = INVALID_HANDLE_VALUE;
  HANDLE map_ = nullptr;
  const char *data_ = nullptr;
  size_t size_ = 0;

public:
  explicit mapped_file_source(const std::string &p) {
    file_ = CreateFileA(p.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE)
      throw std::runtime_error("map open");
    LARGE_INTEGER s;
    GetFileSizeEx(file_, &s);
    size_ = size_t(s.QuadPart);
    if (size_) {
      map_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
      if (map_)
        data_ = static_cast<const char *>(
            MapViewOfFile(map_, FILE_MAP_READ, 0, 0, 0));
      if (!data_)
        throw std::runtime_error("map view");
    }
  }
  ~mapped_file_source() {
    if (data_)
      UnmapViewOfFile(data_);
    if (map_)
      CloseHandle(map_);
    if (file_ != INVALID_HANDLE_VALUE)
      CloseHandle(file_);
  }
  const char *data() const { return data_; }
  size_t size() const { return size_; }
};
} // namespace iostreams
} // namespace boost
