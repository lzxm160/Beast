//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This is a derivative work based on Zlib, copyright below:
/*
    Copyright (C) 1995-2013 Jean-loup Gailly and Mark Adler

    This software is provided 'as-is', without any express or implied
    warranty.  In no event will the authors be held liable for any damages
    arising from the use of this software.

    Permission is granted to anyone to use this software for any purpose,
    including commercial applications, and to alter it and redistribute it
    freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.
    2. Altered source versions must be plainly marked as such, and must not be
       misrepresented as being the original software.
    3. This notice may not be removed or altered from any source distribution.

    Jean-loup Gailly        Mark Adler
    jloup@gzip.org          madler@alumni.caltech.edu

    The data format used by the zlib library is described by RFCs (Request for
    Comments) 1950 to 1952 in the files http://tools.ietf.org/html/rfc1950
    (zlib format), rfc1951 (deflate format) and rfc1952 (gzip format).
*/

#ifndef BEAST_ZLIB_DETAIL_WINDOW_HPP
#define BEAST_ZLIB_DETAIL_WINDOW_HPP

#include <boost/assert.hpp>
#include <cstdint>
#include <cstring>
#include <memory>

namespace beast {
namespace zlib {
namespace detail {

class window
{
    std::uint16_t i_ = 0;
    std::uint16_t size_ = 0;
    std::uint16_t capacity_ = 0;
    std::uint8_t bits_ = 0;
    std::unique_ptr<std::uint8_t[]> p_;

public:
    std::uint8_t
    bits() const
    {
        return bits_;
    }

    std::uint16_t
    capacity() const
    {
        return capacity_;
    }

    std::uint16_t
    size() const
    {
        return size_;
    }

    void
    reset(std::uint16_t capacity);

    void
    read(std::uint8_t* out,
        std::uint16_t pos, std::uint16_t n);

    template<class = void>
    void
    write(std::uint8_t const* in, std::size_t n);
};

inline
void
window::
reset(std::uint16_t bits)
{
    if(bits_ != bits)
    {
        p_.reset();
        bits_ = bits;
        capacity_ = 1 << bits_;
    }
    i_ = 0;
    size_ = 0;
}

inline
void
window::
read(std::uint8_t* out, std::uint16_t pos, std::uint16_t n)
{
    if(i_ >= size_)
    {
        // window is contiguous
        std::memcpy(out, &p_[i_ - pos], n);
        return;
    }

    std::uint16_t i = ((((std::int32_t)i_) - pos) + capacity_) % capacity_;
    std::uint16_t m = capacity_ - i;
    if(n <= m)
    {
        std::memcpy(out, &p_[i], n);
        return;
    }
    std::memcpy(out, &p_[i], m);
    out += m;
    m = n - m;
    std::memcpy(out, &p_[0], m);
}

template<class>
void
window::
write(std::uint8_t const* in, std::size_t n)
{
    if(! p_)
        p_.reset(new std::uint8_t[capacity_]);
    if(n >= capacity_)
    {
        i_ = 0;
        size_ = capacity_;
        std::memcpy(&p_[0], in + n - size_, size_);
        return;
    }
    if(n + i_ <= capacity_)
    {
        std::memcpy(&p_[i_], in, n);
        size_ += n;
        i_ = (i_ + n) % capacity_;
        return;
    }

    std::uint16_t m = capacity_ - i_;
    std::memcpy(&p_[i_], in, m);
    in += m;
    m = n - m;
    std::memcpy(&p_[0], in, m);
    i_ = m;
    size_ = capacity_;
}

} // detail
} // zlib
} // beast

#endif
