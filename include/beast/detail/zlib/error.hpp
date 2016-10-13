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

#ifndef BEAST_ZLIB_ERROR_HPP
#define BEAST_ZLIB_ERROR_HPP

#include <beast/core/error.hpp>

namespace beast {
namespace zlib {

/** Deflate error codes.
*/
enum class error
{
    /// Invalid block type
    invalid_block_type = 1,

    /// Invalid stored block length
    invalid_stored_length,

    /// Too many symbols
    too_many_symbols,

    /// Invalid code lengths
    invalid_code_lenths,

    /// Invalid bit length repeat
    invalid_bit_length_repeat,

    /// Missing end of block code
    missing_eob,

    /// Invalid literal/lengths set
    invalid_literal_lengths,

    /// Invalid distances set
    invalid_distances,

    /// Invalid literal/length code
    invalid_literal_length,

    /// Invalid distance code
    invalid_distance_code,

    /// Invalid distance
    distance_overflow
};

} // zlib
} // beast

#include <beast/detail/zlib/impl/error.ipp>

#endif

