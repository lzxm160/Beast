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

#ifndef BEAST_ZLIB_INFLATE_STREAM_HPP
#define BEAST_ZLIB_INFLATE_STREAM_HPP

#include <beast/zlib/detail/inflate_stream.hpp>

namespace beast {
namespace zlib {

/** Raw deflate decompressor.

    This is a port of ZLib's "inflate" functionality to C++.
*/
class inflate_stream
    : private detail::inflate_stream
{
public:
    /** Construct a raw deflate decompression stream.

        The window size is set to the default of 15 bits.
    */
    inflate_stream() = default;

    /** Reset the stream.

        This puts the stream in a newly constructed state with the
        specified window size, but without de-allocating any dynamically
        created structures.
    */
    void
    reset(int windowBits)
    {
        doReset(windowBits);
    }

    /** Put the stream in a newly constructed state.

        All dynamically allocated memory is de-allocated.
    */
    void
    clear()
    {
        doClear();
    }

    /** Decompressed data.
    */
    void
    write(z_params& zs, Flush flush, error_code& ec)
    {
        doWrite(zs, flush, ec);
    }
};

} // zlib
} // beast

#endif
