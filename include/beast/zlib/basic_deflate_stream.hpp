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

#ifndef BEAST_ZLIB_BASIC_DEFLATE_STREAM_HPP
#define BEAST_ZLIB_BASIC_DEFLATE_STREAM_HPP

#include <beast/zlib/zlib.hpp>
#include <beast/zlib/detail/deflate.hpp>
#include <beast/zlib/detail/deflate_stream_base.hpp>
#include <cstdlib>

#include <memory>

namespace beast {
namespace zlib {

/** Returns the upper limit on the size of a compressed block.

    This function makes a conservative estimate of the maximum number
    of bytes needed to store the result of compressing a block of
    data.

    @param bytes The size of the uncompressed data.

    @return The maximum number of resulting compressed bytes.
*/
std::size_t
deflate_upper_bound(std::size_t bytes);

/** Raw deflate compressor.

    This is a port of zlib's "deflate" functionality to C++.
*/
template<class Allocator>
class basic_deflate_stream
    : private detail::deflate_stream_base<>
    , public z_params
{
public:
    basic_deflate_stream();

    int
    reset(int level, int windowBits, int memLevel, int strategy);

    int
    deflate(int flush);

    int
    deflateSetDictionary(const Byte *dictionary, uInt  dictLength);

    int
    deflateResetKeep();
    
    int
    deflateReset();

    int
    params(int level, int strategy);
    
    int
    tune(int good_length, int max_lazy, int nice_length, int max_chain);

    std::size_t
    upper_bound(std::size_t sourceLen) const;
    
    int
    pending(unsigned *pending, int *bits);

    int
    prime(int bits, int value);

private:
    void tr_init            ();
    void tr_align           ();
    void tr_flush_bits      ();
    void tr_stored_block    (char *bu, std::uint32_t stored_len, int last);
    void tr_flush_block     (char *buf, std::uint32_t stored_len, int last);
    void tr_tally_dist      (std::uint16_t dist, std::uint8_t len, bool& flush);
    void tr_tally_lit       (std::uint8_t c, bool& flush);

    block_state deflate_stored(int flush);
    block_state deflate_fast  (int flush);
    block_state deflate_slow  (int flush);
    block_state deflate_rle   (int flush);
    block_state deflate_huff  (int flush);

    void lm_init();
    void fill_window();
    void flush_pending();
    int  read_buf(Byte *buf, unsigned size);
    uInt longest_match(IPos cur_match);

    using self = basic_deflate_stream;
    typedef block_state(self::*compress_func)(int flush);

    /* Values for max_lazy_match, good_match and max_chain_length, depending on
     * the desired pack level (0..9). The values given below have been tuned to
     * exclude worst case performance for pathological files. Better values may be
     * found for specific files.
     */
    struct config
    {
       std::uint16_t good_length; /* reduce lazy search above this match length */
       std::uint16_t max_lazy;    /* do not perform lazy search above this match length */
       std::uint16_t nice_length; /* quit search above this match length */
       std::uint16_t max_chain;
       compress_func func;

       config(
               std::uint16_t good_length_,
               std::uint16_t max_lazy_,
               std::uint16_t nice_length_,
               std::uint16_t max_chain_,
               compress_func func_)
           : good_length(good_length_)
           , max_lazy(max_lazy_)
           , nice_length(nice_length_)
           , max_chain(max_chain_)
           , func(func_)
       {
       }
    };

    static
    config
    get_config(std::size_t level)
    {
        switch(level)
        {
        //              good lazy nice chain
        case 0: return {  0,   0,   0,    0, &self::deflate_stored}; // store only
        case 1: return {  4,   4,   8,    4, &self::deflate_fast};   // max speed, no lazy matches
        case 2: return {  4,   5,  16,    8, &self::deflate_fast};
        case 3: return {  4,   6,  32,   32, &self::deflate_fast};
        case 4: return {  4,   4,  16,   16, &self::deflate_slow};   // lazy matches
        case 5: return {  8,  16,  32,   32, &self::deflate_slow};
        case 6: return {  8,  16, 128,  128, &self::deflate_slow};
        case 7: return {  8,  32, 128,  256, &self::deflate_slow};
        case 8: return { 32, 128, 258, 1024, &self::deflate_slow};
        default:
        case 9: return { 32, 258, 258, 4096, &self::deflate_slow};    // max compression
        }
    }
};

using deflate_stream = basic_deflate_stream<std::allocator<std::uint8_t>>;

} // zlib
} // beast

#include <beast/zlib/impl/basic_deflate_stream.ipp>

#endif
