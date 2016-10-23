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

#ifndef BEAST_ZLIB_IMPL_BASIC_DEFLATE_STREAM_IPP
#define BEAST_ZLIB_IMPL_BASIC_DEFLATE_STREAM_IPP

#include <beast/zlib/detail/deflate.hpp>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>

namespace beast {
namespace zlib {

/*
 *  ALGORITHM
 *
 *      The "deflation" process depends on being able to identify portions
 *      of the input text which are identical to earlier input (within a
 *      sliding window trailing behind the input currently being processed).
 *
 *      Each code tree is stored in a compressed form which is itself
 *      a Huffman encoding of the lengths of all the code strings (in
 *      ascending order by source values).  The actual code strings are
 *      reconstructed from the lengths in the inflate process, as described
 *      in the deflate specification.
 *
 *      The most straightforward technique turns out to be the fastest for
 *      most input files: try all possible matches and select the longest.
 *      The key feature of this algorithm is that insertions into the string
 *      dictionary are very simple and thus fast, and deletions are avoided
 *      completely. Insertions are performed at each input character, whereas
 *      string matches are performed only when the previous match ends. So it
 *      is preferable to spend more time in matches to allow very fast string
 *      insertions and avoid deletions. The matching algorithm for small
 *      strings is inspired from that of Rabin & Karp. A brute force approach
 *      is used to find longer strings when a small match has been found.
 *      A similar algorithm is used in comic (by Jan-Mark Wams) and freeze
 *      (by Leonid Broukhis).
 *         A previous version of this file used a more sophisticated algorithm
 *      (by Fiala and Greene) which is guaranteed to run in linear amortized
 *      time, but has a larger average cost, uses more memory and is patented.
 *      However the F&G algorithm may be faster for some highly redundant
 *      files if the parameter max_chain_length (described below) is too large.
 *
 *  ACKNOWLEDGEMENTS
 *
 *      The idea of lazy evaluation of matches is due to Jan-Mark Wams, and
 *      I found it in 'freeze' written by Leonid Broukhis.
 *      Thanks to many people for bug reports and testing.
 *
 *  REFERENCES
 *
 *      Deutsch, L.P.,"DEFLATE Compressed Data Format Specification".
 *      Available in http://tools.ietf.org/html/rfc1951
 *
 *      A description of the Rabin and Karp algorithm is given in the book
 *         "Algorithms" by R. Sedgewick, Addison-Wesley, p252.
 *
 *      Fiala,E.R., and Greene,D.H.
 *         Data Compression with Finite Windows, Comm.ACM, 32,4 (1989) 490-595
 *
 */

template<class Allocator>
basic_deflate_stream<Allocator>::
basic_deflate_stream()
{
    // default level 6
    //reset(this, 6, 15, DEF_MEM_LEVEL, Strategy::normal);
}

template<class Allocator>
int
basic_deflate_stream<Allocator>::
reset(
    int  level,
    int  windowBits,
    int  memLevel,
    Strategy  strategy)
{
    /* We overlay pending_buf and d_buf+l_buf. This works since the average
     * output size for (length,distance) codes is <= 24 bits.
     */
    std::uint16_t* overlay;

    if(level == Z_DEFAULT_COMPRESSION)
        level = 6;

    BOOST_ASSERT(windowBits >= 0);
    if(memLevel < 1 || memLevel > MAX_MEM_LEVEL ||
        windowBits < 8 || windowBits > 15 || level < 0 || level > 9)
    {
        return Z_STREAM_ERROR;
    }
    if(windowBits == 8)
        windowBits = 9;  /* until 256-byte window bug fixed */

    w_bits_ = windowBits;
    w_size_ = 1 << w_bits_;
    w_mask_ = w_size_ - 1;

    hash_bits_ = memLevel + 7;
    hash_size_ = 1 << hash_bits_;
    hash_mask_ = hash_size_ - 1;
    hash_shift_ =  ((hash_bits_+limits::minMatch-1)/limits::minMatch);

    lit_bufsize_ = 1 << (memLevel + 6); /* 16K elements by default */

    {
        auto const nwindow  = w_size_ * 2*sizeof(Byte);
        auto const nprev    = w_size_ * sizeof(std::uint16_t);
        auto const nhead    = hash_size_ * sizeof(std::uint16_t);
        auto const noverlay = lit_bufsize_ * (sizeof(std::uint16_t)+2);
        
        buf_.reset(new std::uint8_t[nwindow + nprev + nhead + noverlay]);

        window_ = reinterpret_cast<Byte*>(buf_.get());
        prev_   = reinterpret_cast<std::uint16_t*>(buf_.get() + nwindow);
        head_   = reinterpret_cast<std::uint16_t*>(buf_.get() + nwindow + nprev);
        overlay = reinterpret_cast<std::uint16_t*>(buf_.get() + nwindow + nprev + nhead);
    }

    high_water_ = 0;      /* nothing written to window_ yet */

    pending_buf_ = (std::uint8_t *) overlay;
    pending_buf_size_ = (std::uint32_t)lit_bufsize_ * (sizeof(std::uint16_t)+2L);

    d_buf_ = overlay + lit_bufsize_/sizeof(std::uint16_t);
    l_buf_ = pending_buf_ + (1+sizeof(std::uint16_t))*lit_bufsize_;

    level_ = level;
    strategy_ = strategy;

    return deflateReset();
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
deflateResetKeep()
{
    // VFALCO TODO
    //total_in = 0;
    //total_out = 0;
    //msg = 0;
    //data_type = Z_UNKNOWN;

    pending_ = 0;
    pending_out_ = pending_buf_;

    status_ = BUSY_STATE;
    last_flush_ = Flush::none;

    tr_init();

    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
deflateReset()
{
    int ret = deflateResetKeep();
    if(ret == Z_OK)
        lm_init();
    return ret;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
pending(unsigned *pending, int *bits)
{
    if(pending != 0)
        *pending = pending_;
    if(bits != 0)
        *bits = bi_valid_;
    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
prime(int bits, int value)
{
    int put;

    if((Byte *)(d_buf_) < pending_out_ + ((Buf_size + 7) >> 3))
        return Z_BUF_ERROR;
    do
    {
        put = Buf_size - bi_valid_;
        if(put > bits)
            put = bits;
        bi_buf_ |= (std::uint16_t)((value & ((1 << put) - 1)) << bi_valid_);
        bi_valid_ += put;
        tr_flush_bits();
        value >>= put;
        bits -= put;
    }
    while(bits);
    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
void
basic_deflate_stream<Allocator>::
params(z_params& zs, int level, Strategy strategy, error_code& ec)
{
    compress_func func;

    if(level == Z_DEFAULT_COMPRESSION)
        level = 6;
    if(level < 0 || level > 9)
    {
        ec = error::stream_error;
        return;
    }
    func = get_config(level_).func;

    if((strategy != strategy_ || func != get_config(level).func) &&
        zs.total_in != 0)
    {
        // Flush the last buffer:
        write(zs, Flush::block, ec);
        if(ec == error::need_buffers && pending_ == 0)
            ec = {};
    }
    if(level_ != level)
    {
        level_ = level;
        max_lazy_match_   = get_config(level).max_lazy;
        good_match_       = get_config(level).good_length;
        nice_match_       = get_config(level).nice_length;
        max_chain_length_ = get_config(level).max_chain;
    }
    strategy_ = strategy;
}

/* ========================================================================= */

template<class Allocator>
void
basic_deflate_stream<Allocator>::
tune(
    int good_length,
    int max_lazy,
    int nice_length,
    int max_chain)
{
    good_match_ = good_length;
    nice_match_ = nice_length;
    max_lazy_match_ = max_lazy;
    max_chain_length_ = max_chain;
}

/* =========================================================================
 * For the default windowBits of 15 and memLevel of 8, this function returns
 * a close to exact, as well as small, upper bound on the compressed size.
 * They are coded as constants here for a reason--if the #define's are
 * changed, then this function needs to be changed as well.  The return
 * value for 15 and 8 only works for those exact settings.
 *
 * For any setting other than those defaults for windowBits and memLevel,
 * the value returned is a conservative worst case for the maximum expansion
 * resulting from using fixed blocks instead of stored blocks, which deflate
 * can emit on compressed data for some combinations of the parameters.
 *
 * This function could be more sophisticated to provide closer upper bounds for
 * every combination of windowBits and memLevel.  But even the conservative
 * upper bound of about 14% expansion does not seem onerous for output buffer
 * allocation.
 */

inline
std::size_t
deflate_upper_bound(std::size_t bytes)
{
    return bytes +
        ((bytes + 7) >> 3) +
        ((bytes + 63) >> 6) + 5 +
        6;
}

template<class Allocator>
std::size_t
basic_deflate_stream<Allocator>::
upper_bound(std::size_t sourceLen) const
{
    std::size_t complen;
    std::size_t wraplen;

    /* conservative upper bound for compressed data */
    complen = sourceLen +
              ((sourceLen + 7) >> 3) + ((sourceLen + 63) >> 6) + 5;

    /* compute wrapper length */
    wraplen = 0;

    /* if not default parameters, return conservative bound */
    if(w_bits_ != 15 || hash_bits_ != 8 + 7)
        return complen + wraplen;

    /* default settings: return tight bound for that case */
    return sourceLen + (sourceLen >> 12) + (sourceLen >> 14) +
           (sourceLen >> 25) + 13 - 6 + wraplen;
}

template<class Allocator>
int
basic_deflate_stream<Allocator>::
dictionary(Byte const* dict, uInt dictLength)
{
    uInt str, n;
    unsigned avail;
    const unsigned char *next;

    if(lookahead_)
        return Z_STREAM_ERROR;

    /* if dict would fill window, just replace the history */
    if(dictLength >= w_size_)
    {
        clear_hash();
        strstart_ = 0;
        block_start_ = 0L;
        insert_ = 0;
        dict += dictLength - w_size_;  /* use the tail */
        dictLength = w_size_;
    }

    /* insert dict into window and hash */
    z_params zs;
    zs.avail_in = dictLength;
    zs.next_in = (const Byte *)dict;
    zs.avail_out = 0;
    zs.next_out = 0;
    fill_window(zs);
    while(lookahead_ >= limits::minMatch)
    {
        str = strstart_;
        n = lookahead_ - (limits::minMatch-1);
        do
        {
            update_hash(ins_h_, window_[str + limits::minMatch-1]);
            prev_[str & w_mask_] = head_[ins_h_];
            head_[ins_h_] = (std::uint16_t)str;
            str++;
        }
        while(--n);
        strstart_ = str;
        lookahead_ = limits::minMatch-1;
        fill_window(zs);
    }
    strstart_ += lookahead_;
    block_start_ = (long)strstart_;
    insert_ = lookahead_;
    lookahead_ = 0;
    match_length_ = prev_length_ = limits::minMatch-1;
    match_available_ = 0;
    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
void
basic_deflate_stream<Allocator>::
write(z_params& zs, Flush flush, error_code& ec)
{
    // value of flush param for previous deflate call
    boost::optional<Flush> old_flush;

    if(zs.next_out == 0 || (zs.next_in == 0 && zs.avail_in != 0) ||
        (status_ == FINISH_STATE && flush != Flush::finish))
    {
        ec = error::stream_error;
        return;
    }
    if(zs.avail_out == 0)
    {
        ec = error::need_buffers;
        return;
    }

    old_flush = last_flush_;
    last_flush_ = flush;

    // Flush as much pending output as possible
    if(pending_ != 0)
    {
        flush_pending(zs);
        if(zs.avail_out == 0)
        {
            /* Since avail_out is 0, deflate will be called again with
             * more output space, but possibly with both pending and
             * avail_in equal to zero. There won't be anything to do,
             * but this is not an error situation so make sure we
             * return OK instead of BUF_ERROR at next call of deflate:
             */
            last_flush_ = boost::none;
            return;
        }
    }
    else if(zs.avail_in == 0 && flush <= old_flush &&
        flush != Flush::finish)
    {
        /* Make sure there is something to do and avoid duplicate consecutive
         * flushes. For repeated and useless calls with Flush::finish, we keep
         * returning Z_STREAM_END instead of Z_BUF_ERROR.
         */
        ec = error::need_buffers;
        return;
    }

    // User must not provide more input after the first FINISH:
    if(status_ == FINISH_STATE && zs.avail_in != 0)
    {
        ec = error::need_buffers;
        return;
    }

    /* Start a new block or continue the current one.
     */
    if(zs.avail_in != 0 || lookahead_ != 0 ||
        (flush != Flush::none && status_ != FINISH_STATE))
    {
        block_state bstate;

        switch(strategy_)
        {
        case Strategy::huffman:
            bstate = deflate_huff(zs, flush);
            break;
        case Strategy::rle:
            bstate = deflate_rle(zs, flush);
            break;
        default:
        {
            bstate = (this->*(get_config(level_).func))(zs, flush);
            break;
        }
        }

        if(bstate == finish_started || bstate == finish_done)
        {
            status_ = FINISH_STATE;
        }
        if(bstate == need_more || bstate == finish_started)
        {
            if(zs.avail_out == 0)
            {
                last_flush_ = boost::none; /* avoid BUF_ERROR next call, see above */
            }
            return;
            /*  If flush != Flush::none && avail_out == 0, the next call
                of deflate should use the same flush parameter to make sure
                that the flush is complete. So we don't have to output an
                empty block here, this will be done at next call. This also
                ensures that for a very small output buffer, we emit at most
                one empty block.
            */
        }
        if(bstate == block_done)
        {
            if(flush == Flush::partial)
            {
                tr_align();
            }
            else if(flush != Flush::block)
            {
                /* FULL_FLUSH or SYNC_FLUSH */
                tr_stored_block((char*)0, 0L, 0);
                /* For a full flush, this empty block will be recognized
                 * as a special marker by inflate_sync().
                 */
                if(flush == Flush::full)
                {
                    clear_hash(); // forget history
                    if(lookahead_ == 0)
                    {
                        strstart_ = 0;
                        block_start_ = 0L;
                        insert_ = 0;
                    }
                }
            }
            flush_pending(zs);
            if(zs.avail_out == 0)
            {
                last_flush_ = boost::none; /* avoid BUF_ERROR at next call, see above */
                return;
            }
        }
    }

    if(flush == Flush::finish)
    {
        ec = error::end_of_stream;
        return;
    }
}

//------------------------------------------------------------------------------

/*  Initialize the "longest match" routines for a new zlib stream
*/
template<class Allocator>
void
basic_deflate_stream<Allocator>::
lm_init()
{
    window_size_ = (std::uint32_t)2L*w_size_;

    clear_hash();

    /* Set the default configuration parameters:
     */
    // VFALCO TODO just copy the config struct
    max_lazy_match_   = get_config(level_).max_lazy;
    good_match_       = get_config(level_).good_length;
    nice_match_       = get_config(level_).nice_length;
    max_chain_length_ = get_config(level_).max_chain;

    strstart_ = 0;
    block_start_ = 0L;
    lookahead_ = 0;
    insert_ = 0;
    match_length_ = prev_length_ = limits::minMatch-1;
    match_available_ = 0;
    ins_h_ = 0;
}

} // zlib
} // beast

#endif
