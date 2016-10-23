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

// VFALCO REMOVE
/* To be used only when the state is known to be valid */
#define ERR_RETURN(zs,err) \
  return (zs.msg = "unspecified zlib error", (err))

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
    //reset(this, 6, 15, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
}

template<class Allocator>
int
basic_deflate_stream<Allocator>::
reset(
    int  level,
    int  windowBits,
    int  memLevel,
    int  strategy)
{
    /* We overlay pending_buf and d_buf+l_buf. This works since the average
     * output size for (length,distance) codes is <= 24 bits.
     */
    std::uint16_t* overlay;

    //strm->msg = 0;

    if(level == Z_DEFAULT_COMPRESSION)
        level = 6;

    BOOST_ASSERT(windowBits >= 0);
    if(memLevel < 1 || memLevel > MAX_MEM_LEVEL ||
        windowBits < 8 || windowBits > 15 || level < 0 || level > 9 ||
        strategy < 0 || strategy > Z_FIXED) {
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
int
basic_deflate_stream<Allocator>::
params(z_params& zs, int level, int strategy)
{
    compress_func func;
    int err = Z_OK;

    if(level == Z_DEFAULT_COMPRESSION)
        level = 6;
    if(level < 0 || level > 9 || strategy < 0 || strategy > Z_FIXED)
        return Z_STREAM_ERROR;
    func = get_config(level_).func;

    if((strategy != strategy_ || func != get_config(level).func) &&
        total_in != 0)
    {
        // Flush the last buffer:
        err = deflate(zs, Flush::block);
        if(err == Z_BUF_ERROR && pending_ == 0)
            err = Z_OK;
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
    return err;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
tune(
    int good_length,
    int max_lazy,
    int nice_length,
    int max_chain)
{
    good_match_ = good_length;
    max_lazy_match_ = max_lazy;
    nice_match_ = nice_length;
    max_chain_length_ = max_chain;
    return Z_OK;
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
dictionary(
    Byte const* dict, uInt dictLength)
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
    avail = avail_in;
    next = next_in;
    avail_in = dictLength;
    next_in = (const Byte *)dict;
    fill_window(zs);
    while(lookahead_ >= limits::minMatch) {
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
    next_in = next;
    avail_in = avail;
    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
write(z_params& zs, Flush flush)
{
    // value of flush param for previous deflate call
    boost::optional<Flush> old_flush;

    if(zs.next_out == 0 || (zs.next_in == 0 && zs.avail_in != 0) ||
        (status_ == FINISH_STATE && flush != Flush::finish))
    {
        ERR_RETURN(zs, Z_STREAM_ERROR);
    }
    if(zs.avail_out == 0)
        ERR_RETURN(zs, Z_BUF_ERROR);

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
            return Z_OK;
        }
    /* Make sure there is something to do and avoid duplicate consecutive
     * flushes. For repeated and useless calls with Flush::finish, we keep
     * returning Z_STREAM_END instead of Z_BUF_ERROR.
     */
    }
    else if(zs.avail_in == 0 && flush <= old_flush &&
        flush != Flush::finish)
    {
        ERR_RETURN(zs, Z_BUF_ERROR);
    }

    // User must not provide more input after the first FINISH:
    if(status_ == FINISH_STATE && zs.avail_in != 0)
    {
        ERR_RETURN(zs, Z_BUF_ERROR);
    }

    /* Start a new block or continue the current one.
     */
    if(zs.avail_in != 0 || lookahead_ != 0 ||
        (flush != Flush::none && status_ != FINISH_STATE))
    {
        block_state bstate;

        switch(strategy_)
        {
        case Z_HUFFMAN_ONLY:
            bstate = deflate_huff(zs, flush);
            break;
        case Z_RLE:
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
            return Z_OK;
            /* If flush != Flush::none && avail_out == 0, the next call
             * of deflate should use the same flush parameter to make sure
             * that the flush is complete. So we don't have to output an
             * empty block here, this will be done at next call. This also
             * ensures that for a very small output buffer, we emit at most
             * one empty block.
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
                    clear_hash();             // forget history
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
                return Z_OK;
            }
        }
    }

    if(flush != Flush::finish)
        return Z_OK;
    return Z_STREAM_END;
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

//------------------------------------------------------------------------------

/* ===========================================================================
 * Copy without compression as much as possible from the input stream, return
 * the current block state.
 * This function does not insert new strings in the dictionary since
 * uncompressible data is probably not useful. This function is used
 * only for the level=0 compression option.
 * NOTE: this function should be optimized to avoid extra copying from
 * window to pending_buf.
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_stored(z_params& zs, Flush flush) ->
    block_state
{
    /* Stored blocks are limited to 0xffff bytes, pending_buf is limited
     * to pending_buf_size, and each stored block has a 5 byte header:
     */
    std::uint32_t max_block_size = 0xffff;
    std::uint32_t max_start;

    if(max_block_size > pending_buf_size_ - 5) {
        max_block_size = pending_buf_size_ - 5;
    }

    /* Copy as much as possible from input to output: */
    for(;;) {
        /* Fill the window as much as possible: */
        if(lookahead_ <= 1) {

            Assert(strstart_ < w_size_+max_dist() ||
                   block_start_ >= (long)w_size_, "slide too late");

            fill_window(zs);
            if(lookahead_ == 0 && flush == Flush::none)
                return need_more;

            if(lookahead_ == 0) break; /* flush the current block */
        }
        Assert(block_start_ >= 0L, "block gone");

        strstart_ += lookahead_;
        lookahead_ = 0;

        /* Emit a stored block if pending_buf will be full: */
        max_start = block_start_ + max_block_size;
        if(strstart_ == 0 || (std::uint32_t)strstart_ >= max_start) {
            /* strstart == 0 is possible when wraparound on 16-bit machine */
            lookahead_ = (uInt)(strstart_ - max_start);
            strstart_ = (uInt)max_start;
            flush_block(zs, false);
            if(zs.avail_out == 0)
                return need_more;
        }
        /* Flush if we may have to slide, otherwise block_start may become
         * negative and the data will be gone:
         */
        if(strstart_ - (uInt)block_start_ >= max_dist()) {
            flush_block(zs, false);
            if(zs.avail_out == 0)
                return need_more;
        }
    }
    insert_ = 0;
    if(flush == Flush::finish)
    {
        flush_block(zs, true);
        if(zs.avail_out == 0)
            return finish_started;
        return finish_done;
    }
    if((long)strstart_ > block_start_)
    {
        flush_block(zs, false);
        if(zs.avail_out == 0)
            return need_more;
    }
    return block_done;
}

/* ===========================================================================
 * Compress as much as possible from the input stream, return the current
 * block state.
 * This function does not perform lazy evaluation of matches and inserts
 * new strings in the dictionary only for unmatched strings or for short
 * matches. It is used only for the fast compression options.
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_fast(z_params& zs, Flush flush) ->
    block_state
{
    IPos hash_head;       /* head of the hash chain */
    bool bflush;           /* set if current block must be flushed */

    for(;;)
    {
        /* Make sure that we always have enough lookahead, except
         * at the end of the input file. We need limits::maxMatch bytes
         * for the next match, plus limits::minMatch bytes to insert the
         * string following the next match.
         */
        if(lookahead_ < kMinLookahead)
        {
            fill_window(zs);
            if(lookahead_ < kMinLookahead && flush == Flush::none)
                return need_more;
            if(lookahead_ == 0)
                break; /* flush the current block */
        }

        /* Insert the string window[strstart .. strstart+2] in the
         * dictionary, and set hash_head to the head of the hash chain:
         */
        hash_head = 0;
        if(lookahead_ >= limits::minMatch) {
            insert_string(hash_head);
        }

        /* Find the longest match, discarding those <= prev_length.
         * At this point we have always match_length < limits::minMatch
         */
        if(hash_head != 0 && strstart_ - hash_head <= max_dist()) {
            /* To simplify the code, we prevent matches with the string
             * of window index 0 (in particular we have to avoid a match
             * of the string with itself at the start of the input file).
             */
            match_length_ = longest_match (hash_head);
            /* longest_match() sets match_start */
        }
        if(match_length_ >= limits::minMatch) {
            tr_tally_dist(strstart_ - match_start_,
                           match_length_ - limits::minMatch, bflush);

            lookahead_ -= match_length_;

            /* Insert new strings in the hash table only if the match length
             * is not too large. This saves time but degrades compression.
             */
            if(match_length_ <= max_lazy_match_ &&
                lookahead_ >= limits::minMatch) {
                match_length_--; /* string at strstart already in table */
                do {
                    strstart_++;
                    insert_string(hash_head);
                    /* strstart never exceeds WSIZE-limits::maxMatch, so there are
                     * always limits::minMatch bytes ahead.
                     */
                } while(--match_length_ != 0);
                strstart_++;
            } else
            {
                strstart_ += match_length_;
                match_length_ = 0;
                ins_h_ = window_[strstart_];
                update_hash(ins_h_, window_[strstart_+1]);
                /* If lookahead < limits::minMatch, ins_h is garbage, but it does not
                 * matter since it will be recomputed at next deflate call.
                 */
            }
        } else {
            /* No match, output a literal byte */
            Tracevv((stderr,"%c", window_[strstart_]));
            tr_tally_lit(window_[strstart_], bflush);
            lookahead_--;
            strstart_++;
        }
        if(bflush)
        {
            flush_block(zs, false);
            if(zs.avail_out == 0)
                return need_more;
        }
    }
    insert_ = strstart_ < limits::minMatch-1 ? strstart_ : limits::minMatch-1;
    if(flush == Flush::finish)
    {
        flush_block(zs, true);
        if(zs.avail_out == 0)
            return finish_started;
        return finish_done;
    }
    if(last_lit_)
    {
        flush_block(zs, false);
        if(zs.avail_out == 0)
            return need_more;
    }
    return block_done;
}

/* ===========================================================================
 * Same as above, but achieves better compression. We use a lazy
 * evaluation for matches: a match is finally adopted only if there is
 * no better match at the next window position.
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_slow(z_params& zs, Flush flush) ->
    block_state
{
    IPos hash_head;          /* head of hash chain */
    bool bflush;              /* set if current block must be flushed */

    /* Process the input block. */
    for(;;)
    {
        /* Make sure that we always have enough lookahead, except
         * at the end of the input file. We need limits::maxMatch bytes
         * for the next match, plus limits::minMatch bytes to insert the
         * string following the next match.
         */
        if(lookahead_ < kMinLookahead) {
            fill_window(zs);
            if(lookahead_ < kMinLookahead && flush == Flush::none) {
                return need_more;
            }
            if(lookahead_ == 0) break; /* flush the current block */
        }

        /* Insert the string window[strstart .. strstart+2] in the
         * dictionary, and set hash_head to the head of the hash chain:
         */
        hash_head = 0;
        if(lookahead_ >= limits::minMatch) {
            insert_string(hash_head);
        }

        /* Find the longest match, discarding those <= prev_length.
         */
        prev_length_ = match_length_, prev_match_ = match_start_;
        match_length_ = limits::minMatch-1;

        if(hash_head != 0 && prev_length_ < max_lazy_match_ &&
            strstart_ - hash_head <= max_dist()) {
            /* To simplify the code, we prevent matches with the string
             * of window index 0 (in particular we have to avoid a match
             * of the string with itself at the start of the input file).
             */
            match_length_ = longest_match(hash_head);
            /* longest_match() sets match_start */

            if(match_length_ <= 5 && (strategy_ == Z_FILTERED
                || (match_length_ == limits::minMatch &&
                    strstart_ - match_start_ > kTooFar)
                )) {

                /* If prev_match is also limits::minMatch, match_start is garbage
                 * but we will ignore the current match anyway.
                 */
                match_length_ = limits::minMatch-1;
            }
        }
        /* If there was a match at the previous step and the current
         * match is not better, output the previous match:
         */
        if(prev_length_ >= limits::minMatch && match_length_ <= prev_length_) {
            uInt max_insert = strstart_ + lookahead_ - limits::minMatch;
            /* Do not insert strings in hash table beyond this. */

            tr_tally_dist(strstart_ -1 - prev_match_,
                           prev_length_ - limits::minMatch, bflush);

            /* Insert in hash table all strings up to the end of the match.
             * strstart-1 and strstart are already inserted. If there is not
             * enough lookahead, the last two strings are not inserted in
             * the hash table.
             */
            lookahead_ -= prev_length_-1;
            prev_length_ -= 2;
            do {
                if(++strstart_ <= max_insert) {
                    insert_string(hash_head);
                }
            } while(--prev_length_ != 0);
            match_available_ = 0;
            match_length_ = limits::minMatch-1;
            strstart_++;

            if(bflush)
            {
                flush_block(zs, false);
                if(zs.avail_out == 0)
                    return need_more;
            }

        } else if(match_available_) {
            /* If there was no match at the previous position, output a
             * single literal. If there was a match but the current match
             * is longer, truncate the previous match to a single literal.
             */
            Tracevv((stderr,"%c", window_[strstart_-1]));
            tr_tally_lit(window_[strstart_-1], bflush);
            if(bflush) {
                flush_block(zs, false);
            }
            strstart_++;
            lookahead_--;
            if(zs.avail_out == 0) return need_more;
        } else {
            /* There is no previous match to compare with, wait for
             * the next step to decide.
             */
            match_available_ = 1;
            strstart_++;
            lookahead_--;
        }
    }
    Assert (flush != Flush::none, "no flush?");
    if(match_available_) {
        Tracevv((stderr,"%c", window_[strstart_-1]));
        tr_tally_lit(window_[strstart_-1], bflush);
        match_available_ = 0;
    }
    insert_ = strstart_ < limits::minMatch-1 ? strstart_ : limits::minMatch-1;
    if(flush == Flush::finish)
    {
        flush_block(zs, true);
        if(zs.avail_out == 0)
            return finish_started;
        return finish_done;
    }
    if(last_lit_)
    {
        flush_block(zs, false);
        if(zs.avail_out == 0)
            return need_more;
    }
    return block_done;
}

/* ===========================================================================
 * For Z_RLE, simply look for runs of bytes, generate matches only of distance
 * one.  Do not maintain a hash table.  (It will be regenerated if this run of
 * deflate switches away from Z_RLE.)
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_rle(z_params& zs, Flush flush) ->
    block_state
{
    bool bflush;             /* set if current block must be flushed */
    uInt prev;              /* byte at distance one to match */
    Byte *scan, *strend;   /* scan goes up to strend for length of run */

    for(;;)
    {
        /* Make sure that we always have enough lookahead, except
         * at the end of the input file. We need limits::maxMatch bytes
         * for the longest run, plus one for the unrolled loop.
         */
        if(lookahead_ <= limits::maxMatch) {
            fill_window(zs);
            if(lookahead_ <= limits::maxMatch && flush == Flush::none) {
                return need_more;
            }
            if(lookahead_ == 0) break; /* flush the current block */
        }

        /* See how many times the previous byte repeats */
        match_length_ = 0;
        if(lookahead_ >= limits::minMatch && strstart_ > 0) {
            scan = window_ + strstart_ - 1;
            prev = *scan;
            if(prev == *++scan && prev == *++scan && prev == *++scan) {
                strend = window_ + strstart_ + limits::maxMatch;
                do {
                } while(prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         scan < strend);
                match_length_ = limits::maxMatch - (int)(strend - scan);
                if(match_length_ > lookahead_)
                    match_length_ = lookahead_;
            }
            Assert(scan <= window_+(uInt)(window_size_-1), "wild scan");
        }

        /* Emit match if have run of limits::minMatch or longer, else emit literal */
        if(match_length_ >= limits::minMatch) {
            tr_tally_dist(1, match_length_ - limits::minMatch, bflush);

            lookahead_ -= match_length_;
            strstart_ += match_length_;
            match_length_ = 0;
        } else {
            /* No match, output a literal byte */
            Tracevv((stderr,"%c", window_[strstart_]));
            tr_tally_lit(window_[strstart_], bflush);
            lookahead_--;
            strstart_++;
        }
        if(bflush)
        {
            flush_block(zs, false);
            if(zs.avail_out == 0)
                return need_more;
        }
    }
    insert_ = 0;
    if(flush == Flush::finish)
    {
        flush_block(zs, true);
        if(zs.avail_out == 0)
            return finish_started;
        return finish_done;
    }
    if(last_lit_)
    {
        flush_block(zs, false);
        if(zs.avail_out == 0)
            return need_more;
    }
    return block_done;
}

/* ===========================================================================
 * For Z_HUFFMAN_ONLY, do not look for matches.  Do not maintain a hash table.
 * (It will be regenerated if this run of deflate switches away from Huffman.)
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_huff(z_params& zs, Flush flush) ->
    block_state
{
    bool bflush;             // set if current block must be flushed

    for(;;)
    {
        // Make sure that we have a literal to write.
        if(lookahead_ == 0)
        {
            fill_window(zs);
            if(lookahead_ == 0)
            {
                if(flush == Flush::none)
                    return need_more;
                break;      // flush the current block
            }
        }

        // Output a literal byte
        match_length_ = 0;
        Tracevv((stderr,"%c", window_[strstart_]));
        tr_tally_lit(window_[strstart_], bflush);
        lookahead_--;
        strstart_++;
        if(bflush)
        {
            flush_block(zs, false);
            if(zs.avail_out == 0)
                return need_more;
        }
    }
    insert_ = 0;
    if(flush == Flush::finish)
    {
        flush_block(zs, true);
        if(zs.avail_out == 0)
            return finish_started;
        return finish_done;
    }
    if(last_lit_)
    {
        flush_block(zs, false);
        if(zs.avail_out == 0)
            return need_more;
    }
    return block_done;
}

} // zlib
} // beast

#endif
