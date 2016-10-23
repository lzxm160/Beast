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
#define ERR_RETURN(strm,err) \
  return (strm->msg = "unspecified zlib error", (err))



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

//------------------------------------------------------------------------------

/*  Determine the best encoding for the current block: dynamic trees,
    static trees or store, and output the encoded block to the zip file.
*/
template<class Allocator>
void
basic_deflate_stream<Allocator>::
tr_flush_block(
    char *buf,                  // input block, or NULL if too old
    std::uint32_t stored_len,   // length of input block
    int last)                   // one if this is the last block for a file
{
    std::uint32_t opt_lenb;
    std::uint32_t static_lenb;  // opt_len and static_len in bytes
    int max_blindex = 0;        // index of last bit length code of non zero freq

    // Build the Huffman trees unless a stored block is forced
    if(level_ > 0)
    {
        // Check if the file is binary or text
        if(data_type == Z_UNKNOWN)
            data_type = detect_data_type();

        // Construct the literal and distance trees
        build_tree((tree_desc *)(&(l_desc_)));
        Tracev((stderr, "\nlit data: dyn %ld, stat %ld", opt_len_,
                static_len_));

        build_tree((tree_desc *)(&(d_desc_)));
        Tracev((stderr, "\ndist data: dyn %ld, stat %ld", opt_len_,
                static_len_));
        /* At this point, opt_len and static_len are the total bit lengths of
         * the compressed block data, excluding the tree representations.
         */

        /* Build the bit length tree for the above two trees, and get the index
         * in bl_order of the last bit length code to send.
         */
        max_blindex = build_bl_tree();

        /* Determine the best encoding. Compute the block lengths in bytes. */
        opt_lenb = (opt_len_+3+7)>>3;
        static_lenb = (static_len_+3+7)>>3;

        Tracev((stderr, "\nopt %lu(%lu) stat %lu(%lu) stored %lu lit %u ",
                opt_lenb, opt_len_, static_lenb, static_len_, stored_len,
                last_lit_));
        if(static_lenb <= opt_lenb)
            opt_lenb = static_lenb;
    }
    else
    {
        Assert(buf != (char*)0, "lost buf");
        opt_lenb = static_lenb = stored_len + 5; // force a stored block
    }

#ifdef FORCE_STORED
    if(buf != (char*)0) { /* force stored block */
#else
    if(stored_len+4 <= opt_lenb && buf != (char*)0) {
                       /* 4: two words for the lengths */
#endif
        /* The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE.
         * Otherwise we can't have processed more than WSIZE input bytes since
         * the last block flush, because compression would have been
         * successful. If LIT_BUFSIZE <= WSIZE, it is never too late to
         * transform a block into a stored block.
         */
        tr_stored_block(buf, stored_len, last);

#ifdef FORCE_STATIC
    }
    else if(static_lenb >= 0)
    {
        // force static trees
#else
    }
    else if(strategy_ == Z_FIXED || static_lenb == opt_lenb)
    {
#endif
        send_bits((STATIC_TREES<<1)+last, 3);
        compress_block(lut_.ltree, lut_.dtree);
    }
    else
    {
        send_bits((DYN_TREES<<1)+last, 3);
        send_all_trees(l_desc_.max_code+1, d_desc_.max_code+1,
                       max_blindex+1);
        compress_block((const detail::ct_data *)dyn_ltree_,
                       (const detail::ct_data *)dyn_dtree_);
    }
    Assert (compressed_len_ == bits_sent_, "bad compressed size");
    /* The above check is made mod 2^32, for files larger than 512 MB
     * and std::size_t implemented on 32 bits.
     */
    init_block();

    if(last)
        bi_windup();
    Tracev((stderr,"\ncomprlen %lu(%lu) ", compressed_len_>>3,
           compressed_len_-7*last));
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

template<class Allocator>
void
basic_deflate_stream<Allocator>::
fill_window()
{
    unsigned n, m;
    std::uint16_t *p;
    unsigned more;    // Amount of free space at the end of the window.
    uInt wsize = w_size_;

    Assert(lookahead_ < kMinLookahead, "already enough lookahead");

    do {
        more = (unsigned)(window_size_ -(std::uint32_t)lookahead_ -(std::uint32_t)strstart_);

        /* Deal with !@#$% 64K limit: */
        if(sizeof(int) <= 2) {
            if(more == 0 && strstart_ == 0 && lookahead_ == 0) {
                more = wsize;

            } else if(more == (unsigned)(-1)) {
                /* Very unlikely, but possible on 16 bit machine if
                 * strstart == 0 && lookahead == 1 (input done a byte at time)
                 */
                more--;
            }
        }

        /* If the window is almost full and there is insufficient lookahead,
         * move the upper half to the lower one to make room in the upper half.
         */
        if(strstart_ >= wsize+max_dist()) {

            std::memcpy(window_, window_+wsize, (unsigned)wsize);
            match_start_ -= wsize;
            strstart_    -= wsize; /* we now have strstart >= max_dist */
            block_start_ -= (long) wsize;

            /* Slide the hash table (could be avoided with 32 bit values
               at the expense of memory usage). We slide even when level == 0
               to keep the hash table consistent if we switch back to level > 0
               later. (Using level 0 permanently is not an optimal usage of
               zlib, so we don't care about this pathological case.)
             */
            n = hash_size_;
            p = &head_[n];
            do {
                m = *--p;
                *p = (std::uint16_t)(m >= wsize ? m-wsize : 0);
            } while (--n);

            n = wsize;
            p = &prev_[n];
            do {
                m = *--p;
                *p = (std::uint16_t)(m >= wsize ? m-wsize : 0);
                /* If n is not on any hash chain, prev[n] is garbage but
                 * its value will never be used.
                 */
            } while (--n);
            more += wsize;
        }
        if(avail_in == 0) break;

        /* If there was no sliding:
         *    strstart <= WSIZE+max_dist-1 && lookahead <= kMinLookahead - 1 &&
         *    more == window_size - lookahead - strstart
         * => more >= window_size - (kMinLookahead-1 + WSIZE + max_dist-1)
         * => more >= window_size - 2*WSIZE + 2
         * In the BIG_MEM or MMAP case (not yet supported),
         *   window_size == input_size + kMinLookahead  &&
         *   strstart + lookahead_ <= input_size => more >= kMinLookahead.
         * Otherwise, window_size == 2*WSIZE so more >= 2.
         * If there was sliding, more >= WSIZE. So in all cases, more >= 2.
         */
        Assert(more >= 2, "more < 2");

        n = read_buf(window_ + strstart_ + lookahead_, more);
        lookahead_ += n;

        /* Initialize the hash value now that we have some input: */
        if(lookahead_ + insert_ >= limits::minMatch) {
            uInt str = strstart_ - insert_;
            ins_h_ = window_[str];
            update_hash(ins_h_, window_[str + 1]);
            while(insert_)
            {
                update_hash(ins_h_, window_[str + limits::minMatch-1]);
                prev_[str & w_mask_] = head_[ins_h_];
                head_[ins_h_] = (std::uint16_t)str;
                str++;
                insert_--;
                if(lookahead_ + insert_ < limits::minMatch)
                    break;
            }
        }
        /* If the whole input has less than limits::minMatch bytes, ins_h is garbage,
         * but this is not important since only literal bytes will be emitted.
         */
    }
    while (lookahead_ < kMinLookahead && avail_in != 0);

    /* If the kWinInit bytes after the end of the current data have never been
     * written, then zero those bytes in order to avoid memory check reports of
     * the use of uninitialized (or uninitialised as Julian writes) bytes by
     * the longest match routines.  Update the high water mark for the next
     * time through here.  kWinInit is set to limits::maxMatch since the longest match
     * routines allow scanning to strstart + limits::maxMatch, ignoring lookahead.
     */
    if(high_water_ < window_size_) {
        std::uint32_t curr = strstart_ + (std::uint32_t)(lookahead_);
        std::uint32_t init;

        if(high_water_ < curr) {
            /* Previous high water mark below current data -- zero kWinInit
             * bytes or up to end of window, whichever is less.
             */
            init = window_size_ - curr;
            if(init > kWinInit)
                init = kWinInit;
            std::memset(window_ + curr, 0, (unsigned)init);
            high_water_ = curr + init;
        }
        else if(high_water_ < (std::uint32_t)curr + kWinInit) {
            /* High water mark at or above current data, but below current data
             * plus kWinInit -- zero out to current data plus kWinInit, or up
             * to end of window, whichever is less.
             */
            init = (std::uint32_t)curr + kWinInit - high_water_;
            if(init > window_size_ - high_water_)
                init = window_size_ - high_water_;
            std::memset(window_ + high_water_, 0, (unsigned)init);
            high_water_ += init;
        }
    }

    Assert((std::uint32_t)strstart_ <= window_size_ - kMinLookahead,
           "not enough room for search");
}

/*  Flush as much pending output as possible. All deflate() output goes
    through this function so some applications may wish to modify it
    to avoid allocating a large strm->next_out buffer and copying into it.
    (See also read_buf()).
*/
template<class Allocator>
void
basic_deflate_stream<Allocator>::
flush_pending()
{
    tr_flush_bits();
    unsigned len = pending_;
    if(len > avail_out)
        len = avail_out;
    if(len == 0) return;

    std::memcpy(next_out, pending_out_, len);
    next_out = static_cast<std::uint8_t*>(
        next_out) + len;
    pending_out_  += len;
    total_out += len;
    avail_out  -= len;
    pending_ -= len;
    if(pending_ == 0)
        pending_out_ = pending_buf_;
}

/*  Read a new buffer from the current input stream, update the adler32
    and total number of bytes read.  All deflate() input goes through
    this function so some applications may wish to modify it to avoid
    allocating a large strm->next_in buffer and copying from it.
    (See also flush_pending()).
*/
template<class Allocator>
int
basic_deflate_stream<Allocator>::
read_buf(Byte *buf, unsigned size)
{
    unsigned len = avail_in;

    if(len > size)
        len = size;
    if(len == 0)
        return 0;

    avail_in  -= len;

    std::memcpy(buf, next_in, len);
    next_in = static_cast<
        std::uint8_t const*>(next_in) + len;
    total_in += len;
    return (int)len;
}

/*  Set match_start to the longest match starting at the given string and
    return its length. Matches shorter or equal to prev_length are discarded,
    in which case the result is equal to prev_length and match_start is
    garbage.
    IN assertions: cur_match is the head of the hash chain for the current
        string (strstart) and its distance is <= max_dist, and prev_length >= 1
    OUT assertion: the match length is not greater than s->lookahead_.

    For 80x86 and 680x0, an optimized version will be provided in match.asm or
    match.S. The code will be functionally equivalent.
*/
template<class Allocator>
uInt
basic_deflate_stream<Allocator>::
longest_match(IPos cur_match)
{
    unsigned chain_length = max_chain_length_;/* max hash chain length */
    Byte *scan = window_ + strstart_; /* current string */
    Byte *match;                       /* matched string */
    int len;                           /* length of current match */
    int best_len = prev_length_;              /* best match length so far */
    int nice_match = nice_match_;             /* stop if match long enough */
    IPos limit = strstart_ > (IPos)max_dist() ?
        strstart_ - (IPos)max_dist() : 0;
    /* Stop when cur_match becomes <= limit. To simplify the code,
     * we prevent matches with the string of window index 0.
     */
    std::uint16_t *prev = prev_;
    uInt wmask = w_mask_;

    Byte *strend = window_ + strstart_ + limits::maxMatch;
    Byte scan_end1  = scan[best_len-1];
    Byte scan_end   = scan[best_len];

    /* The code is optimized for HASH_BITS >= 8 and limits::maxMatch-2 multiple of 16.
     * It is easy to get rid of this optimization if necessary.
     */
    Assert(hash_bits_ >= 8 && limits::maxMatch == 258, "fc too clever");

    /* Do not waste too much time if we already have a good match: */
    if(prev_length_ >= good_match_) {
        chain_length >>= 2;
    }
    /* Do not look for matches beyond the end of the input. This is necessary
     * to make deflate deterministic.
     */
    if((uInt)nice_match > lookahead_)
        nice_match = lookahead_;

    Assert((std::uint32_t)strstart_ <= window_size_-kMinLookahead, "need lookahead");

    do {
        Assert(cur_match < strstart_, "no future");
        match = window_ + cur_match;

        /* Skip to next match if the match length cannot increase
         * or if the match length is less than 2.  Note that the checks below
         * for insufficient lookahead only occur occasionally for performance
         * reasons.  Therefore uninitialized memory will be accessed, and
         * conditional jumps will be made that depend on those values.
         * However the length of the match is limited to the lookahead, so
         * the output of deflate is not affected by the uninitialized values.
         */
        if(match[best_len]   != scan_end  ||
            match[best_len-1] != scan_end1 ||
            *match            != *scan     ||
            *++match          != scan[1])      continue;

        /* The check at best_len-1 can be removed because it will be made
         * again later. (This heuristic is not always a win.)
         * It is not necessary to compare scan[2] and match[2] since they
         * are always equal when the other bytes match, given that
         * the hash keys are equal and that HASH_BITS >= 8.
         */
        scan += 2, match++;
        Assert(*scan == *match, "match[2]?");

        /* We check for insufficient lookahead only every 8th comparison;
         * the 256th check will be made at strstart+258.
         */
        do {
        } while (*++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 scan < strend);

        Assert(scan <= window_+(unsigned)(window_size_-1), "wild scan");

        len = limits::maxMatch - (int)(strend - scan);
        scan = strend - limits::maxMatch;

        if(len > best_len) {
            match_start_ = cur_match;
            best_len = len;
            if(len >= nice_match) break;
            scan_end1  = scan[best_len-1];
            scan_end   = scan[best_len];
        }
    } while ((cur_match = prev[cur_match & wmask]) > limit
             && --chain_length != 0);

    if((uInt)best_len <= lookahead_)
        return (uInt)best_len;
    return lookahead_;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
deflateSetDictionary (
    const Byte *dictionary,
    uInt  dictLength)
{
auto strm = this;
    uInt str, n;
    unsigned avail;
    const unsigned char *next;

    auto s = strm;

    if(s->lookahead_)
        return Z_STREAM_ERROR;

    /* if dictionary would fill window, just replace the history */
    if(dictLength >= s->w_size_)
    {
        clear_hash();
        s->strstart_ = 0;
        s->block_start_ = 0L;
        s->insert_ = 0;
        dictionary += dictLength - s->w_size_;  /* use the tail */
        dictLength = s->w_size_;
    }

    /* insert dictionary into window and hash */
    avail = strm->avail_in;
    next = strm->next_in;
    strm->avail_in = dictLength;
    strm->next_in = (const Byte *)dictionary;
    s->fill_window();
    while (s->lookahead_ >= limits::minMatch) {
        str = s->strstart_;
        n = s->lookahead_ - (limits::minMatch-1);
        do
        {
            s->update_hash(s->ins_h_, s->window_[str + limits::minMatch-1]);
            s->prev_[str & s->w_mask_] = s->head_[s->ins_h_];
            s->head_[s->ins_h_] = (std::uint16_t)str;
            str++;
        }
        while (--n);
        s->strstart_ = str;
        s->lookahead_ = limits::minMatch-1;
        s->fill_window();
    }
    s->strstart_ += s->lookahead_;
    s->block_start_ = (long)s->strstart_;
    s->insert_ = s->lookahead_;
    s->lookahead_ = 0;
    s->match_length_ = s->prev_length_ = limits::minMatch-1;
    s->match_available_ = 0;
    strm->next_in = next;
    strm->avail_in = avail;
    return Z_OK;
}

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
deflateResetKeep()
{
    total_in = 0;
    total_out = 0;
    msg = 0;
    data_type = Z_UNKNOWN;

    pending_ = 0;
    pending_out_ = pending_buf_;

    status_ = BUSY_STATE;
    last_flush_ = Z_NO_FLUSH;

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
params(int level, int strategy)
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
        err = deflate(Z_BLOCK);
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

/* ========================================================================= */

template<class Allocator>
int
basic_deflate_stream<Allocator>::
deflate(int flush)
{
    int old_flush; /* value of flush param for previous deflate call */

    if(next_out == 0 ||
        (next_in == 0 && avail_in != 0) ||
        (status_ == FINISH_STATE && flush != Z_FINISH)) {
        ERR_RETURN(this, Z_STREAM_ERROR);
    }
    if(avail_out == 0)
        ERR_RETURN(this, Z_BUF_ERROR);

    old_flush = last_flush_;
    last_flush_ = flush;

    /* Flush as much pending output as possible */
    if(pending_ != 0) {
        flush_pending();
        if(avail_out == 0) {
            /* Since avail_out is 0, deflate will be called again with
             * more output space, but possibly with both pending and
             * avail_in equal to zero. There won't be anything to do,
             * but this is not an error situation so make sure we
             * return OK instead of BUF_ERROR at next call of deflate:
             */
            last_flush_ = -1;
            return Z_OK;
        }

    /* Make sure there is something to do and avoid duplicate consecutive
     * flushes. For repeated and useless calls with Z_FINISH, we keep
     * returning Z_STREAM_END instead of Z_BUF_ERROR.
     */
    } else if(avail_in == 0 && flushRank(flush) <= flushRank(old_flush) &&
               flush != Z_FINISH) {
        ERR_RETURN(this, Z_BUF_ERROR);
    }

    /* User must not provide more input after the first FINISH: */
    if(status_ == FINISH_STATE && avail_in != 0) {
        ERR_RETURN(this, Z_BUF_ERROR);
    }

    /* Start a new block or continue the current one.
     */
    if(avail_in != 0 || lookahead_ != 0 ||
        (flush != Z_NO_FLUSH && status_ != FINISH_STATE)) {
        block_state bstate;

        auto const func = get_config(level_).func;
        bstate = strategy_ == Z_HUFFMAN_ONLY ? deflate_huff(flush) :
                    (strategy_ == Z_RLE ? deflate_rle(flush) :
                        (this->*func)(flush));

        if(bstate == finish_started || bstate == finish_done) {
            status_ = FINISH_STATE;
        }
        if(bstate == need_more || bstate == finish_started) {
            if(avail_out == 0) {
                last_flush_ = -1; /* avoid BUF_ERROR next call, see above */
            }
            return Z_OK;
            /* If flush != Z_NO_FLUSH && avail_out == 0, the next call
             * of deflate should use the same flush parameter to make sure
             * that the flush is complete. So we don't have to output an
             * empty block here, this will be done at next call. This also
             * ensures that for a very small output buffer, we emit at most
             * one empty block.
             */
        }
        if(bstate == block_done) {
            if(flush == Z_PARTIAL_FLUSH) {
                tr_align();
            } else if(flush != Z_BLOCK) { /* FULL_FLUSH or SYNC_FLUSH */
                tr_stored_block((char*)0, 0L, 0);
                /* For a full flush, this empty block will be recognized
                 * as a special marker by inflate_sync().
                 */
                if(flush == Z_FULL_FLUSH)
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
            flush_pending();
            if(avail_out == 0) {
              last_flush_ = -1; /* avoid BUF_ERROR at next call, see above */
              return Z_OK;
            }
        }
    }
    Assert(avail_out > 0, "bug2");

    if(flush != Z_FINISH)
        return Z_OK;
    return Z_STREAM_END;
}

/* ===========================================================================
 * Flush the current block, with given end-of-file flag.
 * IN assertion: strstart is set to the end of the current match.
 */
#define FLUSH_BLOCK_ONLY(last) { \
   tr_flush_block((block_start_ >= 0L ? \
                   (char *)&window_[(unsigned)block_start_] : \
                   (char *)0), \
                (std::uint32_t)((long)strstart_ - block_start_), \
                (last)); \
   block_start_ = strstart_; \
   flush_pending(); \
   Tracev((stderr,"[FLUSH]")); \
}

/* Same but force premature exit if necessary. */
#define FLUSH_BLOCK(last) { \
   FLUSH_BLOCK_ONLY(last); \
   if(avail_out == 0) return (last) ? finish_started : need_more; \
}

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
deflate_stored(int flush) ->
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

            fill_window();
            if(lookahead_ == 0 && flush == Z_NO_FLUSH)
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
            FLUSH_BLOCK(0);
        }
        /* Flush if we may have to slide, otherwise block_start may become
         * negative and the data will be gone:
         */
        if(strstart_ - (uInt)block_start_ >= max_dist()) {
            FLUSH_BLOCK(0);
        }
    }
    insert_ = 0;
    if(flush == Z_FINISH) {
        FLUSH_BLOCK(1);
        return finish_done;
    }
    if((long)strstart_ > block_start_)
        FLUSH_BLOCK(0);
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
deflate_fast(int flush) ->
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
            fill_window();
            if(lookahead_ < kMinLookahead && flush == Z_NO_FLUSH)
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
                } while (--match_length_ != 0);
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
        if(bflush) FLUSH_BLOCK(0);
    }
    insert_ = strstart_ < limits::minMatch-1 ? strstart_ : limits::minMatch-1;
    if(flush == Z_FINISH) {
        FLUSH_BLOCK(1);
        return finish_done;
    }
    if(last_lit_)
        FLUSH_BLOCK(0);
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
deflate_slow(int flush) ->
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
            fill_window();
            if(lookahead_ < kMinLookahead && flush == Z_NO_FLUSH) {
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
            } while (--prev_length_ != 0);
            match_available_ = 0;
            match_length_ = limits::minMatch-1;
            strstart_++;

            if(bflush) FLUSH_BLOCK(0);

        } else if(match_available_) {
            /* If there was no match at the previous position, output a
             * single literal. If there was a match but the current match
             * is longer, truncate the previous match to a single literal.
             */
            Tracevv((stderr,"%c", window_[strstart_-1]));
            tr_tally_lit(window_[strstart_-1], bflush);
            if(bflush) {
                FLUSH_BLOCK_ONLY(0);
            }
            strstart_++;
            lookahead_--;
            if(avail_out == 0) return need_more;
        } else {
            /* There is no previous match to compare with, wait for
             * the next step to decide.
             */
            match_available_ = 1;
            strstart_++;
            lookahead_--;
        }
    }
    Assert (flush != Z_NO_FLUSH, "no flush?");
    if(match_available_) {
        Tracevv((stderr,"%c", window_[strstart_-1]));
        tr_tally_lit(window_[strstart_-1], bflush);
        match_available_ = 0;
    }
    insert_ = strstart_ < limits::minMatch-1 ? strstart_ : limits::minMatch-1;
    if(flush == Z_FINISH) {
        FLUSH_BLOCK(1);
        return finish_done;
    }
    if(last_lit_)
        FLUSH_BLOCK(0);
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
deflate_rle(int flush) ->
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
            fill_window();
            if(lookahead_ <= limits::maxMatch && flush == Z_NO_FLUSH) {
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
                } while (prev == *++scan && prev == *++scan &&
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
        if(bflush) FLUSH_BLOCK(0);
    }
    insert_ = 0;
    if(flush == Z_FINISH) {
        FLUSH_BLOCK(1);
        return finish_done;
    }
    if(last_lit_)
        FLUSH_BLOCK(0);
    return block_done;
}

/* ===========================================================================
 * For Z_HUFFMAN_ONLY, do not look for matches.  Do not maintain a hash table.
 * (It will be regenerated if this run of deflate switches away from Huffman.)
 */
template<class Allocator>
auto
basic_deflate_stream<Allocator>::
deflate_huff(int flush) ->
    block_state
{
    bool bflush;             // set if current block must be flushed

    for(;;)
    {
        // Make sure that we have a literal to write.
        if(lookahead_ == 0)
        {
            fill_window();
            if(lookahead_ == 0)
            {
                if(flush == Z_NO_FLUSH)
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
            FLUSH_BLOCK(0);
    }
    insert_ = 0;
    if(flush == Z_FINISH)
    {
        FLUSH_BLOCK(1);
        return finish_done;
    }
    if(last_lit_)
        FLUSH_BLOCK(0);
    return block_done;
}

} // zlib
} // beast

#endif
