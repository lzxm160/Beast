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

#ifndef BEAST_ZLIB_DETAIL_DEFLATE_STREAM_BASE_HPP
#define BEAST_ZLIB_DETAIL_DEFLATE_STREAM_BASE_HPP

#include <beast/zlib/zlib.hpp>
#include <beast/zlib/detail/deflate.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace beast {
namespace zlib {
namespace detail {

template<class = void>
class deflate_stream_base
{
protected:
    deflate_stream_base()
        :  lut_(get_deflate_tables())
    {
    }

    /*  Note: the deflate() code requires max_lazy >= limits::minMatch and max_chain >= 4
        For deflate_fast() (levels <= 3) good is ignored and lazy has a different
        meaning.
    */

    // maximum heap size
    static std::uint16_t constexpr HEAP_SIZE = 2 * limits::lCodes + 1;

    // size of bit buffer in bi_buf
    static std::uint8_t constexpr Buf_size = 16;

    // Matches of length 3 are discarded if their distance exceeds kTooFar
    static std::size_t constexpr kTooFar = 4096;

    /*  Minimum amount of lookahead, except at the end of the input file.
        See deflate.c for comments about the limits::minMatch+1.
    */
    static std::size_t constexpr kMinLookahead = limits::maxMatch + limits::minMatch+1;

    /*  Number of bytes after end of data in window to initialize in order
        to avoid memory checker errors from longest match routines
    */
    static std::size_t constexpr kWinInit = limits::maxMatch;

    // VFALCO This might not be needed, e.g. for zip/gzip
    enum StreamStatus
    {
        EXTRA_STATE = 69,
        NAME_STATE = 73,
        COMMENT_STATE = 91,
        HCRC_STATE = 103,
        BUSY_STATE = 113,
        FINISH_STATE = 666
    };

    struct tree_desc
    {
        ct_data *dyn_tree;           /* the dynamic tree */
        int     max_code;            /* largest code with non zero frequency */
        static_tree_desc const* stat_desc; /* the corresponding static tree */
    };

    /* A std::uint16_t is an index in the character window. We use short instead of int to
     * save space in the various tables. IPos is used only for parameter passing.
     */
    using IPos = unsigned;

    enum block_state
    {
        need_more,      /* block not completed, need more input or more output */
        block_done,     /* block flush performed */
        finish_started, /* finish started, need only more output at next deflate */
        finish_done     /* finish done, accept no more input or output */
    };

    deflate_tables const& lut_;

    std::unique_ptr<std::uint8_t[]> buf_;

    int status_;                    // as the name implies
    Byte* pending_buf_;             // output still pending
    std::uint32_t
        pending_buf_size_;          // size of pending_buf
    Byte* pending_out_;             // next pending byte to output to the stream
    uInt pending_;                  // nb of bytes in the pending buffer
    int last_flush_;                // value of flush param for previous deflate call

    uInt w_size_;                   // LZ77 window size (32K by default)
    uInt w_bits_;                   // log2(w_size)  (8..16)
    uInt w_mask_;                   // w_size - 1

    /*  Sliding window. Input bytes are read into the second half of the window,
        and move to the first half later to keep a dictionary of at least wSize
        bytes. With this organization, matches are limited to a distance of
        wSize-limits::maxMatch bytes, but this ensures that IO is always
        performed with a length multiple of the block size. Also, it limits
        the window size to 64K.
        To do: use the user input buffer as sliding window.
    */
    Byte *window_ = nullptr;

    /*  Actual size of window: 2*wSize, except when the user input buffer
        is directly used as sliding window.
    */
    std::uint32_t window_size_;

    /*  Link to older string with same hash index. To limit the size of this
        array to 64K, this link is maintained only for the last 32K strings.
        An index in this array is thus a window index modulo 32K.
    */
    std::uint16_t* prev_;

    std::uint16_t* head_;           // Heads of the hash chains or 0

    uInt  ins_h_;                   // hash index of string to be inserted
    uInt  hash_size_;               // number of elements in hash table
    uInt  hash_bits_;               // log2(hash_size)
    uInt  hash_mask_;               // hash_size-1

    /*  Number of bits by which ins_h must be shifted at each input
        step. It must be such that after limits::minMatch steps,
        the oldest byte no longer takes part in the hash key, that is:
        hash_shift * limits::minMatch >= hash_bits
    */
    uInt hash_shift_;

    /*  Window position at the beginning of the current output block.
        Gets negative when the window is moved backwards.
    */
    long block_start_;

    uInt match_length_;             // length of best match
    IPos prev_match_;               // previous match
    int match_available_;           // set if previous match exists
    uInt strstart_;                 // start of string to insert
    uInt match_start_;              // start of matching string
    uInt lookahead_;                // number of valid bytes ahead in window

    /*  Length of the best match at previous step. Matches not greater
        than this are discarded. This is used in the lazy match evaluation.
    */
    uInt prev_length_;

    /*  To speed up deflation, hash chains are never searched beyond
        this length. A higher limit improves compression ratio but
        degrades the speed.
    */
    uInt max_chain_length_;

    /*  Attempt to find a better match only when the current match is strictly
        smaller than this value. This mechanism is used only for compression
        levels >= 4.

        OR Insert new strings in the hash table only if the match length is not
        greater than this length. This saves time but degrades compression.
        used only for compression levels <= 3.
    */
    uInt max_lazy_match_;

    int level_;                     // compression level (1..9)
    int strategy_;                  // favor or force Huffman coding

    // Use a faster search when the previous match is longer than this
    uInt good_match_;

    int nice_match_;                // Stop searching when current match exceeds this

    ct_data dyn_ltree_[
        HEAP_SIZE];                 // literal and length tree
    ct_data dyn_dtree_[
        2*limits::dCodes+1];        // distance tree */
    ct_data bl_tree_[
        2*limits::blCodes+1];       // Huffman tree for bit lengths

    tree_desc l_desc_;              // desc. for literal tree
    tree_desc d_desc_;              // desc. for distance tree
    tree_desc bl_desc_;             // desc. for bit length tree

    // number of codes at each bit length for an optimal tree
    std::uint16_t bl_count_[limits::maxBits+1];

    // Index within the heap array of least frequent node in the Huffman tree
    static std::size_t constexpr kSmallest = 1;

    /*  The sons of heap[n] are heap[2*n] and heap[2*n+1].
        heap[0] is not used. The same heap array is used to build all trees.
    */

    int heap_[2*limits::lCodes+1];  // heap used to build the Huffman trees
    int heap_len_;                  // number of elements in the heap
    int heap_max_;                  // element of largest frequency

    // Depth of each subtree used as tie breaker for trees of equal frequency
    std::uint8_t depth_[2*limits::lCodes+1];

    std::uint8_t *l_buf_;           // buffer for literals or lengths

    /*  Size of match buffer for literals/lengths.
        There are 4 reasons for limiting lit_bufsize to 64K:
          - frequencies can be kept in 16 bit counters
          - if compression is not successful for the first block, all input
            data is still in the window so we can still emit a stored block even
            when input comes from standard input.  (This can also be done for
            all blocks if lit_bufsize is not greater than 32K.)
          - if compression is not successful for a file smaller than 64K, we can
            even emit a stored file instead of a stored block (saving 5 bytes).
            This is applicable only for zip (not gzip or zlib).
          - creating new Huffman trees less frequently may not provide fast
            adaptation to changes in the input data statistics. (Take for
            example a binary file with poorly compressible code followed by
            a highly compressible string table.) Smaller buffer sizes give
            fast adaptation but have of course the overhead of transmitting
            trees more frequently.
          - I can't count above 4
    */
    uInt lit_bufsize_;
    uInt last_lit_;                 // running index in l_buf_

    /*  Buffer for distances. To simplify the code, d_buf_ and l_buf_
        have the same number of elements. To use different lengths, an
        extra flag array would be necessary.
    */
    std::uint16_t* d_buf_;

    std::uint32_t opt_len_;         // bit length of current block with optimal trees
    std::uint32_t static_len_;      // bit length of current block with static trees
    uInt matches_;                  // number of string matches in current block
    uInt insert_;                   // bytes at end of window left to insert

    /*  Output buffer.
        Bits are inserted starting at the bottom (least significant bits).
     */
    std::uint16_t bi_buf_;

    /*  Number of valid bits in bi_buf._  All bits above the last valid
        bit are always zero.
    */
    int bi_valid_;

    /*  High water mark offset in window for initialized bytes -- bytes
        above this are set to zero in order to avoid memory check warnings
        when longest match routines access bytes past the input.  This is
        then updated to the new high water mark.
    */
    std::uint32_t high_water_;

    //--------------------------------------------------------------------------

    // rank Z_BLOCK between Z_NO_FLUSH and Z_PARTIAL_FLUSH
    static
    int
    flushRank(int flush)
    {
        return (flush << 1) - (flush > 4 ? 9 : 0);
    }

    /*  In order to simplify the code, particularly on 16 bit machines, match
        distances are limited to MAX_DIST instead of WSIZE.
    */
    inline
    std::size_t
    max_dist() const
    {
        return w_size_ - kMinLookahead;
    }

    void
    put_byte(std::uint8_t c)
    {
        pending_buf_[pending_++] = c;
    }

    void
    put_short(std::uint16_t w)
    {
        put_byte(w & 0xff);
        put_byte(w >> 8);
    }

    /*  Send a value on a given number of bits.
        IN assertion: length <= 16 and value fits in length bits.
    */
    void
    send_bits(int value, int length)
    {
        if(bi_valid_ > (int)Buf_size - length)
        {
            bi_buf_ |= (std::uint16_t)value << bi_valid_;
            put_short(bi_buf_);
            bi_buf_ = (std::uint16_t)value >> (Buf_size - bi_valid_);
            bi_valid_ += length - Buf_size;
        }
        else
        {
            bi_buf_ |= (std::uint16_t)(value) << bi_valid_;
            bi_valid_ += length;
        }
    }

    // Send a code of the given tree
    void
    send_code(int value, ct_data const* tree)
    {
        send_bits(tree[value].fc, tree[value].dl);
    }

    /*  Mapping from a distance to a distance code. dist is the
        distance - 1 and must not have side effects. _dist_code[256]
        and _dist_code[257] are never used.
    */
    std::uint8_t
    d_code(unsigned dist)
    {
        if(dist < 256)
            return lut_.dist_code[dist];
        return lut_.dist_code[256+(dist>>7)];
    }

    /*  Update a hash value with the given input byte
        IN  assertion: all calls to to update_hash are made with
            consecutive input characters, so that a running hash
            key can be computed from the previous key instead of
            complete recalculation each time.
    */
    void
    update_hash(uInt& h, std::uint8_t c)
    {
        h = ((h << hash_shift_) ^ c) & hash_mask_;
    }

    /*  Initialize the hash table (avoiding 64K overflow for 16
        bit systems). prev[] will be initialized on the fly.
    */
    void
    clear_hash()
    {
        head_[hash_size_-1] = 0;
        std::memset((Byte *)head_, 0,
            (unsigned)(hash_size_-1)*sizeof(*head_));
    }

    /*  Compares two subtrees, using the tree depth as tie breaker
        when the subtrees have equal frequency. This minimizes the
        worst case length.
    */
    bool
    smaller(ct_data const* tree, int n, int m)
    {
        return tree[n].fc < tree[m].fc ||
            (tree[n].fc == tree[m].fc &&
                depth_[n] <= depth_[m]);
    }

    /*  Insert string str in the dictionary and set match_head to the
        previous head of the hash chain (the most recent string with
        same hash key). Return the previous length of the hash chain.
        If this file is compiled with -DFASTEST, the compression level
        is forced to 1, and no hash chains are maintained.
        IN  assertion: all calls to to INSERT_STRING are made with
            consecutive input characters and the first limits::minMatch
            bytes of str are valid (except for the last limits::minMatch-1
            bytes of the input file).
    */
    void
    insert_string(IPos& hash_head)
    {
        update_hash(ins_h_, window_[strstart_ + (limits::minMatch-1)]);
        hash_head = prev_[strstart_ & w_mask_] = head_[ins_h_];
        head_[ins_h_] = (std::uint16_t)strstart_;
    }

    //--------------------------------------------------------------------------

    void init_block         ();
    void pqdownheap         (detail::ct_data const* tree, int k);
    void pqremove           (detail::ct_data const* tree, int& top);
    void gen_bitlen         (tree_desc *desc);
    void build_tree         (tree_desc *desc);
    void scan_tree          (detail::ct_data *tree, int max_code);
    void send_tree          (detail::ct_data *tree, int max_code);
    int  build_bl_tree      ();
    void send_all_trees     (int lcodes, int dcodes, int blcodes);
    void compress_block     (detail::ct_data const* ltree, detail::ct_data const* dtree);
    int  detect_data_type   ();
    void bi_windup          ();
    void bi_flush           ();
    void copy_block         (char *buf, unsigned len, int header);
};

//--------------------------------------------------------------------------

// Initialize a new block.
//
template<class _>
void
deflate_stream_base<_>::
init_block()
{
    for(int n = 0; n < limits::lCodes;  n++)
        dyn_ltree_[n].fc = 0;
    for(int n = 0; n < limits::dCodes;  n++)
        dyn_dtree_[n].fc = 0;
    for(int n = 0; n < limits::blCodes; n++)
        bl_tree_[n].fc = 0;
    dyn_ltree_[END_BLOCK].fc = 1;
    opt_len_ = 0L;
    static_len_ = 0L;
    last_lit_ = 0;
    matches_ = 0;
}

/*  Restore the heap property by moving down the tree starting at node k,
    exchanging a node with the smallest of its two sons if necessary,
    stopping when the heap property is re-established (each father smaller
    than its two sons).
*/
template<class _>
void
deflate_stream_base<_>::
pqdownheap(
    detail::ct_data const* tree,    // the tree to restore
    int k)                          // node to move down
{
    int v = heap_[k];
    int j = k << 1;  // left son of k
    while(j <= heap_len_)
    {
        // Set j to the smallest of the two sons:
        if(j < heap_len_ &&
                smaller(tree, heap_[j+1], heap_[j]))
            j++;
        // Exit if v is smaller than both sons
        if(smaller(tree, v, heap_[j]))
            break;

        // Exchange v with the smallest son
        heap_[k] = heap_[j];
        k = j;

        // And continue down the tree,
        // setting j to the left son of k
        j <<= 1;
    }
    heap_[k] = v;
}

/*  Remove the smallest element from the heap and recreate the heap
    with one less element. Updates heap and heap_len.
*/
template<class _>
inline
void
deflate_stream_base<_>::
pqremove(detail::ct_data const* tree, int& top)
{
    top = heap_[kSmallest];
    heap_[kSmallest] = heap_[heap_len_--];
    pqdownheap(tree, kSmallest);
}

/*  Compute the optimal bit lengths for a tree and update the total bit length
    for the current block.
    IN assertion: the fields freq and dad are set, heap[heap_max] and
       above are the tree nodes sorted by increasing frequency.
    OUT assertions: the field len is set to the optimal bit length, the
        array bl_count contains the frequencies for each bit length.
        The length opt_len is updated; static_len is also updated if stree is
        not null.
*/
template<class _>
void
deflate_stream_base<_>::
gen_bitlen(tree_desc *desc)
{
    detail::ct_data *tree           = desc->dyn_tree;
    int max_code                    = desc->max_code;
    detail::ct_data const* stree    = desc->stat_desc->static_tree;
    std::uint8_t const *extra       = desc->stat_desc->extra_bits;
    int base                        = desc->stat_desc->extra_base;
    int max_length                  = desc->stat_desc->max_length;
    int h;                          // heap index
    int n, m;                       // iterate over the tree elements
    int bits;                       // bit length
    int xbits;                      // extra bits
    std::uint16_t f;                // frequency
    int overflow = 0;               // number of elements with bit length too large

    std::fill(&bl_count_[0], &bl_count_[limits::maxBits+1], 0);

    /* In a first pass, compute the optimal bit lengths (which may
     * overflow in the case of the bit length tree).
     */
    tree[heap_[heap_max_]].dl = 0; // root of the heap

    for(h = heap_max_+1; h < HEAP_SIZE; h++) {
        n = heap_[h];
        bits = tree[tree[n].dl].dl + 1;
        if(bits > max_length) bits = max_length, overflow++;
        // We overwrite tree[n].dl which is no longer needed
        tree[n].dl = (std::uint16_t)bits;

        if(n > max_code)
            continue; // not a leaf node

        bl_count_[bits]++;
        xbits = 0;
        if(n >= base)
            xbits = extra[n-base];
        f = tree[n].fc;
        opt_len_ += (std::uint32_t)f * (bits + xbits);
        if(stree)
            static_len_ += (std::uint32_t)f * (stree[n].dl + xbits);
    }
    if(overflow == 0)
        return;

    /* This happens for example on obj2 and pic of the Calgary corpus */
    Trace((stderr,"\nbit length overflow\n"));

    // Find the first bit length which could increase:
    do
    {
        bits = max_length-1;
        while(bl_count_[bits] == 0)
            bits--;
        bl_count_[bits]--;      // move one leaf down the tree
        bl_count_[bits+1] += 2; // move one overflow item as its brother
        bl_count_[max_length]--;
        /* The brother of the overflow item also moves one step up,
         * but this does not affect bl_count[max_length]
         */
        overflow -= 2;
    }
    while(overflow > 0);

    /* Now recompute all bit lengths, scanning in increasing frequency.
     * h is still equal to HEAP_SIZE. (It is simpler to reconstruct all
     * lengths instead of fixing only the wrong ones. This idea is taken
     * from 'ar' written by Haruhiko Okumura.)
     */
    for(bits = max_length; bits != 0; bits--)
    {
        n = bl_count_[bits];
        while(n != 0)
        {
            m = heap_[--h];
            if(m > max_code)
                continue;
            if((unsigned) tree[m].dl != (unsigned) bits)
            {
                Trace((stderr,"code %d bits %d->%d\n", m, tree[m].dl, bits));
                opt_len_ += ((long)bits - (long)tree[m].dl) *(long)tree[m].fc;
                tree[m].dl = (std::uint16_t)bits;
            }
            n--;
        }
    }
}

/*  Construct one Huffman tree and assigns the code bit strings and lengths.
    Update the total bit length for the current block.
    IN assertion: the field freq is set for all tree elements.
    OUT assertions: the fields len and code are set to the optimal bit length
        and corresponding code. The length opt_len is updated; static_len is
        also updated if stree is not null. The field max_code is set.
*/
template<class _>
void
deflate_stream_base<_>::
build_tree(tree_desc *desc)
{
    detail::ct_data *tree         = desc->dyn_tree;
    detail::ct_data const* stree  = desc->stat_desc->static_tree;
    int elems                     = desc->stat_desc->elems;
    int n, m;          // iterate over heap elements
    int max_code = -1; // largest code with non zero frequency
    int node;          // new node being created

    /* Construct the initial heap, with least frequent element in
     * heap[kSmallest]. The sons of heap[n] are heap[2*n] and heap[2*n+1].
     * heap[0] is not used.
     */
    heap_len_ = 0;
    heap_max_ = HEAP_SIZE;

    for(n = 0; n < elems; n++)
    {
        if(tree[n].fc != 0)
        {
            heap_[++(heap_len_)] = max_code = n;
            depth_[n] = 0;
        }
        else
        {
            tree[n].dl = 0;
        }
    }

    /* The pkzip format requires that at least one distance code exists,
     * and that at least one bit should be sent even if there is only one
     * possible code. So to avoid special checks later on we force at least
     * two codes of non zero frequency.
     */
    while(heap_len_ < 2)
    {
        node = heap_[++(heap_len_)] = (max_code < 2 ? ++max_code : 0);
        tree[node].fc = 1;
        depth_[node] = 0;
        opt_len_--;
        if(stree)
            static_len_ -= stree[node].dl;
        // node is 0 or 1 so it does not have extra bits
    }
    desc->max_code = max_code;

    /* The elements heap[heap_len/2+1 .. heap_len] are leaves of the tree,
     * establish sub-heaps of increasing lengths:
     */
    for(n = heap_len_/2; n >= 1; n--)
        pqdownheap(tree, n);

    /* Construct the Huffman tree by repeatedly combining the least two
     * frequent nodes.
     */
    node = elems;              /* next internal node of the tree */
    do
    {
        pqremove(tree, n);  /* n = node of least frequency */
        m = heap_[kSmallest]; /* m = node of next least frequency */

        heap_[--(heap_max_)] = n; /* keep the nodes sorted by frequency */
        heap_[--(heap_max_)] = m;

        /* Create a new node father of n and m */
        tree[node].fc = tree[n].fc + tree[m].fc;
        depth_[node] = (std::uint8_t)((depth_[n] >= depth_[m] ?
                                depth_[n] : depth_[m]) + 1);
        tree[n].dl = tree[m].dl = (std::uint16_t)node;
        /* and insert the new node in the heap */
        heap_[kSmallest] = node++;
        pqdownheap(tree, kSmallest);

    }
    while(heap_len_ >= 2);

    heap_[--(heap_max_)] = heap_[kSmallest];

    /* At this point, the fields freq and dad are set. We can now
     * generate the bit lengths.
     */
    gen_bitlen((tree_desc *)desc);

    /* The field len is now set, we can generate the bit codes */
    detail::gen_codes(tree, max_code, bl_count_);
}

/*  Scan a literal or distance tree to determine the frequencies
    of the codes in the bit length tree.
*/
template<class _>
void
deflate_stream_base<_>::
scan_tree(
    detail::ct_data *tree,      // the tree to be scanned
    int max_code)               // and its largest code of non zero frequency
{
    int n;                      // iterates over all tree elements
    int prevlen = -1;           // last emitted length
    int curlen;                 // length of current code
    int nextlen = tree[0].dl;   // length of next code
    int count = 0;              // repeat count of the current code
    int max_count = 7;          // max repeat count
    int min_count = 4;          // min repeat count

    if(nextlen == 0)
    {
        max_count = 138;
        min_count = 3;
    }
    tree[max_code+1].dl = (std::uint16_t)0xffff; // guard

    for(n = 0; n <= max_code; n++)
    {
        curlen = nextlen; nextlen = tree[n+1].dl;
        if(++count < max_count && curlen == nextlen)
        {
            continue;
        }
        else if(count < min_count)
        {
            bl_tree_[curlen].fc += count;
        }
        else if(curlen != 0)
        {
            if(curlen != prevlen) bl_tree_[curlen].fc++;
                bl_tree_[REP_3_6].fc++;
        }
        else if(count <= 10)
        {
            bl_tree_[REPZ_3_10].fc++;
        }
        else
        {
            bl_tree_[REPZ_11_138].fc++;
        }
        count = 0;
        prevlen = curlen;
        if(nextlen == 0)
        {
            max_count = 138;
            min_count = 3;
        }
        else if(curlen == nextlen)
        {
            max_count = 6;
            min_count = 3;
        }
        else
        {
            max_count = 7;
            min_count = 4;
        }
    }
}

/*  Send a literal or distance tree in compressed form,
    using the codes in bl_tree.
*/
template<class _>
void
deflate_stream_base<_>::
send_tree(
    detail::ct_data *tree,      // the tree to be scanned
    int max_code)               // and its largest code of non zero frequency
{
    int n;                      // iterates over all tree elements
    int prevlen = -1;           // last emitted length
    int curlen;                 // length of current code
    int nextlen = tree[0].dl;   // length of next code
    int count = 0;              // repeat count of the current code
    int max_count = 7;          // max repeat count
    int min_count = 4;          // min repeat count

    // tree[max_code+1].dl = -1; // guard already set
    if(nextlen == 0)
    {
        max_count = 138;
        min_count = 3;
    }

    for(n = 0; n <= max_code; n++)
    {
        curlen = nextlen;
        nextlen = tree[n+1].dl;
        if(++count < max_count && curlen == nextlen)
        {
            continue;
        }
        else if(count < min_count)
        {
            do
            {
                send_code(curlen, bl_tree_);
            }
            while (--count != 0);
        }
        else if(curlen != 0)
        {
            if(curlen != prevlen)
            {
                send_code(curlen, bl_tree_);
                count--;
            }
            Assert(count >= 3 && count <= 6, " 3_6?");
            send_code(REP_3_6, bl_tree_);
            send_bits(count-3, 2);
        }
        else if(count <= 10)
        {
            send_code(REPZ_3_10, bl_tree_);
            send_bits(count-3, 3);
        }
        else
        {
            send_code(REPZ_11_138, bl_tree_);
            send_bits(count-11, 7);
        }
        count = 0;
        prevlen = curlen;
        if(nextlen == 0)
        {
            max_count = 138;
            min_count = 3;
        }
        else if(curlen == nextlen)
        {
            max_count = 6;
            min_count = 3;
        }
        else
        {
            max_count = 7;
            min_count = 4;
        }
    }
}

/*  Construct the Huffman tree for the bit lengths and return
    the index in bl_order of the last bit length code to send.
*/
template<class _>
int
deflate_stream_base<_>::
build_bl_tree()
{
    int max_blindex;  // index of last bit length code of non zero freq

    // Determine the bit length frequencies for literal and distance trees
    scan_tree((detail::ct_data *)dyn_ltree_, l_desc_.max_code);
    scan_tree((detail::ct_data *)dyn_dtree_, d_desc_.max_code);

    // Build the bit length tree:
    build_tree((tree_desc *)(&(bl_desc_)));
    /* opt_len now includes the length of the tree representations, except
     * the lengths of the bit lengths codes and the 5+5+4 bits for the counts.
     */

    /* Determine the number of bit length codes to send. The pkzip format
     * requires that at least 4 bit length codes be sent. (appnote.txt says
     * 3 but the actual value used is 4.)
     */
    for(max_blindex = limits::blCodes-1; max_blindex >= 3; max_blindex--)
    {
        if(bl_tree_[lut_.bl_order[max_blindex]].dl != 0)
            break;
    }
    // Update opt_len to include the bit length tree and counts
    opt_len_ += 3*(max_blindex+1) + 5+5+4;
    Tracev((stderr, "\ndyn trees: dyn %ld, stat %ld",
            opt_len_, static_len_));
    return max_blindex;
}

/*  Send the header for a block using dynamic Huffman trees: the counts,
    the lengths of the bit length codes, the literal tree and the distance
    tree.
    IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.
*/
template<class _>
void
deflate_stream_base<_>::
send_all_trees(
    int lcodes,
    int dcodes,
    int blcodes)    // number of codes for each tree
{
    int rank;       // index in bl_order

    Assert (lcodes >= 257 && dcodes >= 1 && blcodes >= 4, "not enough codes");
    Assert (lcodes <= limits::lCodes && dcodes <= limits::dCodes && blcodes <= limits::blCodes,
            "too many codes");
    Tracev((stderr, "\nbl counts: "));
    send_bits(lcodes-257, 5); // not +255 as stated in appnote.txt
    send_bits(dcodes-1,   5);
    send_bits(blcodes-4,  4); // not -3 as stated in appnote.txt
    for(rank = 0; rank < blcodes; rank++)
    {
        Tracev((stderr, "\nbl code %2d ", bl_order[rank]));
        send_bits(bl_tree_[lut_.bl_order[rank]].dl, 3);
    }
    Tracev((stderr, "\nbl tree: sent %ld", bits_sent_));

    send_tree((detail::ct_data *)dyn_ltree_, lcodes-1); // literal tree
    Tracev((stderr, "\nlit tree: sent %ld", bits_sent_));

    send_tree((detail::ct_data *)dyn_dtree_, dcodes-1); // distance tree
    Tracev((stderr, "\ndist tree: sent %ld", bits_sent_));
}

/*  Send the block data compressed using the given Huffman trees
*/
template<class _>
void
deflate_stream_base<_>::
compress_block(
    detail::ct_data const* ltree, // literal tree
    detail::ct_data const* dtree) // distance tree
{
    unsigned dist;      /* distance of matched string */
    int lc;             /* match length or unmatched char (if dist == 0) */
    unsigned lx = 0;    /* running index in l_buf */
    unsigned code;      /* the code to send */
    int extra;          /* number of extra bits to send */

    if(last_lit_ != 0)
    {
        do
        {
            dist = d_buf_[lx];
            lc = l_buf_[lx++];
            if(dist == 0)
            {
                send_code(lc, ltree); /* send a literal byte */
                Tracecv(isgraph(lc), (stderr," '%c' ", lc));
            }
            else
            {
                /* Here, lc is the match length - limits::minMatch */
                code = lut_.length_code[lc];
                send_code(code+limits::literals+1, ltree); /* send the length code */
                extra = lut_.extra_lbits[code];
                if(extra != 0)
                {
                    lc -= lut_.base_length[code];
                    send_bits(lc, extra);       /* send the extra length bits */
                }
                dist--; /* dist is now the match distance - 1 */
                code = d_code(dist);
                Assert (code < limits::dCodes, "bad d_code");

                send_code(code, dtree);       /* send the distance code */
                extra = lut_.extra_dbits[code];
                if(extra != 0)
                {
                    dist -= lut_.base_dist[code];
                    send_bits(dist, extra);   /* send the extra distance bits */
                }
            } /* literal or match pair ? */

            /* Check that the overlay between pending_buf and d_buf+l_buf is ok: */
            Assert((uInt)(pending_) < lit_bufsize_ + 2*lx,
               "pendingBuf overflow");
        }
        while(lx < last_lit_);
    }

    send_code(END_BLOCK, ltree);
}

/*  Check if the data type is TEXT or BINARY, using the following algorithm:
    - TEXT if the two conditions below are satisfied:
        a) There are no non-portable control characters belonging to the
            "black list" (0..6, 14..25, 28..31).
        b) There is at least one printable character belonging to the
            "white list" (9 {TAB}, 10 {LF}, 13 {CR}, 32..255).
    - BINARY otherwise.
    - The following partially-portable control characters form a
        "gray list" that is ignored in this detection algorithm:
        (7 {BEL}, 8 {BS}, 11 {VT}, 12 {FF}, 26 {SUB}, 27 {ESC}).
    IN assertion: the fields fc of dyn_ltree are set.
*/
template<class _>
int
deflate_stream_base<_>::
detect_data_type()
{
    /* black_mask is the bit mask of black-listed bytes
     * set bits 0..6, 14..25, and 28..31
     * 0xf3ffc07f = binary 11110011111111111100000001111111
     */
    unsigned long black_mask = 0xf3ffc07fUL;
    int n;

    // Check for non-textual ("black-listed") bytes.
    for(n = 0; n <= 31; n++, black_mask >>= 1)
        if((black_mask & 1) && (dyn_ltree_[n].fc != 0))
            return Z_BINARY;

    // Check for textual ("white-listed") bytes. */
    if(dyn_ltree_[9].fc != 0 || dyn_ltree_[10].fc != 0
            || dyn_ltree_[13].fc != 0)
        return Z_TEXT;
    for(n = 32; n < limits::literals; n++)
        if(dyn_ltree_[n].fc != 0)
            return Z_TEXT;

    /* There are no "black-listed" or "white-listed" bytes:
     * this stream either is empty or has tolerated ("gray-listed") bytes only.
     */
    return Z_BINARY;
}

/*  Flush the bit buffer and align the output on a byte boundary
*/
template<class _>
void
deflate_stream_base<_>::
bi_windup()
{
    if(bi_valid_ > 8)
        put_short(bi_buf_);
    else if(bi_valid_ > 0)
        put_byte((Byte)bi_buf_);
    bi_buf_ = 0;
    bi_valid_ = 0;
}

/*  Flush the bit buffer, keeping at most 7 bits in it.
*/
template<class _>
void
deflate_stream_base<_>::
bi_flush()
{
    if(bi_valid_ == 16)
    {
        put_short(bi_buf_);
        bi_buf_ = 0;
        bi_valid_ = 0;
    }
    else if(bi_valid_ >= 8)
    {
        put_byte((Byte)bi_buf_);
        bi_buf_ >>= 8;
        bi_valid_ -= 8;
    }
}

/*  Copy a stored block, storing first the length and its
    one's complement if requested.
*/
template<class _>
void
deflate_stream_base<_>::
copy_block(
    char    *buf,       // the input data
    unsigned len,       // its length
    int      header)    // true if block header must be written
{
    bi_windup();        // align on byte boundary

    if(header)
    {
        put_short((std::uint16_t)len);
        put_short((std::uint16_t)~len);
    }
    // VFALCO Use memcpy?
    while (len--)
        put_byte(*buf++);
}

//------------------------------------------------------------------------------

} // detail
} // zlib
} // beast

#endif
