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
#include <boost/optional.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <type_traits>

namespace beast {
namespace zlib {
namespace detail {

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
    boost::optional<Flush>
        last_flush_;                // value of flush param for previous deflate call

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
    Strategy strategy_;             // favor or force Huffman coding

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

    /*  In order to simplify the code, particularly on 16 bit machines, match
        distances are limited to MAX_DIST instead of WSIZE.
    */
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

    template<class = void> void init_block          ();
    template<class = void> void pqdownheap          (detail::ct_data const* tree, int k);
    template<class = void> void pqremove            (detail::ct_data const* tree, int& top);
    template<class = void> void gen_bitlen          (tree_desc *desc);
    template<class = void> void build_tree          (tree_desc *desc);
    template<class = void> void scan_tree           (detail::ct_data *tree, int max_code);
    template<class = void> void send_tree           (detail::ct_data *tree, int max_code);
    template<class = void> int  build_bl_tree       ();
    template<class = void> void send_all_trees      (int lcodes, int dcodes, int blcodes);
    template<class = void> void compress_block      (detail::ct_data const* ltree, detail::ct_data const* dtree);
    template<class = void> int  detect_data_type    ();
    template<class = void> void bi_windup           ();
    template<class = void> void bi_flush            ();
    template<class = void> void copy_block          (char *buf, unsigned len, int header);

    template<class = void> void tr_init             ();
    template<class = void> void tr_align            ();
    template<class = void> void tr_flush_bits       ();
    template<class = void> void tr_stored_block     (char *bu, std::uint32_t stored_len, int last);
    template<class = void> void tr_tally_dist       (std::uint16_t dist, std::uint8_t len, bool& flush);
    template<class = void> void tr_tally_lit        (std::uint8_t c, bool& flush);

    template<class = void> void tr_flush_block      (z_params& zs, char *buf, std::uint32_t stored_len, int last);
    template<class = void> void fill_window         (z_params& zs);
    template<class = void> void flush_pending       (z_params& zs);
    template<class = void> void flush_block         (z_params& zs, bool last);
    template<class = void> int  read_buf            (z_params& zs, Byte *buf, unsigned size);
    template<class = void> uInt longest_match       (IPos cur_match);

    template<class = void> block_state f_stored     (z_params& zs, Flush flush);
    template<class = void> block_state f_fast       (z_params& zs, Flush flush);
    template<class = void> block_state f_slow       (z_params& zs, Flush flush);
    template<class = void> block_state f_rle        (z_params& zs, Flush flush);
    template<class = void> block_state f_huff       (z_params& zs, Flush flush);

    block_state
    deflate_stored(z_params& zs, Flush flush)
    {
        return f_stored(zs, flush);
    }

    block_state
    deflate_fast(z_params& zs, Flush flush)
    {
        return f_fast(zs, flush);
    }

    block_state
    deflate_slow(z_params& zs, Flush flush)
    {
        return f_slow(zs, flush);
    }

    block_state
    deflate_rle(z_params& zs, Flush flush)
    {
        return f_rle(zs, flush);
    }

    block_state
    deflate_huff(z_params& zs, Flush flush)
    {
        return f_huff(zs, flush);
    }
};

//--------------------------------------------------------------------------

// Initialize a new block.
//
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
inline
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
int
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
int
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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
template<class>
void
deflate_stream_base::
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

/* Initialize the tree data structures for a new zlib stream.
*/
template<class>
void
deflate_stream_base::
tr_init()
{
    l_desc_.dyn_tree = dyn_ltree_;
    l_desc_.stat_desc = &lut_.l_desc;

    d_desc_.dyn_tree = dyn_dtree_;
    d_desc_.stat_desc = &lut_.d_desc;

    bl_desc_.dyn_tree = bl_tree_;
    bl_desc_.stat_desc = &lut_.bl_desc;

    bi_buf_ = 0;
    bi_valid_ = 0;

    /* Initialize the first block of the first file: */
    init_block();
}

/*  Send one empty static block to give enough lookahead for inflate.
    This takes 10 bits, of which 7 may remain in the bit buffer.
*/
template<class>
void
deflate_stream_base::
tr_align()
{
    send_bits(STATIC_TREES<<1, 3);
    send_code(END_BLOCK, lut_.ltree);
    bi_flush();
}

/* Flush the bits in the bit buffer to pending output (leaves at most 7 bits)
*/
template<class>
void
deflate_stream_base::
tr_flush_bits()
{
    bi_flush();
}

/* Send a stored block
*/
template<class>
void
deflate_stream_base::
tr_stored_block(
    char *buf,                  // input block
    std::uint32_t stored_len,   // length of input block
    int last)                   // one if this is the last block for a file
{
    send_bits((STORED_BLOCK<<1)+last, 3);       // send block type
    copy_block(buf, (unsigned)stored_len, 1);   // with header
}

template<class>
inline
void
deflate_stream_base::
tr_tally_dist(std::uint16_t dist, std::uint8_t len, bool& flush)
{
    d_buf_[last_lit_] = dist;
    l_buf_[last_lit_++] = len;
    dist--;
    dyn_ltree_[lut_.length_code[len]+limits::literals+1].fc++;
    dyn_dtree_[d_code(dist)].fc++;
    flush = (last_lit_ == lit_bufsize_-1);
}

template<class>
inline
void
deflate_stream_base::
tr_tally_lit(std::uint8_t c, bool& flush)
{
    d_buf_[last_lit_] = 0;
    l_buf_[last_lit_++] = c;
    dyn_ltree_[c].fc++;
    flush = (last_lit_ == lit_bufsize_-1);
}

//------------------------------------------------------------------------------

/*  Determine the best encoding for the current block: dynamic trees,
    static trees or store, and output the encoded block to the zip file.
*/
template<class>
void
deflate_stream_base::
tr_flush_block(
    z_params& zs,
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
        if(zs.data_type == Z_UNKNOWN)
            zs.data_type = detect_data_type();

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
    else if(strategy_ == Strategy::fixed || static_lenb == opt_lenb)
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

template<class>
void
deflate_stream_base::
fill_window(z_params& zs)
{
    unsigned n, m;
    unsigned more;    // Amount of free space at the end of the window.
    std::uint16_t *p;
    uInt wsize = w_size_;

    do
    {
        more = (unsigned)(window_size_ -
            (std::uint32_t)lookahead_ -(std::uint32_t)strstart_);

        // Deal with !@#$% 64K limit:
        if(sizeof(int) <= 2)
        {
            if(more == 0 && strstart_ == 0 && lookahead_ == 0)
            {
                more = wsize;
            }
            else if(more == (unsigned)(-1))
            {
                /* Very unlikely, but possible on 16 bit machine if
                 * strstart == 0 && lookahead == 1 (input done a byte at time)
                 */
                more--;
            }
        }

        /*  If the window is almost full and there is insufficient lookahead,
            move the upper half to the lower one to make room in the upper half.
        */
        if(strstart_ >= wsize+max_dist())
        {
            std::memcpy(window_, window_+wsize, (unsigned)wsize);
            match_start_ -= wsize;
            strstart_    -= wsize; // we now have strstart >= max_dist
            block_start_ -= (long) wsize;

            /* Slide the hash table (could be avoided with 32 bit values
               at the expense of memory usage). We slide even when level == 0
               to keep the hash table consistent if we switch back to level > 0
               later. (Using level 0 permanently is not an optimal usage of
               zlib, so we don't care about this pathological case.)
            */
            n = hash_size_;
            p = &head_[n];
            do
            {
                m = *--p;
                *p = (std::uint16_t)(m >= wsize ? m-wsize : 0);
            }
            while(--n);

            n = wsize;
            p = &prev_[n];
            do
            {
                m = *--p;
                *p = (std::uint16_t)(m >= wsize ? m-wsize : 0);
                /*  If n is not on any hash chain, prev[n] is garbage but
                    its value will never be used.
                */
            }
            while(--n);
            more += wsize;
        }
        if(zs.avail_in == 0)
            break;

        /*  If there was no sliding:
               strstart <= WSIZE+max_dist-1 && lookahead <= kMinLookahead - 1 &&
               more == window_size - lookahead - strstart
            => more >= window_size - (kMinLookahead-1 + WSIZE + max_dist-1)
            => more >= window_size - 2*WSIZE + 2
            In the BIG_MEM or MMAP case (not yet supported),
              window_size == input_size + kMinLookahead  &&
              strstart + lookahead_ <= input_size => more >= kMinLookahead.
            Otherwise, window_size == 2*WSIZE so more >= 2.
            If there was sliding, more >= WSIZE. So in all cases, more >= 2.
        */
        n = read_buf(zs, window_ + strstart_ + lookahead_, more);
        lookahead_ += n;

        // Initialize the hash value now that we have some input:
        if(lookahead_ + insert_ >= limits::minMatch)
        {
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
        /*  If the whole input has less than limits::minMatch bytes, ins_h is garbage,
            but this is not important since only literal bytes will be emitted.
        */
    }
    while(lookahead_ < kMinLookahead && zs.avail_in != 0);

    /*  If the kWinInit bytes after the end of the current data have never been
        written, then zero those bytes in order to avoid memory check reports of
        the use of uninitialized (or uninitialised as Julian writes) bytes by
        the longest match routines.  Update the high water mark for the next
        time through here.  kWinInit is set to limits::maxMatch since the longest match
        routines allow scanning to strstart + limits::maxMatch, ignoring lookahead.
    */
    if(high_water_ < window_size_)
    {
        std::uint32_t curr = strstart_ + (std::uint32_t)(lookahead_);
        std::uint32_t init;

        if(high_water_ < curr)
        {
            /*  Previous high water mark below current data -- zero kWinInit
                bytes or up to end of window, whichever is less.
            */
            init = window_size_ - curr;
            if(init > kWinInit)
                init = kWinInit;
            std::memset(window_ + curr, 0, (unsigned)init);
            high_water_ = curr + init;
        }
        else if(high_water_ < (std::uint32_t)curr + kWinInit)
        {
            /*  High water mark at or above current data, but below current data
                plus kWinInit -- zero out to current data plus kWinInit, or up
                to end of window, whichever is less.
            */
            init = (std::uint32_t)curr + kWinInit - high_water_;
            if(init > window_size_ - high_water_)
                init = window_size_ - high_water_;
            std::memset(window_ + high_water_, 0, (unsigned)init);
            high_water_ += init;
        }
    }
}

/*  Flush as much pending output as possible. All write() output goes
    through this function so some applications may wish to modify it
    to avoid allocating a large strm->next_out buffer and copying into it.
    (See also read_buf()).
*/
template<class>
void
deflate_stream_base::
flush_pending(z_params& zs)
{
    tr_flush_bits();
    unsigned len = pending_;
    if(len > zs.avail_out)
        len = zs.avail_out;
    if(len == 0)
        return;

    std::memcpy(zs.next_out, pending_out_, len);
    zs.next_out =
        static_cast<std::uint8_t*>(zs.next_out) + len;
    pending_out_  += len;
    zs.total_out += len;
    zs.avail_out  -= len;
    pending_ -= len;
    if(pending_ == 0)
        pending_out_ = pending_buf_;
}

/*  Flush the current block, with given end-of-file flag.
    IN assertion: strstart is set to the end of the current match.
*/
template<class>
inline
void
deflate_stream_base::
flush_block(z_params& zs, bool last)
{
    tr_flush_block(zs,
        (block_start_ >= 0L ?
            (char *)&window_[(unsigned)block_start_] :
            (char *)0),
        (std::uint32_t)((long)strstart_ - block_start_),
        last);
   block_start_ = strstart_;
   flush_pending(zs);
}

/*  Read a new buffer from the current input stream, update the adler32
    and total number of bytes read.  All write() input goes through
    this function so some applications may wish to modify it to avoid
    allocating a large strm->next_in buffer and copying from it.
    (See also flush_pending()).
*/
template<class>
int
deflate_stream_base::
read_buf(z_params& zs, Byte *buf, unsigned size)
{
    unsigned len = zs.avail_in;

    if(len > size)
        len = size;
    if(len == 0)
        return 0;

    zs.avail_in  -= len;

    std::memcpy(buf, zs.next_in, len);
    zs.next_in = static_cast<
        std::uint8_t const*>(zs.next_in) + len;
    zs.total_in += len;
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
template<class>
uInt
deflate_stream_base::
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
        if(     match[best_len]   != scan_end  ||
                match[best_len-1] != scan_end1 ||
                *match            != *scan     ||
                *++match          != scan[1])
            continue;

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
        do
        {
        }
        while(  *++scan == *++match && *++scan == *++match &&
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
    }
    while((cur_match = prev[cur_match & wmask]) > limit
        && --chain_length != 0);

    if((uInt)best_len <= lookahead_)
        return (uInt)best_len;
    return lookahead_;
}

//------------------------------------------------------------------------------

/*  Copy without compression as much as possible from the input stream, return
    the current block state.
    This function does not insert new strings in the dictionary since
    uncompressible data is probably not useful. This function is used
    only for the level=0 compression option.
    NOTE: this function should be optimized to avoid extra copying from
    window to pending_buf.
*/
template<class>
auto
deflate_stream_base::
f_stored(z_params& zs, Flush flush) ->
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

/*  Compress as much as possible from the input stream, return the current
    block state.
    This function does not perform lazy evaluation of matches and inserts
    new strings in the dictionary only for unmatched strings or for short
    matches. It is used only for the fast compression options.
*/
template<class>
auto
deflate_stream_base::
f_fast(z_params& zs, Flush flush) ->
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

/*  Same as above, but achieves better compression. We use a lazy
    evaluation for matches: a match is finally adopted only if there is
    no better match at the next window position.
*/
template<class>
auto
deflate_stream_base::
f_slow(z_params& zs, Flush flush) ->
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

            if(match_length_ <= 5 && (strategy_ == Strategy::filtered
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

/*  For Strategy::rle, simply look for runs of bytes, generate matches only of distance
    one.  Do not maintain a hash table.  (It will be regenerated if this run of
    deflate switches away from Strategy::rle.)
*/
template<class>
auto
deflate_stream_base::
f_rle(z_params& zs, Flush flush) ->
    block_state
{
    bool bflush;            // set if current block must be flushed
    uInt prev;              // byte at distance one to match
    Byte *scan, *strend;    // scan goes up to strend for length of run

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
 * For Strategy::huffman, do not look for matches.  Do not maintain a hash table.
 * (It will be regenerated if this run of deflate switches away from Huffman.)
 */
template<class>
auto
deflate_stream_base::
f_huff(z_params& zs, Flush flush) ->
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

} // detail
} // zlib
} // beast

#endif
