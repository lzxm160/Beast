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

#ifndef BEAST_ZLIB_IMPL_BASIC_INFLATE_STREAM_IPP
#define BEAST_ZLIB_IMPL_BASIC_INFLATE_STREAM_IPP

#include <beast/zlib/error.hpp>
#include <array>
#include <cassert>
#include <cstring>

namespace beast {
namespace zlib {

/* Macros for inflate(): */

template<class Allocator>
basic_inflate_stream<Allocator>::
basic_inflate_stream()
{
    w_.reset(15);
}

template<class Allocator>
basic_inflate_stream<Allocator>::
~basic_inflate_stream()
{
}

template<class Allocator>
void
basic_inflate_stream<Allocator>::
reset(int windowBits)
{
    if(windowBits < 8 || windowBits > 15)
        throw std::domain_error("windowBits out of range");
    w_.reset(windowBits);

    bi_.flush();
    mode_ = HEAD;
    last_ = 0;
    dmax_ = 32768U;
    hold_ = 0;
    bits_ = 0;
    lencode_ = codes_;
    distcode_ = codes_;
    next_ = codes_;
    back_ = -1;
}

template<class Allocator>
void
basic_inflate_stream<Allocator>::
fixedTables()
{
    auto const fc = detail::get_fixed_tables();
    lencode_ = fc.lencode;
    lenbits_ = fc.lenbits;
    distcode_ = fc.distcode;
    distbits_ = fc.distbits;
}

//------------------------------------------------------------------------------

template<class Allocator>
void
basic_inflate_stream<Allocator>::
write(z_params& zs, Flush flush, error_code& ec)
{
    detail::ranges r;
    r.in.first = reinterpret_cast<
        std::uint8_t const*>(zs.next_in);
    r.in.last = r.in.first + zs.avail_in;
    r.in.next = r.in.first;
    r.out.first = reinterpret_cast<
        std::uint8_t*>(zs.next_out);
    r.out.last = r.out.first + zs.avail_out;
    r.out.next = r.out.first;

    auto const done =
        [&]
        {
            /*
               Return from inflate(), updating the total counts and the check value.
               If there was no progress during the inflate() call, return a buffer
               error.  Call updatewindow() to create and/or update the window state.
               Note: a memory error from inflate() is non-recoverable.
             */


            // VFALCO TODO Don't allocate update the window unless necessary
            if(/*wsize_ ||*/ (r.out.used() && mode_ < BAD &&
                    (mode_ < CHECK || flush != Flush::finish)))
                w_.write(r.out.first, r.out.used());

            zs.next_in = r.in.next;
            zs.avail_in = r.in.avail();
            zs.next_out = r.out.next;
            zs.avail_out = r.out.avail();
            zs.total_in += r.in.used();
            zs.total_out += r.out.used();
            zs.data_type = bi_.size() + (last_ ? 64 : 0) +
                (mode_ == TYPE ? 128 : 0) +
                (mode_ == LEN_ || mode_ == COPY_ ? 256 : 0);

            if(((! r.in.used() && ! r.out.used()) ||
                    flush == Flush::finish) && ! ec)
                ec = error::no_progress;
        };
    auto const err =
        [&](error e)
        {
            ec = e;
            mode_ = BAD;
        };

    if(mode_ == TYPE)
        mode_ = TYPEDO;

    for(;;)
    {
        switch(mode_)
        {
        case HEAD:
            mode_ = TYPEDO;
            break;

        case TYPE:
            if(flush == Flush::block || flush == Flush::trees)
                return done();
            // fall through

        case TYPEDO:
        {
            if(last_)
            {
                bi_.flush_byte();
                mode_ = CHECK;
                break;
            }
            if(! bi_.fill(3, r.in.next, r.in.last))
                return done();
            std::uint8_t v;
            bi_.read(v, 1, r.in.next, r.in.last);
            last_ = v != 0;
            bi_.read(v, 2, r.in.next, r.in.last);
            switch(v)
            {
            case 0:
                // uncompressed block
                mode_ = STORED;
                break;
            case 1:
                // fixed Huffman table
                fixedTables();
                mode_ = LEN_;             /* decode codes */
                if(flush == Flush::trees)
                    return done();
                break;
            case 2:
                // dynamic Huffman table
                mode_ = TABLE;
                break;

            default:
                return err(error::invalid_block_type);
            }
            break;
        }

        case STORED:
        {
            bi_.flush_byte();
            std::uint32_t v;
            if(! bi_.peek(v, 32, r.in.next, r.in.last))
                return done();
            length_ = v & 0xffff;
            if(length_ != ((v >> 16) ^ 0xffff))
                return err(error::invalid_stored_length);
            // flush instead of read, otherwise
            // undefined right shift behavior.
            bi_.flush();
            mode_ = COPY_;
            if(flush == Flush::trees)
                return done();
            // fall through
        }

        case COPY_:
            mode_ = COPY;
            // fall through

        case COPY:
        {
            auto copy = length_;
            if(copy == 0)
            {
                mode_ = TYPE;
                break;
            }
            copy = detail::clamp(copy, r.in.avail());
            copy = detail::clamp(copy, r.out.avail());
            if(copy == 0)
                return done();
            std::memcpy(r.out.next, r.in.next, copy);
            r.in.next += copy;
            r.out.next += copy;
            length_ -= copy;
            break;
        }

        case TABLE:
            if(! bi_.fill(5 + 5 + 4, r.in.next, r.in.last))
                return done();
            bi_.read(nlen_, 5, r.in.next, r.in.last);
            nlen_ += 257;
            bi_.read(ndist_, 5, r.in.next, r.in.last);
            ndist_ += 1;
            bi_.read(ncode_, 4, r.in.next, r.in.last);
            ncode_ += 4;
            if(nlen_ > 286 || ndist_ > 30)
                return err(error::too_many_symbols);
            have_ = 0;
            mode_ = LENLENS;
            // fall through

        case LENLENS:
        {
            static std::array<std::uint8_t, 19> constexpr order = {{
                16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}};
            while(have_ < ncode_)
            {
                if(! bi_.read(lens_[order[have_]], 3, r.in.next, r.in.last))
                    return done();
                ++have_;
            }
            while(have_ < order.size())
                lens_[order[have_++]] = 0;

            next_ = &codes_[0];
            lencode_ = next_;
            lenbits_ = 7;
            inflate_table(detail::CODES, &lens_[0],
                order.size(), &next_, &lenbits_, work_, ec);
            if(ec)
            {
                mode_ = BAD;
                break;
            }
            have_ = 0;
            mode_ = CODELENS;
            // fall through
        }

        case CODELENS:
        {
            while(have_ < nlen_ + ndist_)
            {
                std::uint16_t v;
                if(! bi_.peek(v, lenbits_, r.in.next, r.in.last))
                    return done();
                auto cp = &lencode_[v];
                if(cp->val < 16)
                {
                    bi_.drop(cp->bits);
                    lens_[have_++] = cp->val;
                }
                else
                {
                    std::uint16_t len;
                    std::uint16_t copy;
                    if(cp->val == 16)
                    {
                        if(! bi_.fill(cp->bits + 2, r.in.next, r.in.last))
                            return done();
                        bi_.drop(cp->bits);
                        if(have_ == 0)
                            return err(error::invalid_bit_length_repeat);
                        bi_.read(copy, 2, r.in.next, r.in.last);
                        len = lens_[have_ - 1];
                        copy += 3;

                    }
                    else if(cp->val == 17)
                    {
                        if(! bi_.fill(cp->bits + 3, r.in.next, r.in.last))
                            return done();
                        bi_.drop(cp->bits);
                        bi_.read(copy, 3, r.in.next, r.in.last);
                        len = 0;
                        copy += 3;
                    }
                    else
                    {
                        if(! bi_.fill(cp->bits + 7, r.in.next, r.in.last))
                            return done();
                        bi_.drop(cp->bits);
                        bi_.read(copy, 7, r.in.next, r.in.last);
                        len = 0;
                        copy += 11;
                    }
                    if(have_ + copy > nlen_ + ndist_)
                        return err(error::invalid_bit_length_repeat);
#if 0
                    while(copy--)
                        lens_[have_++] = len;
#else
                    std::fill(&lens_[have_], &lens_[have_ + copy], len);
                    have_ += copy;
                    copy = 0;
#endif
                }
            }
            // handle error breaks in while
            if(mode_ == BAD)
                break;
            // check for end-of-block code (better have one)
            if(lens_[256] == 0)
                return err(error::missing_eob);
            /* build code tables -- note: do not change the lenbits or distbits
               values here (9 and 6) without reading the comments in inftrees.hpp
               concerning the ENOUGH constants, which depend on those values */
            next_ = &codes_[0];
            lencode_ = next_;
            lenbits_ = 9;
            inflate_table(detail::LENS, &lens_[0],
                nlen_, &next_, &lenbits_, work_, ec);
            if(ec)
            {
                mode_ = BAD;
                return;
            }
            distcode_ = next_;
            distbits_ = 6;
            inflate_table(detail::DISTS, lens_ + nlen_,
                ndist_, &next_, &distbits_, work_, ec);
            if(ec)
            {
                mode_ = BAD;
                return;
            }
            mode_ = LEN_;
            if(flush == Flush::trees)
                return done();
            // fall through
        }

        case LEN_:
            mode_ = LEN;
            // fall through

        case LEN:
        {
            if(r.in.avail() >= 6 && r.out.avail() >= 258)
            {
                inflate_fast(r, ec);
                if(ec)
                {
                    mode_ = BAD;
                    return;
                }
                if(mode_ == TYPE)
                    back_ = -1;
                break;
            }
            std::uint16_t v;
            back_ = 0;
            if(! bi_.peek(v, lenbits_, r.in.next, r.in.last))
                return done();
            auto cp = &lencode_[v];
            if(cp->op && (cp->op & 0xf0) == 0)
            {
                auto prev = cp;
                if(! bi_.peek(v, prev->bits + prev->op, r.in.next, r.in.last))
                    return done();
                cp = &lencode_[prev->val + (v >> prev->bits)];
                bi_.drop(prev->bits + cp->bits);
                back_ += prev->bits + cp->bits;
            }
            else
            {
                bi_.drop(cp->bits);
                back_ += cp->bits;
            }
            length_ = cp->val;
            if(cp->op == 0)
            {
                mode_ = LIT;
                break;
            }
            if(cp->op & 32)
            {
                back_ = -1;
                mode_ = TYPE;
                break;
            }
            if(cp->op & 64)
                return err(error::invalid_literal_length);
            extra_ = cp->op & 15;
            mode_ = LENEXT;
            // fall through
        }

        case LENEXT:
            if(extra_)
            {
                std::uint16_t v;
                if(! bi_.read(v, extra_, r.in.next, r.in.last))
                    return done();
                length_ += v;
                back_ += extra_;
            }
            was_ = length_;
            mode_ = DIST;
            // fall through

        case DIST:
        {
            std::uint16_t v;
            if(! bi_.peek(v, distbits_, r.in.next, r.in.last))
                return done();
            auto cp = &distcode_[v];
            if((cp->op & 0xf0) == 0)
            {
                auto prev = cp;
                if(! bi_.peek(v, prev->bits + prev->op, r.in.next, r.in.last))
                    return done();
                cp = &distcode_[prev->val + (v >> prev->bits)];
                bi_.drop(prev->bits + cp->bits);
                back_ += prev->bits + cp->bits;
            }
            else
            {
                bi_.drop(cp->bits);
                back_ += cp->bits;
            }
            if(cp->op & 64)
                return err(error::invalid_distance_code);
            offset_ = cp->val;
            extra_ = cp->op & 15;
            mode_ = DISTEXT;
            // fall through
        }

        case DISTEXT:
            if(extra_)
            {
                std::uint16_t v;
                if(! bi_.read(v, extra_, r.in.next, r.in.last))
                    return done();
                offset_ += v;
                back_ += extra_;
            }
#ifdef INFLATE_STRICT
            if(offset_ > dmax_)
                return err(error::invalid_distance);
#endif
            mode_ = MATCH;
            // fall through

        case MATCH:
        {
            if(! r.out.avail())
                return done();
            if(offset_ > r.out.used())
            {
                // copy from window
                auto offset = static_cast<std::uint16_t>(
                    offset_ - r.out.used());
                if(offset > w_.size())
                    return err(error::invalid_distance);
                auto const n = detail::clamp(length_, offset);
                w_.read(r.out.next, offset, n);
                r.out.next += n;
                length_ -= n;
            }
            else
            {
                if(offset_ > 1)
                {
                    // copy from output
                    auto n = detail::clamp(length_, offset_);
                    std::memcpy(
                        r.out.next, r.out.next - offset_, n);
                    r.out.next += n;
                    length_ -= n;
                }
                if(length_ > 0)
                {
                    // fill from output
                    auto n = detail::clamp(length_, r.out.avail());
                    std::memset(r.out.next, r.out.next[-1], n);
                    r.out.next += n;
                    length_ -= n;
                }
            }
            if(length_ == 0)
                mode_ = LEN;
            break;
        }

        case LIT:
        {
            if(! r.out.avail())
                return done();
            auto const v = static_cast<std::uint8_t>(length_);
            *r.out.next++ = v;
            mode_ = LEN;
            break;
        }

        case CHECK:
            mode_ = DONE;
            // fall through

        case DONE:
            ec = error::end_of_stream;
            return done();

        case BAD:
            return done();

        case SYNC:
        default:
            throw std::logic_error("stream error");
        }
    }
}

/*
   Decode literal, length, and distance codes and write out the resulting
   literal and match bytes until either not enough input or output is
   available, an end-of-block is encountered, or a data error is encountered.
   When large enough input and output buffers are supplied to inflate(), for
   example, a 16K input buffer and a 64K output buffer, done than 95% of the
   inflate execution time is spent in this routine.

   Entry assumptions:

        state->mode_ == LEN
        zs.avail_in >= 6
        zs.avail_out >= 258
        start >= zs.avail_out
        state->bits_ < 8

   On return, state->mode_ is one of:

        LEN -- ran out of enough output space or enough available input
        TYPE -- reached end of block code, inflate() to interpret next block
        BAD -- error in block data

   Notes:

    - The maximum input bits used by a length/distance pair is 15 bits for the
      length code, 5 bits for the length extra, 15 bits for the distance code,
      and 13 bits for the distance extra.  This totals 48 bits, or six bytes.
      Therefore if zs.avail_in >= 6, then there is enough input to avoid
      checking for available input while decoding.

    - The maximum bytes that a single length/distance pair can output is 258
      bytes, which is the maximum length that can be coded.  inflate_fast()
      requires zs.avail_out >= 258 for each loop to avoid checking for
      output space.
 */
template<class Allocator>
void
basic_inflate_stream<Allocator>::
inflate_fast(detail::ranges& r, error_code& ec)
{
    unsigned char const* last;  // have enough input while in < last
    unsigned char *end;         // while out < end, enough space available
    unsigned op;                // code bits, operation, extra bits, or window position, window bytes to copy
    unsigned len;               // match length, unused bytes
    unsigned dist;              // match distance
    unsigned const lmask =
        (1U << lenbits_) - 1;   // mask for first level of length codes
    unsigned const dmask =
        (1U << distbits_) - 1;  // mask for first level of distance codes

    last = r.in.next + (r.in.avail() - 5);
    end = r.out.next + (r.out.avail() - 257);

    /* decode literals and length/distances until end-of-block or not enough
       input data or output space */
    do
    {
        if(bi_.size() < 15)
            bi_.fill_16(r.in.next);
        auto cp = &lencode_[bi_.peek_fast() & lmask];
    dolen:
        bi_.drop(cp->bits);
        op = (unsigned)(cp->op);
        if(op == 0)
        {
            // literal
            *r.out.next++ = (unsigned char)(cp->val);
        }
        else if(op & 16)
        {
            // length base
            len = (unsigned)(cp->val);
            op &= 15; // number of extra bits
            if(op)
            {
                if(bi_.size() < op)
                    bi_.fill_8(r.in.next);
                len += (unsigned)bi_.peek_fast() & ((1U << op) - 1);
                bi_.drop(op);
            }
            if(bi_.size() < 15)
                bi_.fill_16(r.in.next);
            cp = &distcode_[bi_.peek_fast() & dmask];
        dodist:
            bi_.drop(cp->bits);
            op = (unsigned)(cp->op);
            if(op & 16)
            {
                // distance base
                dist = (unsigned)(cp->val);
                op &= 15; // number of extra bits
                if(bi_.size() < op)
                {
                    bi_.fill_8(r.in.next);
                    if(bi_.size() < op)
                        bi_.fill_8(r.in.next);
                }
                dist += (unsigned)bi_.peek_fast() & ((1U << op) - 1);
#ifdef INFLATE_STRICT
                if(dist > dmax_)
                {
                    ec = error::invalid_distance;
                    mode_ = BAD;
                    break;
                }
#endif
                bi_.drop(op);

                op = r.out.used();
                if(dist > op)
                {
                    // copy from window
                    op = dist - op; // distance back in window
                    if(op > w_.size())
                    {
                        ec = error::invalid_distance;
                        mode_ = BAD;
                        break;
                    }
                    auto const n = detail::clamp(len, op);
                    w_.read(r.out.next, op, n);
                    r.out.next += n;
                    len -= n;
                }
                if(len > 0)
                {
                    if(dist > 1)
                    {
                        // copy from output
                        auto n = detail::clamp(len, dist);
                        std::memcpy(r.out.next, r.out.next - dist, n);
                        r.out.next += n;
                        len -= n;
                    }
                    if(len > 0)
                    {
                        // fill from output
                        std::memset(r.out.next, r.out.next[-1], len);
                        r.out.next += len;
                    }
                }
            }
            else if((op & 64) == 0)
            {
                // 2nd level distance code
                cp = &distcode_[cp->val + (bi_.peek_fast() & ((1U << op) - 1))];
                goto dodist;
            }
            else
            {
                ec = error::invalid_distance_code;
                mode_ = BAD;
                break;
            }
        }
        else if((op & 64) == 0)
        {
            // 2nd level length code
            cp = &lencode_[cp->val + (bi_.peek_fast() & ((1U << op) - 1))];
            goto dolen;
        }
        else if(op & 32)
        {
            // end-of-block
            mode_ = TYPE;
            break;
        }
        else
        {
            ec = error::invalid_literal_length;
            mode_ = BAD;
            break;
        }
    }
    while(r.in.next < last && r.out.next < end);

    // return unused bytes (on entry, bits < 8, so in won't go too far back)
    bi_.rewind(r.in.next);
}

/*
   inflate_fast() speedups that turned out slower (on a PowerPC G3 750CXe):
   - Using bit fields for code structure
   - Different op definition to avoid & for extra bits (do & for table bits)
   - Three separate decoding do-loops for direct, window, and wnext == 0
   - Special case for distance > 1 copies to do overlapped load and store copy
   - Explicit branch predictions (based on measured branch probabilities)
   - Deferring match copy and interspersed it with decoding subsequent codes
   - Swapping literal/length else
   - Swapping window/direct else
   - Larger unrolled copy loops (three is about right)
   - Moving len -= 3 statement into middle of loop
 */

} // zlib
} // beast

#endif
