//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_WEBSOCKET_DETAIL_PMD_EXTENSION_HPP
#define BEAST_WEBSOCKET_DETAIL_PMD_EXTENSION_HPP

#include <beast/core/error.hpp>
#include <beast/core/consuming_buffers.hpp>
#include <beast/core/detail/ci_char_traits.hpp>
#include <beast/zlib/deflate_stream.hpp>
#include <beast/zlib/inflate_stream.hpp>
#include <beast/websocket/option.hpp>
#include <beast/http/rfc7230.hpp>
#include <boost/asio/buffer.hpp>
#include <utility>

#include "../test/zlib/zlib-1.2.8/zlib.h"

namespace beast {
namespace websocket {
namespace detail {

// permessage-deflate offer parameters
//
// "context takeover" means:
// preserve sliding window across messages
//
struct pmd_offer
{
    bool accept;

    // 0 = absent, or 8..15
    int server_max_window_bits;

    // -1 = present, 0 = absent, or 8..15
    int client_max_window_bits;

    // `true` if server_no_context_takeover offered
    bool server_no_context_takeover;

    // `true` if client_no_context_takeover offered
    bool client_no_context_takeover;
};

template<class = void>
int
parse_bits(boost::string_ref const& s)
{
    if(s.size() == 0)
        return -1;
    if(s.size() > 2)
        return -1;
    if(s[0] < '1' || s[0] > '9')
        return -1;
    int i = 0;
    for(auto c : s)
    {
        if(c < '0' || c > '9')
            return -1;
        i = 10 * i + (c - '0');
    }
    return i;
}

// Parse permessage-deflate request headers
//
template<class Headers>
void
pmd_read(pmd_offer& offer, Headers const& headers)
{
    offer.accept = false;
    offer.server_max_window_bits= 0;
    offer.client_max_window_bits = 0;
    offer.server_no_context_takeover = false;
    offer.client_no_context_takeover = false;

    using beast::detail::ci_equal;
    http::ext_list list{
        headers["Sec-WebSocket-Extensions"]};
    for(auto const& ext : list)
    {
        if(ci_equal(ext.first, "permessage-deflate"))
        {
            for(auto const& param : ext.second)
            {
                if(ci_equal(param.first,
                    "server_max_window_bits"))
                {
                    if(offer.server_max_window_bits != 0)
                    {
                        // The negotiation offer contains multiple
                        // extension parameters with the same name.
                        //
                        return; // MUST decline
                    }
                    if(param.second.empty())
                    {
                        // The negotiation offer extension
                        // parameter is missing the value.
                        //
                        return; // MUST decline
                    }
                    offer.server_max_window_bits =
                        parse_bits(param.second);
                    if( offer.server_max_window_bits < 8 ||
                        offer.server_max_window_bits > 15)
                    {
                        // The negotiation offer contains an
                        // extension parameter with an invalid value.
                        //
                        return; // MUST decline
                    }
                }
                else if(ci_equal(param.first,
                    "client_max_window_bits"))
                {
                    if(offer.client_max_window_bits != 0)
                    {
                        // The negotiation offer contains multiple
                        // extension parameters with the same name.
                        //
                        return; // MUST decline
                    }
                    if(! param.second.empty())
                    {
                        offer.client_max_window_bits =
                            parse_bits(param.second);
                        if( offer.client_max_window_bits < 8 ||
                            offer.client_max_window_bits > 15)
                        {
                            // The negotiation offer contains an
                            // extension parameter with an invalid value.
                            //
                            return; // MUST decline
                        }
                    }
                    else
                    {
                        offer.client_max_window_bits = -1;
                    }
                }
                else if(ci_equal(param.first,
                    "server_no_context_takeover"))
                {
                    if(offer.server_no_context_takeover)
                    {
                        // The negotiation offer contains multiple
                        // extension parameters with the same name.
                        //
                        return; // MUST decline
                    }
                    if(! param.second.empty())
                    {
                        // The negotiation offer contains an
                        // extension parameter with an invalid value.
                        //
                        return; // MUST decline
                    }
                    offer.server_no_context_takeover = true;
                }
                else if(ci_equal(param.first,
                    "client_no_context_takeover"))
                {
                    if(offer.client_no_context_takeover)
                    {
                        // The negotiation offer contains multiple
                        // extension parameters with the same name.
                        //
                        return; // MUST decline
                    }
                    if(! param.second.empty())
                    {
                        // The negotiation offer contains an
                        // extension parameter with an invalid value.
                        //
                        return; // MUST decline
                    }
                    offer.client_no_context_takeover = true;
                }
                else
                {
                    // The negotiation offer contains an extension
                    // parameter not defined for use in an offer.
                    //
                    return; // MUST decline
                }
            }
            offer.accept = true;
            return;
        }
    }
}

// Set permessage-deflate headers for a client offer
//
template<class Headers>
void
pmd_write(Headers& headers, pmd_offer const& offer)
{
    std::string s;
    s = "permessage-deflate";
    if(offer.server_max_window_bits != 0)
    {
        if(offer.server_max_window_bits != -1)
        {
            s += "; server_max_window_bits=";
            s += std::to_string(
                offer.server_max_window_bits);
        }
        else
        {
            s += "; server_max_window_bits";
        }
    }
    if(offer.client_max_window_bits != 0)
    {
        if(offer.client_max_window_bits != -1)
        {
            s += "; client_max_window_bits=";
            s += std::to_string(
                offer.server_max_window_bits);
        }
        else
        {
            s += "; client_max_window_bits";
        }
    }
    if(offer.server_no_context_takeover)
    {
        s += "; server_no_context_takeover";
    }
    if(offer.client_no_context_takeover)
    {
        s += "; client_no_context_takeover";
    }
    headers.replace("Sec-WebSocket-Extensions", s);
}

// Negotiate a permessage-deflate client offer
//
template<class Headers>
void
pmd_negotiate(
    Headers& headers,
    pmd_offer& config,
    pmd_offer const& offer,
    permessage_deflate const& o)
{
    if(! offer.accept)
    {
        config.accept = false;
        return;
    }
    config.accept = true;

    std::string s = "permessage-deflate";

    config.server_no_context_takeover =
        offer.server_no_context_takeover ||
            o.server_no_context_takeover;
    if(config.server_no_context_takeover)
        s += "; server_no_context_takeover";

    config.client_no_context_takeover =
        o.client_no_context_takeover ||
            offer.client_no_context_takeover;
    if(config.client_no_context_takeover)
        s += "; client_no_context_takeover";

    if(offer.server_max_window_bits != 0)
        config.server_max_window_bits = std::min(
            offer.server_max_window_bits,
                o.server_max_window_bits);
    else
        config.server_max_window_bits =
            o.server_max_window_bits;
    if(config.server_max_window_bits < 15)
    {
        s += "; server_max_window_bits=";
        s += std::to_string(
            config.server_max_window_bits);
    }
    
    switch(offer.client_max_window_bits)
    {
    case -1:
        // extension parameter is present with no value
        config.client_max_window_bits =
            o.client_max_window_bits;
        if(config.client_max_window_bits < 15)
        {
            s += "client_max_window_bits=";
            s += std::to_string(
                config.client_max_window_bits);
        }
        break;

    case 0:
        /*  extension parameter is absent.

            If a received extension negotiation offer doesn't have the
            "client_max_window_bits" extension parameter, the corresponding
            extension negotiation response to the offer MUST NOT include the
            "client_max_window_bits" extension parameter.
        */
        if(o.client_max_window_bits == 15)
            config.client_max_window_bits = 15;
        else
            config.accept = false;
        break;

    default:
        // extension parameter has value in [8..15]
        if(o.client_max_window_bits <
           offer.client_max_window_bits)
        {
            // Use server's lower configured limit
            config.client_max_window_bits =
                o.client_max_window_bits;
            s += "client_max_window_bits=";
            s += std::to_string(
                config.client_max_window_bits);
        }
        else
        {
            config.client_max_window_bits =
                offer.client_max_window_bits;
        }
        break;
    }
    if(config.accept)
        headers.replace("Sec-WebSocket-Extensions", s);
}

// Normalize the server's response
//
inline
void
pmd_normalize(pmd_offer& offer)
{
    if(offer.accept)
    {
        if( offer.server_max_window_bits == 0)
            offer.server_max_window_bits = 15;

        if( offer.client_max_window_bits ==  0 ||
            offer.client_max_window_bits == -1)
            offer.client_max_window_bits = 15;
    }
}

//--------------------------------------------------------------------

// Decompress into a DynamicBuffer
//
template<class InflateStream, class DynamicBuffer>
void
inflate(
    InflateStream& zi,
    DynamicBuffer& dynabuf,
    boost::asio::const_buffer const& in,
    error_code& ec)
{
    using boost::asio::buffer_cast;
    using boost::asio::buffer_size;
    zlib::z_params zs;
    zs.avail_in = buffer_size(in);
    zs.next_in = buffer_cast<void const*>(in);
    for(;;)
    {
        auto const bs = dynabuf.prepare(
            read_size_helper(dynabuf, 65536));
        auto const out = *bs.begin();
        zs.avail_out = buffer_size(out);
        zs.next_out = buffer_cast<void*>(out);
        zi.write(zs, zlib::Flush::sync, ec);
        dynabuf.commit(zs.total_out);
        zs.total_out = 0;
        if( ec == zlib::error::need_buffers ||
            ec == zlib::error::end_of_stream)
        {
            ec = {};
            break;
        }
        if(ec)
            return;
    }
}

// Compress a buffer sequence
// Returns: input used, output used
//
template<class DeflateStream, class ConstBufferSequence>
std::pair<std::size_t, std::size_t>
deflate(
    DeflateStream& zo,
    boost::asio::mutable_buffer const& out,
    consuming_buffers<ConstBufferSequence>& cb,
    bool last,
    error_code& ec)
{
    using boost::asio::buffer_cast;
    using boost::asio::buffer_size;
    zlib::z_params zs;
    zs.avail_out = buffer_size(out);
    zs.next_out = buffer_cast<void*>(out);
    for(auto const& in : cb)
    {
        zs.avail_in = buffer_size(in);
        zs.next_in = buffer_cast<void const*>(in);
        zo.write(zs, zlib::Flush::block, ec);
        if(ec == zlib::error::need_buffers)
        {
            ec = {};
            break;
        }
        if(ec)
            return { 0, 0 };
        BOOST_ASSERT(zs.avail_in == 0);
    }
    if( last &&
        zs.avail_in == 0 &&
        buffer_size(out) - zs.total_out >= 6)
    {
        zo.write(zs, zlib::Flush::full, ec);
        BOOST_ASSERT(! ec);
        // remove flush marker
        zs.total_out -= 4;
    }
    cb.consume(zs.total_in);
    return { zs.total_in, zs.total_out };
}

//--------------------------------------------------------------------

class zinflate_stream
{
    ::z_stream zs_;

public:
    zinflate_stream()
    {
        std::memset(&zs_, 0, sizeof(zs_));
        inflateInit2(&zs_, -15);
    }

    void
    reset(int windowBits)
    {
        inflateReset2(&zs_, -windowBits);
    }

    void
    reset()
    {
        inflateReset(&zs_);
    }

    void
    write(zlib::z_params& zs, zlib::Flush flush, error_code& ec)
    {
        zs_.next_in = (Bytef*)zs.next_in;
        zs_.next_out = (Bytef*)zs.next_out;
        zs_.avail_in = zs.avail_in;
        zs_.avail_out = zs.avail_out;
        zs_.total_in = zs.total_in;
        zs_.total_out = zs.total_out;

        auto const result = inflate(
            &zs_, Z_SYNC_FLUSH);

        switch(result)
        {
        case Z_BUF_ERROR: ec = zlib::error::need_buffers; break;
        case Z_STREAM_END: ec = zlib::error::end_of_stream; break;
        case Z_OK: break;
        default:
            ec = zlib::error::stream_error;
            break;
        }

        zs.next_in =    zs_.next_in;
        zs.next_out =   zs_.next_out;
        zs.avail_in =   zs_.avail_in;
        zs.avail_out =  zs_.avail_out;
        zs.total_in =   zs_.total_in;
        zs.total_out =  zs_.total_out;
    }

    ~zinflate_stream()
    {
        inflateEnd(&zs_);
    }
};

class zdeflate_stream
{
    ::z_stream zs_;

public:
    zdeflate_stream()
    {
        std::memset(&zs_, 0, sizeof(zs_));
        deflateInit2(&zs_,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            -15,
            4,
            Z_DEFAULT_STRATEGY);
    }

    ~zdeflate_stream()
    {
        deflateEnd(&zs_);
    }

    void reset(
        int compLevel,
        int windowBits,
        int memLevel,
        zlib::Strategy strategy)
    {
        deflateEnd(&zs_);
        deflateInit2(&zs_,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            -15,
            4,
            Z_DEFAULT_STRATEGY);
    }

    void
    write(zlib::z_params& zs, zlib::Flush flush, error_code& ec)
    {
        zs_.next_in = (Bytef*)zs.next_in;
        zs_.next_out = (Bytef*)zs.next_out;
        zs_.avail_in = zs.avail_in;
        zs_.avail_out = zs.avail_out;
        zs_.total_in = zs.total_in;
        zs_.total_out = zs.total_out;

        int fl;
        switch(flush)
        {
        case zlib::Flush::none: fl = Z_NO_FLUSH; break;
        case zlib::Flush::full: fl = Z_FULL_FLUSH; break;
        case zlib::Flush::block: fl = Z_BLOCK; break;
        default:
            throw std::invalid_argument{"unknown flush"};
        }
        auto const result = deflate(&zs_, fl);

        switch(result)
        {
        case Z_BUF_ERROR: ec = zlib::error::need_buffers; break;
        case Z_STREAM_END: ec = zlib::error::end_of_stream; break;
        case Z_OK: break;
        default:
            ec = zlib::error::stream_error;
            break;
        }

        zs.next_in =    zs_.next_in;
        zs.next_out =   zs_.next_out;
        zs.avail_in =   zs_.avail_in;
        zs.avail_out =  zs_.avail_out;
        zs.total_in =   zs_.total_in;
        zs.total_out =  zs_.total_out;
    }
};

} // detail
} // websocket
} // beast

#endif
