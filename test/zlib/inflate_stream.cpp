//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Test that header file is self-contained.
#include <beast/zlib/inflate_stream.hpp>

#include "ztest.hpp"
#include <beast/unit_test/suite.hpp>
#include <chrono>
#include <random>

namespace beast {
namespace zlib {

class inflate_stream_test : public beast::unit_test::suite
{
public:
    using self = inflate_stream_test;
    typedef void(self::*pmf_t)(
        int windowBits, std::string const& in, std::string const& check);

    //--------------------------------------------------------------------------

    //
    // Decompress in a single step using Z_SYNC_FLUSH
    //

    void
    doInflate1_zlib(int windowBits,
        std::string const& in, std::string const& check)
    {
        int result;
        std::string out;
        out.resize(check.size() + 1);
        ::z_stream zs;
        memset(&zs, 0, sizeof(zs));
        result = inflateInit2(&zs, -windowBits);
        if(! BEAST_EXPECT(result == Z_OK))
            goto err;
        zs.next_in = (Bytef*)in.data();
        zs.avail_in = in.size();
        zs.next_out = (Bytef*)out.data();
        zs.avail_out = out.size();
        {
            bool progress = true;
            for(;;)
            {
                result = inflate(&zs, Z_SYNC_FLUSH);
                if( result == Z_BUF_ERROR ||
                    result == Z_STREAM_END) // per zlib FAQ
                    goto fin;
                if(! BEAST_EXPECT(progress))
                    goto err;
                progress = false;
            }
        }

    fin:
        out.resize(zs.total_out);
        BEAST_EXPECT(out == check);

    err:
        inflateEnd(&zs);
    }

    void
    doInflate1_beast(int windowBits,
        std::string const& in, std::string const& check)
    {
        std::string out;
        out.resize(check.size() + 1);
        z_params zs;
        zs.next_in = (Bytef*)in.data();
        zs.avail_in = in.size();
        zs.next_out = (Bytef*)out.data();
        zs.avail_out = out.size();
        inflate_stream is;
        is.reset(windowBits);
        {
            bool progress = true;
            for(;;)
            {
                error_code ec;
                is.write(zs, Flush::sync, ec);
                if( ec == error::no_progress ||
                    ec == error::end_of_stream) // per zlib FAQ
                    goto fin;
                if(! BEAST_EXPECTS(! ec, ec.message()))
                    goto err;
                progress = false;
            }
        }

    fin:
        out.resize(zs.total_out);
        BEAST_EXPECT(out == check);
    err:
        ;
    }

    //--------------------------------------------------------------------------

    //
    // Decompress the input in two pieces, using Z_BLOCK
    //

    void
    doInflate2_zlib(int windowBits,
        std::string const& in, std::string const& check)
    {
        BEAST_EXPECT(in.size() > 1);
        BEAST_EXPECT(check.size() > 1);
        for(std::size_t i = 1; i < in.size(); ++i)
        {
            int result;
            std::string out;
            out.resize(check.size() + 1);
            ::z_stream zs;
            memset(&zs, 0, sizeof(zs));
            result = inflateInit2(&zs, -windowBits);
            if(! BEAST_EXPECT(result == Z_OK))
                continue;
            zs.next_in = (Bytef*)in.data();
            zs.avail_in = i;
            zs.next_out = (Bytef*)out.data();
            zs.avail_out = out.size();
            bool b = false;
            for(;;)
            {
                result = inflate(&zs, Z_BLOCK);
                if( result == Z_BUF_ERROR ||
                    result == Z_STREAM_END) // per zlib FAQ
                    goto fin;
                if(! BEAST_EXPECT(result == Z_OK))
                    goto err;
                if(zs.avail_in == 0 && ! b)
                {
                    b = true;
                    zs.avail_in = in.size() - i;
                }
            }

        fin:
            out.resize(zs.total_out);
            BEAST_EXPECT(out == check);

        err:
            inflateEnd(&zs);
        }
    }

    void
    doInflate2_beast(int windowBits,
        std::string const& in, std::string const& check)
    {
        BEAST_EXPECT(in.size() > 1);
        BEAST_EXPECT(check.size() > 1);
        for(std::size_t i = 1; i < in.size(); ++i)
        {
            std::string out;
            out.resize(check.size() + 1);
            z_params zs;
            zs.next_in = (Bytef*)in.data();
            zs.avail_in = i;
            zs.next_out = (Bytef*)out.data();
            zs.avail_out = out.size();
            inflate_stream is;
            is.reset(windowBits);
            bool b = false;
            for(;;)
            {
                error_code ec;
                is.write(zs, Flush::block, ec);
                if( ec == error::no_progress ||
                    ec == error::end_of_stream) // per zlib FAQ
                    goto fin;
                if(! BEAST_EXPECTS(! ec, ec.message()))
                    goto err;
                if(zs.avail_in == 0 && ! b)
                {
                    b = true;
                    zs.avail_in = in.size() - i;
                }
            }

        fin:
            out.resize(zs.total_out);
            BEAST_EXPECT(out == check);

        err:
            ;
        }
    }

    //--------------------------------------------------------------------------

    //
    // Decompress with input and output each broken into
    // two pieces, using Z_SYNC_FLUSH (this is CPU intensive)
    //

    void
    doInflate3_zlib(int windowBits,
        std::string const& in, std::string const& check)
    {
        BEAST_EXPECT(in.size() > 1);
        BEAST_EXPECT(check.size() > 1);
        for(std::size_t i = 1; i < in.size(); ++i)
        {
            for(std::size_t j = 1; j < check.size(); ++j)
            {
                int result;
                std::string out;
                out.resize(check.size() + 1);
                ::z_stream zs;
                memset(&zs, 0, sizeof(zs));
                result = inflateInit2(&zs, -windowBits);
                if(! BEAST_EXPECT(result == Z_OK))
                    continue;
                zs.next_in = (Bytef*)in.data();
                zs.avail_in = i;
                zs.next_out = (Bytef*)out.data();
                zs.avail_out = j;
                bool bi = false;
                bool bo = false;
                for(;;)
                {
                    result = inflate(&zs, Z_SYNC_FLUSH);
                    if( result == Z_BUF_ERROR ||
                        result == Z_STREAM_END) // per zlib FAQ
                        goto fin;
                    if(! BEAST_EXPECT(result == Z_OK))
                        goto err;
                    if(zs.avail_in == 0 && ! bi)
                    {
                        bi = true;
                        zs.avail_in = in.size() - i;
                    }
                    if(zs.avail_out == 0 && ! bo)
                    {
                        bo = true;
                        zs.avail_out = check.size() - j;
                    }
                }

            fin:
                out.resize(zs.total_out);
                BEAST_EXPECT(out == check);

            err:
                inflateEnd(&zs);
            }
        }
    }

    void
    doInflate3_beast(int windowBits,
        std::string const& in, std::string const& check)
    {
        BEAST_EXPECT(in.size() > 1);
        BEAST_EXPECT(check.size() > 1);
        for(std::size_t i = 1; i < in.size(); ++i)
        {
            for(std::size_t j = 1; j < check.size(); ++j)
            {
                std::string out;
                out.resize(check.size() + 1);
                z_params zs;
                zs.next_in = (Bytef*)in.data();
                zs.avail_in = i;
                zs.next_out = (Bytef*)out.data();
                zs.avail_out = j;
                inflate_stream is;
                is.reset(windowBits);
                bool bi = false;
                bool bo = false;
                for(;;)
                {
                    error_code ec;
                    is.write(zs, Flush::sync, ec);
                    if( ec == error::no_progress ||
                        ec == error::end_of_stream) // per zlib FAQ
                        goto fin;
                    if(! BEAST_EXPECTS(! ec, ec.message()))
                        goto err;
                    if(zs.avail_in == 0 && ! bi)
                    {
                        bi = true;
                        zs.avail_in = in.size() - i;
                    }
                    if(zs.avail_out == 0 && ! bo)
                    {
                        bo = true;
                        zs.avail_out = check.size() - j;
                    }
                }

            fin:
                out.resize(zs.total_out);
                BEAST_EXPECT(out == check);

            err:
                ;
            }
        }
    }

    //--------------------------------------------------------------------------

    //
    // Calls a decompression test function with all possible
    // compressed versions of the specified check plaintext
    //

    void
    doMatrix(std::string const& label,
        std::string const& check, pmf_t pmf)
    {
        using namespace std::chrono;
        using clock_type = steady_clock;
        auto const when = clock_type::now();
        for(int level = 0; level <= 9; ++level)
        {
            for(int windowBits = 8; windowBits <= 15; ++windowBits)
            {
                for(int strategy = 0; strategy <= 4; ++strategy)
                {
                    z_deflator zd;
                    zd.level(level);
                    zd.windowBits(windowBits);
                    zd.strategy(strategy);
                    auto const in = zd(check);
                    (this->*pmf)(windowBits, in, check);
                }
            }
        }
        auto const elapsed = clock_type::now() - when;
        log <<
            label << ": " <<
            duration_cast<
                milliseconds>(elapsed).count() << "ms\n";
        log.flush();
    }

    void
    testInflate()
    {
        {
            doMatrix("1.zlib  ", "Hello, world!", &self::doInflate1_zlib);
            doMatrix("1.beast ", "Hello, world!", &self::doInflate1_beast);
        }
        {
            auto const s = corpus1(300);
            doMatrix("2.zlib  ", s, &self::doInflate1_zlib);
            doMatrix("2.beast ", s, &self::doInflate1_beast);
        }
        {
            doMatrix("3.zlib  ", "Hello, world!", &self::doInflate2_zlib);
            doMatrix("3.beast ", "Hello, world!", &self::doInflate2_beast);
        }
        {
            auto const s = corpus1(300);
            doMatrix("4.zlib  ", s, &self::doInflate2_zlib);
            doMatrix("4.beast ", s, &self::doInflate2_beast);
        }
        {
            doMatrix("5.zlib  ",
                "iEYEARECAAYFAjdY"
                "CQoACgkQJ9S6ULt1"
                "dqz6IwCfQ7wP6i/i"
                "8HhbcOSKF4ELyQB1"
                "oCoAoOuqpRqEzr4k"
                "OkQqHRLE/b8/Rw2k",
                    &self::doInflate3_zlib);
            doMatrix("5.beast ",
                "iEYEARECAAYFAjdY"
                "CQoACgkQJ9S6ULt1"
                "dqz6IwCfQ7wP6i/i"
                "8HhbcOSKF4ELyQB1"
                "oCoAoOuqpRqEzr4k"
                "OkQqHRLE/b8/Rw2k",
                    &self::doInflate3_beast);
        }

#if 0
        {
            // Takes over 2 minutes on release
            auto const s = corpus1(300);
            doMatrix("6.zlib  ", s, &self::doInflate3_zlib);
            doMatrix("6.beast ", s, &self::doInflate3_beast);
        }
#endif
    }

    void
    run() override
    {
        testInflate();
    }
};

BEAST_DEFINE_TESTSUITE(inflate_stream,core,beast);

} // zlib
} // beast