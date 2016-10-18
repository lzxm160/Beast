//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Test that header file is self-contained.
//#include <beast/zlib/inflate_stream.hpp>

#include "ztest.hpp"
#include <beast/unit_test/suite.hpp>

namespace beast {
namespace zlib {

class inflate_stream_test : public beast::unit_test::suite
{
public:
    // Decompress using ZLib
    void
    doInflate(int windowBits,
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
                z_stream zs;
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
                    auto const flush = Z_SYNC_FLUSH;
                    result = inflate(&zs, flush);
                    if(result == Z_BUF_ERROR) // per zlib FAQ
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
    doMatrix(std::string const& check)
    {
        z_deflator zd;
        doInflate(15, zd(check), check);
    }

    void
    testInflate()
    {
        doMatrix("Hello, world!");
        doMatrix("Hello, world! Hello, world!");
        doMatrix("Hello, world! Hello, world! Hello, world! Hello, world! Hello, world!");
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
