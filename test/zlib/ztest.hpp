//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_ZTEST_HPP
#define BEAST_ZTEST_HPP

#include "zlib-1.2.8/zlib.h"
#include <string>

class z_deflator
{
public:
    std::string
    operator()(std::string const& in)
    {
        int result;
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        result = deflateInit2(
            &zs,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            -15,
            4,
            Z_DEFAULT_STRATEGY
        );
        std::string out;
        out.resize(deflateBound(&zs, in.size()));
        zs.next_in = (Bytef*)in.data();
        zs.avail_in = in.size();
        zs.next_out = (Bytef*)&out[0];
        zs.avail_out = out.size();
        result = deflate(&zs, Z_FULL_FLUSH);
        out.resize(zs.total_out);
        deflateEnd(&zs);
        return out;
    }
};

class z_inflator
{
public:
    std::string
    operator()(std::string const& in)
    {
        int result;
        std::string out;
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        result = inflateInit2(&zs, -15);
        try
        {
            zs.next_in = (Bytef*)in.data();
            zs.avail_in = in.size();
            for(;;)
            {
                out.resize(zs.total_out + 1024);
                zs.next_out = (Bytef*)&out[zs.total_out];
                zs.avail_out = out.size() - zs.total_out;
                result = inflate(&zs, Z_SYNC_FLUSH);
                if( result == Z_NEED_DICT ||
                    result == Z_DATA_ERROR ||
                    result == Z_MEM_ERROR)
                {
                    throw std::logic_error("inflate failed");
                }
                if(zs.avail_out > 0)
                    break;
                if(result == Z_STREAM_END)
                    break;
            }
            out.resize(zs.total_out);
            inflateEnd(&zs);
        }
        catch(...)
        {
            inflateEnd(&zs);
            throw;
        }
        return out;
    }
};

#endif
