//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Test that header file is self-contained.
#include <beast/http/headers_parser_v1.hpp>

#include <beast/http/headers.hpp>
#include <beast/unit_test/suite.hpp>
#include <boost/asio/buffer.hpp>

namespace beast {
namespace http {

class headers_parser_v1_test : public beast::unit_test::suite
{
public:
    void testParser()
    {
        {
            error_code ec;
            headers_parser_v1<true, headers> p;
            BEAST_EXPECT(! p.complete());
            auto const n = p.write(boost::asio::buffer(
                "GET / HTTP/1.1\r\n"
                "User-Agent: test\r\n"
                "\r\n"
                ), ec);
            BEAST_EXPECTS(! ec, ec.message());
            BEAST_EXPECT(p.complete());
            BEAST_EXPECT(n == 36);
        }
        {
            error_code ec;
            headers_parser_v1<true, headers> p;
            BEAST_EXPECT(! p.complete());
            auto const n = p.write(boost::asio::buffer(
                "GET / HTTP/1.1\r\n"
                "User-Agent: test\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "*****"
                ), ec);
            BEAST_EXPECT(n == 55);
            BEAST_EXPECTS(! ec, ec.message());
            BEAST_EXPECT(p.complete());
        }
        {
            error_code ec;
            headers_parser_v1<false, headers> p;
            BEAST_EXPECT(! p.complete());
            auto const n = p.write(boost::asio::buffer(
                "HTTP/1.1 200 OK\r\n"
                "Server: test\r\n"
                "\r\n"
                ), ec);
            BEAST_EXPECT(n == 33);
            BEAST_EXPECTS(! ec, ec.message());
            BEAST_EXPECT(p.complete());
        }
        {
            error_code ec;
            headers_parser_v1<false, headers> p;
            BEAST_EXPECT(! p.complete());
            auto const n = p.write(boost::asio::buffer(
                "HTTP/1.1 200 OK\r\n"
                "Server: test\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "*****"
                ), ec);
            BEAST_EXPECT(n == 52);
            BEAST_EXPECTS(! ec, ec.message());
            BEAST_EXPECT(p.complete());
        }
    }

    void run() override
    {
        testParser();
    }
};

BEAST_DEFINE_TESTSUITE(headers_parser_v1,http,beast);

} // http
} // beast
