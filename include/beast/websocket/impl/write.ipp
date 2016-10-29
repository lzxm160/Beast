//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_WEBSOCKET_IMPL_WRITE_IPP
#define BEAST_WEBSOCKET_IMPL_WRITE_IPP

#include <beast/core/bind_handler.hpp>
#include <beast/core/buffer_cat.hpp>
#include <beast/core/buffer_concepts.hpp>
#include <beast/core/consuming_buffers.hpp>
#include <beast/core/handler_alloc.hpp>
#include <beast/core/prepare_buffers.hpp>
#include <beast/core/static_streambuf.hpp>
#include <beast/core/stream_concepts.hpp>
#include <beast/core/detail/clamp.hpp>
#include <beast/websocket/detail/frame.hpp>
#include <boost/assert.hpp>
#include <algorithm>
#include <memory>

namespace beast {
namespace websocket {

template<class NextLayer>
template<class Buffers, class Handler>
class stream<NextLayer>::write_frame_op
{
    using alloc_type =
        handler_alloc<char, Handler>;

    struct data : op
    {
        stream<NextLayer>& ws;
        consuming_buffers<Buffers> cb;
        Handler h;
        bool fin;
        detail::frame_header fh;
        detail::fh_streambuf fh_buf;
        detail::prepared_key key;
        std::uint64_t remain;
        bool cont;
        int state = 0;
        int entry;

        template<class DeducedHandler>
        data(DeducedHandler&& h_, stream<NextLayer>& ws_,
                bool fin_, Buffers const& bs)
            : ws(ws_)
            , cb(bs)
            , h(std::forward<DeducedHandler>(h_))
            , fin(fin_)
            , cont(boost_asio_handler_cont_helpers::
                is_continuation(h))
        {
        }
    };

    std::shared_ptr<data> d_;

public:
    write_frame_op(write_frame_op&&) = default;
    write_frame_op(write_frame_op const&) = default;

    template<class DeducedHandler, class... Args>
    write_frame_op(DeducedHandler&& h,
            stream<NextLayer>& ws, Args&&... args)
        : d_(std::make_shared<data>(
            std::forward<DeducedHandler>(h), ws,
                std::forward<Args>(args)...))
    {
        (*this)(error_code{}, false);
    }

    void operator()()
    {
        (*this)(error_code{});
    }

    void operator()(error_code ec, std::size_t);

    void operator()(error_code ec, bool again = true);

    friend
    void* asio_handler_allocate(
        std::size_t size, write_frame_op* op)
    {
        return boost_asio_handler_alloc_helpers::
            allocate(size, op->d_->h);
    }

    friend
    void asio_handler_deallocate(
        void* p, std::size_t size, write_frame_op* op)
    {
        return boost_asio_handler_alloc_helpers::
            deallocate(p, size, op->d_->h);
    }

    friend
    bool asio_handler_is_continuation(write_frame_op* op)
    {
        return op->d_->cont;
    }

    template<class Function>
    friend
    void asio_handler_invoke(Function&& f, write_frame_op* op)
    {
        return boost_asio_handler_invoke_helpers::
            invoke(f, op->d_->h);
    }
};

template<class NextLayer>
template<class Buffers, class Handler>
void 
stream<NextLayer>::
write_frame_op<Buffers, Handler>::
operator()(error_code ec, std::size_t)
{
    auto& d = *d_;
    if(ec)
        d.ws.failed_ = true;
    (*this)(ec);
}

template<class NextLayer>
template<class Buffers, class Handler>
void
stream<NextLayer>::
write_frame_op<Buffers, Handler>::
operator()(error_code ec, bool again)
{
    using beast::detail::clamp;
    using boost::asio::buffer;
    using boost::asio::buffer_copy;
    using boost::asio::buffer_size;
    using boost::asio::mutable_buffers_1;
    enum
    {
        do_init = 0,
        do_nomask_nofrag = 20,
        do_nomask_frag = 30,
        do_mask_nofrag = 40,
        do_mask_frag = 50,
        do_deflate = 60,
        do_maybe_suspend = 80,
        do_upcall = 99
    };
    auto& d = *d_;
    d.cont = d.cont || again;
    if(ec)
        goto upcall;
    for(;;)
    {
        switch(d.state)
        {
        case do_init:
            if(! d.ws.wr_.cont)
            {
                d.ws.wr_begin();
                d.fh.rsv1 = d.ws.wr_.compress;
            }
            d.fh.rsv2 = false;
            d.fh.rsv3 = false;
            d.fh.op = d.ws.wr_.cont ?
                opcode::cont : d.ws.wr_opcode_;
            d.fh.mask =
                d.ws.role_ == detail::role_type::client;
            d.ws.wr_.cont = ! d.fin;

            if(! d.fh.mask)
            {
                if(! d.ws.wr_.autofrag)
                {
                    d.entry = do_nomask_nofrag;
                }
                else
                {
                    BOOST_ASSERT(d.ws.wr_.buf_size != 0);
                    d.remain = buffer_size(d.cb);
                    if(d.remain > d.ws.wr_.buf_size)
                        d.entry = do_nomask_frag;
                    else
                        d.entry = do_nomask_nofrag;
                }
                d.state = do_maybe_suspend;
            }
            else
            {
                if(! d.ws.wr_.autofrag)
                {
                    d.entry = do_mask_nofrag;
                }
                else
                {
                    BOOST_ASSERT(d.ws.wr_.buf_size != 0);
                    d.remain = buffer_size(d.cb);
                    if(d.remain > d.ws.wr_.buf_size)
                        d.entry = do_mask_frag;
                    else
                        d.entry = do_mask_nofrag;
                }
                d.state = do_maybe_suspend;
            }
            break;

        //----------------------------------------------------------------------

        case do_nomask_nofrag:
        {
            d.fh.fin = d.fin;
            d.fh.len = buffer_size(d.cb);
            detail::write<static_streambuf>(
                d.fh_buf, d.fh);
            // Send frame
            d.state = do_upcall;
            BOOST_ASSERT(! d.ws.wr_block_);
            d.ws.wr_block_ = &d;
            boost::asio::async_write(d.ws.stream_,
                buffer_cat(d.fh_buf.data(), d.cb),
                    std::move(*this));
            return;
        }

        //----------------------------------------------------------------------

        case do_nomask_frag:
            d.fh.len = clamp(
                d.remain, d.ws.wr_.buf_size);
            d.remain -= d.fh.len;
            d.fh.fin = d.fin ? d.remain == 0 : false;
            detail::write<static_streambuf>(
                d.fh_buf, d.fh);
            // Send frame
            d.state = d.remain == 0 ?
                do_upcall : do_nomask_frag + 1;
            BOOST_ASSERT(! d.ws.wr_block_);
            d.ws.wr_block_ = &d;
            boost::asio::async_write(d.ws.stream_,
                buffer_cat(d.fh_buf.data(),
                    prepare_buffers(d.fh.len, d.cb)),
                        std::move(*this));
            return;

        case do_nomask_frag + 1:
            d.cb.consume(d.fh.len);
            d.fh_buf.reset();
            d.fh.op = opcode::cont;
            if(d.ws.wr_block_ == &d)
                d.ws.wr_block_ = nullptr;
            d.ws.rd_op_.maybe_invoke();
            d.state = do_maybe_suspend;
            d.ws.get_io_service().post(
                std::move(*this));
            return;

        //----------------------------------------------------------------------

        case do_mask_nofrag:
        {
            d.fh.fin = d.fin;
            d.fh.len = d.remain;
            d.fh.key = d.ws.maskgen_();
            detail::prepare_key(d.key, d.fh.key);
            detail::write<static_streambuf>(
                d.fh_buf, d.fh);
            auto const n =
                clamp(d.remain, d.ws.wr_.buf_size);
            auto const b =
                buffer(d.ws.wr_.buf.get(), n);
            buffer_copy(b, d.cb);
            detail::mask_inplace(b, d.key);
            d.remain -= n;
            // Send frame header and partial payload
            d.state = d.remain == 0 ?
                do_upcall : do_mask_nofrag + 1;
            BOOST_ASSERT(! d.ws.wr_block_);
            d.ws.wr_block_ = &d;
            boost::asio::async_write(d.ws.stream_,
                buffer_cat(d.fh_buf.data(), b),
                    std::move(*this));
            return;
        }

        case do_mask_nofrag + 1:
        {
            d.cb.consume(d.ws.wr_.buf_size);
            auto const n =
                clamp(d.remain, d.ws.wr_.buf_size);
            auto const b =
                buffer(d.ws.wr_.buf.get(), n);
            buffer_copy(b, d.cb);
            detail::mask_inplace(b, d.key);
            d.remain -= n;
            // Send parial payload
            if(d.remain == 0)
                d.state = do_upcall;
            boost::asio::async_write(
                d.ws.stream_, b, std::move(*this));
            return;
        }

        //----------------------------------------------------------------------

        case do_mask_frag:
        {
            d.fh.len = clamp(
                d.remain, d.ws.wr_.buf_size);
            d.fh.key = d.ws.maskgen_();
            detail::prepare_key(d.key, d.fh.key);
            auto const b = buffer(
                d.ws.wr_.buf.get(), d.fh.len);
            buffer_copy(b, d.cb);
            detail::mask_inplace(b, d.key);
            d.remain -= d.fh.len;
            d.fh.fin = d.fin ? d.remain == 0 : false;
            detail::write<static_streambuf>(
                d.fh_buf, d.fh);
            // Send frame
            d.state = d.remain == 0 ?
                do_upcall : do_mask_frag + 1;
            BOOST_ASSERT(! d.ws.wr_block_);
            d.ws.wr_block_ = &d;
            boost::asio::async_write(d.ws.stream_,
                buffer_cat(d.fh_buf.data(), b),
                    std::move(*this));
            return;
        }

        case do_mask_frag + 1:
            d.cb.consume(d.fh.len);
            d.fh_buf.reset();
            d.fh.op = opcode::cont;
            if(d.ws.wr_block_ == &d)
                d.ws.wr_block_ = nullptr;
            d.ws.rd_op_.maybe_invoke();
            d.state = do_maybe_suspend;
            d.ws.get_io_service().post(
                std::move(*this));
            return;

        //----------------------------------------------------------------------

        case do_deflate:

            break;

        //----------------------------------------------------------------------

        case do_maybe_suspend:
        {
            if(d.ws.wr_block_)
            {
                // suspend
                d.state = do_maybe_suspend + 1;
                d.ws.wr_op_.template emplace<
                    write_frame_op>(std::move(*this));
                return;
            }
            if(d.ws.failed_ || d.ws.wr_close_)
            {
                // call handler
                d.state = do_upcall;
                d.ws.get_io_service().post(
                    bind_handler(std::move(*this),
                        boost::asio::error::operation_aborted));
                return;
            }
            d.state = d.entry;
            break;
        }

        case do_maybe_suspend + 1:
            d.state = do_maybe_suspend + 2;
            d.ws.get_io_service().post(bind_handler(
                std::move(*this), ec));
            return;

        case do_maybe_suspend + 2:
            if(d.ws.failed_ || d.ws.wr_close_)
            {
                // call handler
                ec = boost::asio::error::operation_aborted;
                goto upcall;
            }
            d.state = d.entry;
            break;

        //----------------------------------------------------------------------

        case do_upcall:
            goto upcall;
        }
    }
upcall:
    if(d.ws.wr_block_ == &d)
        d.ws.wr_block_ = nullptr;
    d.ws.rd_op_.maybe_invoke();
    d.h(ec);
}

template<class NextLayer>
template<class ConstBufferSequence, class WriteHandler>
typename async_completion<
    WriteHandler, void(error_code)>::result_type
stream<NextLayer>::
async_write_frame(bool fin,
    ConstBufferSequence const& bs, WriteHandler&& handler)
{
    static_assert(is_AsyncStream<next_layer_type>::value,
        "AsyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    beast::async_completion<
        WriteHandler, void(error_code)
            > completion(handler);
    write_frame_op<ConstBufferSequence, decltype(
        completion.handler)>{completion.handler,
            *this, fin, bs};
    return completion.result.get();
}

template<class NextLayer>
template<class ConstBufferSequence>
void
stream<NextLayer>::
write_frame(bool fin, ConstBufferSequence const& buffers)
{
    static_assert(is_SyncStream<next_layer_type>::value,
        "SyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    error_code ec;
    write_frame(fin, buffers, ec);
    if(ec)
        throw system_error{ec};
}

template<class NextLayer>
template<class ConstBufferSequence>
void
stream<NextLayer>::
write_frame(bool fin,
    ConstBufferSequence const& buffers, error_code& ec)
{
    static_assert(is_SyncStream<next_layer_type>::value,
        "SyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    using beast::detail::clamp;
    using boost::asio::buffer;
    using boost::asio::buffer_copy;
    using boost::asio::buffer_size;
    detail::frame_header fh;
    if(! wr_.cont)
    {
        wr_begin();
        fh.rsv1 = wr_.compress;
    }
    fh.rsv2 = false;
    fh.rsv3 = false;
    fh.op = wr_.cont ? opcode::cont : wr_opcode_;
    fh.mask = role_ == detail::role_type::client;
    wr_.cont = ! fin;
    auto remain = buffer_size(buffers);
    if(wr_.compress)
    {
        consuming_buffers<
            ConstBufferSequence> cb{buffers};
        for(;;)
        {
            std::size_t ni;
            std::size_t no;
            std::tie(ni, no) = detail::deflate(pmd_->zo,
                buffer(wr_.buf.get(), wr_.buf_size),
                    cb, fin, ec);
            if(ec == zlib::error::need_buffers)
                ec = {};
            if(ec)
                failed_ = true;
            auto const mb = buffer(wr_.buf.get(), no);
            if(fh.mask)
            {
                fh.key = maskgen_();
                detail::prepared_key key;
                detail::prepare_key(key, fh.key);
                detail::mask_inplace(mb, key);
            }
            fh.fin = fin ? no < wr_.buf_size : false;
            fh.len = no;
            detail::fh_streambuf fh_buf;
            detail::write<static_streambuf>(fh_buf, fh);
            boost::asio::write(stream_,
                buffer_cat(fh_buf.data(), mb), ec);
            failed_ = ec != 0;
            if(failed_)
                return;
            if(no < wr_.buf_size)
                break;
            fh.op = opcode::cont;
            fh.rsv1 = false;
        }
        if(fh.fin && (
            (role_ == detail::role_type::client &&
                pmd_config_.client_no_context_takeover) ||
            (role_ == detail::role_type::server &&
                pmd_config_.server_no_context_takeover)))
            pmd_->zo.reset();
        return;
    }
    if(! fh.mask)
    {
        if(! wr_.autofrag)
        {
            // no mask, no autofrag
            fh.fin = fin;
            fh.len = remain;
            detail::fh_streambuf fh_buf;
            detail::write<static_streambuf>(fh_buf, fh);
            boost::asio::write(stream_,
                buffer_cat(fh_buf.data(), buffers), ec);
            failed_ = ec != 0;
            if(failed_)
                return;
        }
        else
        {
            // no mask, autofrag
            BOOST_ASSERT(wr_.buf_size != 0);
            consuming_buffers<
                ConstBufferSequence> cb{buffers};
            for(;;)
            {
                fh.len = clamp(remain, wr_.buf_size);
                remain -= fh.len;
                fh.fin = fin ? remain == 0 : false;
                detail::fh_streambuf fh_buf;
                detail::write<static_streambuf>(fh_buf, fh);
                boost::asio::write(stream_,
                    buffer_cat(fh_buf.data(),
                        prepare_buffers(fh.len, cb)), ec);
                failed_ = ec != 0;
                if(failed_)
                    return;
                if(remain == 0)
                    break;
                fh.op = opcode::cont;
                cb.consume(fh.len);
            }
        }
        return;
    }
    if(! wr_.autofrag)
    {
        // mask, no autofrag
        fh.fin = fin;
        fh.len = remain;
        fh.key = maskgen_();
        detail::prepared_key key;
        detail::prepare_key(key, fh.key);
        detail::fh_streambuf fh_buf;
        detail::write<static_streambuf>(fh_buf, fh);
        consuming_buffers<
            ConstBufferSequence> cb{buffers};
        {
            auto const n = clamp(remain, wr_.buf_size);
            auto const mb = buffer(wr_.buf.get(), n);
            buffer_copy(mb, cb);
            cb.consume(n);
            remain -= n;
            detail::mask_inplace(mb, key);
            boost::asio::write(stream_,
                buffer_cat(fh_buf.data(), mb), ec);
            failed_ = ec != 0;
            if(failed_)
                return;
        }
        while(remain > 0)
        {
            auto const n = clamp(remain, wr_.buf_size);
            auto const mb = buffer(wr_.buf.get(), n);
            buffer_copy(mb, cb);
            cb.consume(n);
            remain -= n;
            detail::mask_inplace(mb, key);
            boost::asio::write(stream_, mb, ec);
            failed_ = ec != 0;
            if(failed_)
                return;
        }
        return;
    }
    {
        // mask, autofrag
        BOOST_ASSERT(wr_.buf_size != 0);
        consuming_buffers<
            ConstBufferSequence> cb{buffers};
        for(;;)
        {
            fh.key = maskgen_();
            detail::prepared_key key;
            detail::prepare_key(key, fh.key);
            auto const n = clamp(remain, wr_.buf_size);
            auto const mb = buffer(wr_.buf.get(), n);
            buffer_copy(mb, cb);
            detail::mask_inplace(mb, key);
            fh.len = n;
            remain -= n;
            fh.fin = fin ? remain == 0 : false;
            detail::fh_streambuf fh_buf;
            detail::write<static_streambuf>(fh_buf, fh);
            boost::asio::write(stream_,
                buffer_cat(fh_buf.data(), mb), ec);
            failed_ = ec != 0;
            if(failed_)
                return;
            if(remain == 0)
                break;
            fh.op = opcode::cont;
            cb.consume(n);
        }
        return;
    }
}

//------------------------------------------------------------------------------

template<class NextLayer>
template<class Buffers, class Handler>
class stream<NextLayer>::write_op
{
    using alloc_type =
        handler_alloc<char, Handler>;

    struct data : op
    {
        stream<NextLayer>& ws;
        consuming_buffers<Buffers> cb;
        Handler h;
        std::size_t remain;
        bool cont;
        int state = 0;

        template<class DeducedHandler>
        data(DeducedHandler&& h_,
            stream<NextLayer>& ws_, Buffers const& bs)
            : ws(ws_)
            , cb(bs)
            , h(std::forward<DeducedHandler>(h_))
            , remain(boost::asio::buffer_size(cb))
            , cont(boost_asio_handler_cont_helpers::
                is_continuation(h))
        {
        }
    };

    std::shared_ptr<data> d_;

public:
    write_op(write_op&&) = default;
    write_op(write_op const&) = default;

    template<class DeducedHandler, class... Args>
    explicit
    write_op(DeducedHandler&& h,
            stream<NextLayer>& ws, Args&&... args)
        : d_(std::allocate_shared<data>(alloc_type{h},
            std::forward<DeducedHandler>(h), ws,
                std::forward<Args>(args)...))
    {
        (*this)(error_code{}, false);
    }

    void operator()(error_code ec, bool again = true);

    friend
    void* asio_handler_allocate(
        std::size_t size, write_op* op)
    {
        return boost_asio_handler_alloc_helpers::
            allocate(size, op->d_->h);
    }

    friend
    void asio_handler_deallocate(
        void* p, std::size_t size, write_op* op)
    {
        return boost_asio_handler_alloc_helpers::
            deallocate(p, size, op->d_->h);
    }

    friend
    bool asio_handler_is_continuation(write_op* op)
    {
        return op->d_->cont;
    }

    template<class Function>
    friend
    void asio_handler_invoke(Function&& f, write_op* op)
    {
        return boost_asio_handler_invoke_helpers::
            invoke(f, op->d_->h);
    }
};

template<class NextLayer>
template<class Buffers, class Handler>
void
stream<NextLayer>::
write_op<Buffers, Handler>::
operator()(error_code ec, bool again)
{
    auto& d = *d_;
    d.cont = d.cont || again;
    if(! ec)
    {
        switch(d.state)
        {
        case 0:
        {
            auto const n = d.remain;
            d.remain -= n;
            auto const fin = d.remain <= 0;
            if(fin)
                d.state = 99;
            auto const pb = prepare_buffers(n, d.cb);
            d.cb.consume(n);
            d.ws.async_write_frame(fin, pb, std::move(*this));
            return;
        }

        case 99:
            break;
        }
    }
    d.h(ec);
}

template<class NextLayer>
template<class ConstBufferSequence, class WriteHandler>
typename async_completion<
    WriteHandler, void(error_code)>::result_type
stream<NextLayer>::
async_write(ConstBufferSequence const& bs, WriteHandler&& handler)
{
    static_assert(is_AsyncStream<next_layer_type>::value,
        "AsyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    beast::async_completion<
        WriteHandler, void(error_code)> completion(handler);
    write_op<ConstBufferSequence, decltype(completion.handler)>{
        completion.handler, *this, bs};
    return completion.result.get();
}

template<class NextLayer>
template<class ConstBufferSequence>
void
stream<NextLayer>::
write(ConstBufferSequence const& buffers)
{
    static_assert(is_SyncStream<next_layer_type>::value,
        "SyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    error_code ec;
    write(buffers, ec);
    if(ec)
        throw system_error{ec};
}

template<class NextLayer>
template<class ConstBufferSequence>
void
stream<NextLayer>::
write(ConstBufferSequence const& buffers, error_code& ec)
{
    static_assert(is_SyncStream<next_layer_type>::value,
        "SyncStream requirements not met");
    static_assert(beast::is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence requirements not met");
    write_frame(true, buffers, ec);
}

//------------------------------------------------------------------------------

} // websocket
} // beast

#endif
