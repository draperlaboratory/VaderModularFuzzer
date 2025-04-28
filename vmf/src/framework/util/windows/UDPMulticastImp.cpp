
/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (only) as 
 * published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 * @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
 * ===========================================================================*/
#include "UDPMulticastImp.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"


using namespace vmf;

UDPMulticastAPI* UDPMulticastAPI::instance()
{
    return new UDPMulticastImp();
}

UDPMulticastImp::UDPMulticastImp()
{
    memset(&fd, 0, sizeof(fd));
    memset(&addr, 0, sizeof(addr));
    memset(&mreq, 0, sizeof(mreq));
}

UDPMulticastImp::~UDPMulticastImp()
{

}

void UDPMulticastImp::buildSocket(std::string address, int port)
{

    //Based on https://gist.github.com/hostilefork/f7cae3dc33e7416f2dd25a402857b6c6

    const char* group = address.c_str();

    // create what looks like an ordinary UDP socket
    //
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERROR << "Socket() error code:" << WSAGetLastError();
        throw RuntimeException("Error creating socket", RuntimeException::OTHER);
    }

    // allow multiple sockets to use the same PORT number
    //
    unsigned int yes = 1;
    if (
        setsockopt(
            fd, SOL_SOCKET, SO_REUSEADDR, (char*) &yes, sizeof(yes)
        ) < 0
    ){
       LOG_ERROR << "setsockopt error code:" << WSAGetLastError();
       throw RuntimeException("Error reusing socket address", RuntimeException::OTHER);
    }

    // set up destination address
    //
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // differs from sender
    addr.sin_port = htons(port);

    // bind to receive address
    //
    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        LOG_ERROR << "bind error code:" << WSAGetLastError();
        throw RuntimeException("Error binding socket", RuntimeException::OTHER);
    }

    // use setsockopt() to request that the kernel join a multicast group
    //
    
    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (
        setsockopt(
            fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)
        ) < 0
    ){
        LOG_ERROR << "setsockopt error code:" << WSAGetLastError();
        throw RuntimeException("Error setting socket options", RuntimeException::OTHER);
    }

    //Set to non-blocking mode
    unsigned long nonBlocking = 1;

    int status = ::ioctlsocket(fd, FIONBIO, &nonBlocking);

    if (status < 0)
    {
        LOG_ERROR << "ioctlsocket error code:" << WSAGetLastError();
        throw RuntimeException("Error setting socket to non-blocking", RuntimeException::OTHER);
    }

}

int UDPMulticastImp::readData(char* msgbuf, int size)
{
    int addrlen = sizeof(addr);
    int nbytes = recvfrom(
        fd,
        msgbuf,
        size,
        0,
        (struct sockaddr *) &addr,
        (socklen_t*)&addrlen
    );

    if (nbytes < 0) 
    {

        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK)
        {
            LOG_ERROR << "Socket error code:" << error;
            throw RuntimeException("Error reading from socket", RuntimeException::OTHER);
        }
        else
        {
            nbytes = 0;
        }
    }

    return nbytes;
}



