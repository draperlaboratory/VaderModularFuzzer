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
#pragma once
#include <string>

namespace vmf {
/**
 * @brief Wrapper class to encapsulate UDP Multicast functionality.
 * 
 */
class UDPMulticastAPI
{
    public:
        /**
         * @brief Returns a UDP multicast socket instance
         * buildSocket must be called on the instance to configure it prior to use
         * 
         * @return UDPMulticastAPI* the instance
         */
        static UDPMulticastAPI* instance();

        UDPMulticastAPI() {};

        /**
         * @brief Configures the socket
         * This must be called prior to readData
         * 
         * @param address the address of the host
         * @param port the port to use
         */
        virtual void buildSocket(std::string address, int port) = 0;

        /**
         * @brief Reads data from the socket.
         * 
         * @param msgbuf the message buffer to read into
         * @param size the size of msgbuf
         * @return int the number of bytes read (0 if there was no data)
         */
        virtual int readData(char* msgbuf, int size) = 0;

        virtual ~UDPMulticastAPI() {};
};
}