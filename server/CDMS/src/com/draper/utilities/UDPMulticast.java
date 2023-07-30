/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
 *  
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * Is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *  
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
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
package com.draper.utilities;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import java.net.DatagramPacket;

/**********************************************************************************************
 * 
 *
 */
public class UDPMulticast
{    
   /**********************************************************************************************
     * 
     * @param host
     * @param port
     */
    public static void Broadcast(String broadcastMessage) throws Exception 
    {        
        MulticastSocket dSocket = null;
        
        try
        {
            dSocket = new MulticastSocket();    
                      
            byte[]         buffer  = broadcastMessage.getBytes();                               
            DatagramPacket packet  = new DatagramPacket(buffer, buffer.length, InetAddress.getByName("237.255.255.255"), 8888);    
                
            dSocket.send(packet);                        
        }
        catch( Exception e )
        {
            Logger.println( e );
        }
        finally
        {
            dSocket.close();
        }
   }
    
    
    /**********************************************************************************************
     * 
     * @param host
     * @param port
     */
    public static String Listen() throws Exception 
    {
        MulticastSocket     cSocket     = null;
        String              data        = null;
        InetAddress         mcastaddr   = InetAddress.getByName("237.255.255.255");
        InetSocketAddress   group       = new InetSocketAddress(mcastaddr, 8888);
        NetworkInterface    netIf       = NetworkInterface.getByIndex(0);
       
        try
        {            
            cSocket = new MulticastSocket(8888);
            cSocket.joinGroup(new InetSocketAddress(mcastaddr, 0), netIf);
            
            Logger.println( ">>>Listening for multicast packets");

            // Receive a packet
            byte[]         recvBuf  = new byte[200];
            DatagramPacket packet   = new DatagramPacket(recvBuf, recvBuf.length);
            
            cSocket.receive(packet);

            byte[] messageBytes  = new byte[packet.getLength()];     
            
            for( int i = 0; i < messageBytes.length; i ++ )
            {
                messageBytes[i] = packet.getData()[i];
            }
            
            data = new String(messageBytes);
            
            // Packet received
            Logger.println( ">>>Packet received from:  " + packet.getAddress().getHostAddress());
            Logger.println( ">>>Packet received data:  " + data + " :" + data.length() );
        }
        catch (IOException ex)
        {
            Logger.println( ex );
        }
        finally
        {
            cSocket.leaveGroup(group, netIf);
            cSocket.close();
        }
        
        return data;
    }
    
    
    /**********************************************************************************************
     * 
     * @param host
     * @param port
     */
    public static List<InetAddress> listAllBroadcastAddresses() throws SocketException
    {
        List<InetAddress>               broadcastList   = new ArrayList<>();
        Enumeration<NetworkInterface>   interfaces      = NetworkInterface.getNetworkInterfaces();
        
        while (interfaces.hasMoreElements())
        {
            NetworkInterface networkInterface = interfaces.nextElement();

            if (networkInterface.isLoopback() || !networkInterface.isUp())
            {
                continue;
            }

            networkInterface.getInterfaceAddresses().stream().map(a -> a.getBroadcast()).filter(Objects::nonNull).forEach(broadcastList::add);
        }
        
        return broadcastList;
    }  
}
