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
import java.util.ArrayList;
import java.util.LinkedList;
import java.lang.reflect.Type;
import com.google.gson.Gson;

/**
 * @author sjd3078
 *
 **/
public final class JSONParser<T>
{    
    /***********************************************************************************
     * Convert Generic <T> to JSON
     */
    public String toJSON(T obj) throws Exception
    {
        String json = null;
        
        try
        {
            Gson gson    = new Gson();
                 json    = gson.toJson(obj);         
        }
        catch(Exception ioe)
        {
            ioe.printStackTrace();
        }
        
        return json;
    }
    
    /**********************************************************************************************
     * Get Generic <T> from a JSON representation
     * 
     * @throws IOException
     */
    public T fromJSON(String json, Class<T> t) throws IOException
    {
        Gson gson   = new Gson();
        T    obj    = (T)gson.fromJson(json, t );
    
        return obj;
    }
    
    /**********************************************************************************************
     * Get Generic <T> from a JSON representation
     * 
     * @throws IOException
     */
    public LinkedList<T> fromJSONArray(String json, Type listType) throws IOException
    {
        Gson            gson        = new Gson();
        LinkedList<T>   obj         = (LinkedList<T>)gson.fromJson(json, listType);
    
        return obj;
    }
    
    /**********************************************************************************************
     * Get Generic <T> from a JSON representation
     * 
     * @throws IOException
     */
    public String toJSONArray(ArrayList<T> obj, Type listType) throws IOException
    {
        Gson    gson        = new Gson();
        String  json        = gson.toJson(obj, listType);
    
        return json;
    }
}
