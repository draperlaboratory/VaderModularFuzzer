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
package com.draper.extensions;

import java.lang.reflect.Constructor;
import com.draper.utilities.Logger;

/*******************************************************************
 * Provides Extension Services
 */
public class ExtensionManager
{
	private static final ExtensionManager 	instance 	     = new ExtensionManager();
    private              SystemExtension    systemExtension  = null;
    
	/**
	 * Instance pattern for singleton
	 *
	 */
 	static public ExtensionManager Instance()
	{		
		return instance;
	}
	
 	
    /********************************************************************************************************************
     * 
     *
    */ 
    public SystemExtension getSystemExtension() throws Exception
    {
        if( null == systemExtension )
        {
            try
            {
                String      className                        = "com.draper.extensions.SystemExtension";
                Class<?>    theImpClass                      = (Class<?>)Class.forName( className ); 
                Constructor<SystemExtension> theConstructor  = (Constructor<SystemExtension>)theImpClass.getConstructor();
                this.systemExtension                         = theConstructor.newInstance();
            }
            catch( Exception e )
            {   
                Logger.println( "Customer Extension Class Loading error: " + e );
                throw(e);
            }
        }
        
        return systemExtension;    
    }   
}
