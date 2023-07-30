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
package com.draper.application;

import java.io.File;
import java.io.Reader;
import java.sql.Driver;
import java.sql.DriverManager;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import com.draper.poller.PollManager;
import com.draper.services.c2.C2Services;
import com.draper.services.corpus.CorpusServices;
import com.draper.services.database.DatabaseService;
import com.draper.utilities.Logger;
import com.draper.utilities.UiUtil;
import com.ibatis.common.resources.Resources;
import com.ibatis.sqlmap.client.SqlMapClientBuilder;

public class AppStartStopListener implements ServletContextListener
{
    /**
     * Called when the web application starts up.
     */
    public void contextInitialized(ServletContextEvent sce)
    {
        try
        {         
            //---------------------------------------------------------------------------------------
            // Get the Base Path of the WebService 

            AppConfig.webservicePath = new File(sce.getServletContext().getRealPath("/")).getParentFile().getAbsolutePath();
            
            //---------------------------------------------------------------------------------------          
            // Get the Directory where the WebService will store its files
            
            AppConfig.storagePath = sce.getServletContext().getInitParameter("storagePath");
            
            if( true == AppConfig.storagePath.trim().isEmpty() )
            {
                AppConfig.storagePath = AppConfig.webservicePath;
            }
           
            //---------------------------------------------------------------------------------------
            // Initialize the SQL map 
            
            Reader       reader  = Resources.getResourceAsReader(AppConfig.sqlMapConfig);
            AppConfig.sqlMap     = SqlMapClientBuilder.buildSqlMapClient(reader);

            DatabaseService.Instance().Init(AppConfig.sqlMap);  
            
            //---------------------------------------------------------------------------------------
            // Initialize the Logger.
            
            String  stdoutEchoProp  = UiUtil.notNull(DatabaseService.Instance().getProperty("use.stdout"));         
            String logfileBaseName  = AppConfig.storagePath + File.separator + "logs" + File.separator + sce.getServletContext().getInitParameter("logFileBaseName");
            
            Logger.initialize( logfileBaseName, new Date(), Boolean.parseBoolean(stdoutEchoProp) );

            //---------------------------------------------------------------------------------------
            // Initialize Corpus Service that will handle all the cluster and test case storage
                   
           
            CorpusServices.Instance().Initialize(AppConfig.storagePath);
                
            //---------------------------------------------------------------------------------------
            // Install Pollers
            
            PollManager.Instance().Init(1,5); // One Thread, Five Second Delay Startup

            PollManager.Instance().InstallPoller(C2Services.Instance(), 1, TimeUnit.SECONDS);

            //---------------------------------------------------------------------------------------          
            // Web Server and WebService Identification Information

            AppConfig.serverIdentificationInfo     = sce.getServletContext().getServerInfo();
            AppConfig.webServiceIdentificationInfo = sce.getServletContext().getServletContextName() + " Release " + AppConfig.softwareVersion;

            // Print the information we will use to initialize the system
            Logger.println(this, "Server Id  : " + AppConfig.serverIdentificationInfo);
            Logger.println(this, "WebService : " + AppConfig.webServiceIdentificationInfo);
            Logger.println(this, "Log        : " + Logger.getLogFileName());
            Logger.println(this, "Storage    : " + AppConfig.storagePath);
            Logger.println(this, "WebRoot    : " + AppConfig.webservicePath);
            Logger.println(this, "Use Stdout : " + Boolean.parseBoolean(stdoutEchoProp));                    
            Logger.println(this, "WebService Initialized.");                 
        }
        catch (Exception e)
        {
            Logger.println(this, "WebService Failed to Initialize: " + AppConfig.webServiceIdentificationInfo);
            e.printStackTrace();
        }
    }

    /**
     * Called when the web application is stopped or undeployed.
     */
    public void contextDestroyed(ServletContextEvent sce)
    {
        try
        {
            Logger.println(this, "WebService Shutting Down");
            
            PollManager.Instance().Stop();
            
            // DeRegister JDBC driver
            Enumeration<Driver> drivers = DriverManager.getDrivers();

            while (drivers.hasMoreElements())
            {
                Driver driver = drivers.nextElement();

                try
                {
                    DriverManager.deregisterDriver(driver);
                    Logger.println(this, "Deregistering jdbc driver: " + driver);
                }
                catch (Exception e)
                {
                    Logger.println(this, "Error deregistering driver: " + driver);
                }
            }

            // Complete the Logging
            Logger.println(this, "WebService Stopped");
            Logger.close();
        }
        catch (Exception e)
        {
            Logger.println(e.toString());
        }
    }
}
