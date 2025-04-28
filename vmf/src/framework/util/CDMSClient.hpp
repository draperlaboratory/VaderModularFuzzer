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
#include "ConfigInterface.hpp"
#include "StorageModule.hpp"
#include "UDPMulticastAPI.hpp"
#include "json11.hpp"
#include "restclient-cpp/restclient.h"
#include "restclient-cpp/connection.h"
#include <chrono>

namespace vmf
{
    
/**
 * @brief Singleton class to encapsulated the client behaviors to interact with the CDMS server
 * 
 * The init() method must be called to setup the connection to the CDMS server prior to using
 * any other methods.
 * 
 */
class CDMSClient
{
    public:
        //struct sockaddr_in addr;
        //struct ip_mreq mreq;

        /**
         * @brief The list of valid statuses for a vmf client
         * 
         */
        enum StatusType
        {
            TASKED          = 1021,
            RUNNING         = 1022,
            FAILED          = 1023,
            IDLE            = 1024,
            UNREGISTER      = 1025,
            PAUSED          = 1026
        };

        /**
         * @brief The valid command codes that can be sent from the server
         * 
         */
        enum CmdType
        {
            NEW_CORPUS = 2022,
            RESTART = 2023,
            SHUTDOWN = 2024,
            STOP = 2025,
            PAUSE = 2026
        };
        
        static CDMSClient*      getInstance();
        void                    init(ConfigInterface& config, int pid, std::string name, std::string hostname);
        std::string             getHostname();
        std::string             getName();
        int                     getPid();
        int                     getClusterId();
        int                     getScenarioId();
        int                     getUniqueId();
        bool                    sendRegistration(bool taskingComplete);
        void                    sendKPI(json11::Json metrics);
        json11::Json            getTasking();
        json11::Json            getCorpusInitialSeeds(std::string tags, bool getMinCorpus);
        std::string             getConfigFile(std::string file);
        std::string             getCorpusFile(std::string file);
        void                    requestCorpusSync(std::vector<std::string> files, bool atClusterLevel);
        void                    requestPauseFuzzers();
        void                    sendRegistrationStatus(CDMSClient::StatusType status, std::string reason);
        std::vector<int>        getCommands();
        void                    sendTestCase(char* buff, int size, std::string tags);
        void                    sendTestCases(std::unique_ptr<Iterator>& entriesToSend, std::vector<std::string> tags, int testCaseKey);
        json11::Json            getCorpusUpdates(std::string tags);
        json11::Json            getCorpus(std::string tags);

        std::string formatTagList(std::vector<std::string> tags);

    private:
        void buildSocket();
        int readMulticast(char* msgbuf, int size);
        void createNewTestCasesFromJsonImpl(StorageModule& storage, json11::Json json, int testCaseKey, int serverTestCaseTag, int fileNameKey, bool useFilename);

        std::string             doGet(std::string url);
        std::string             doPost(std::string url, std::string json);
        std::string             doBinaryPost(std::string url, char* buff, int size);
        std::string             doBinaryPost(std::string url, char* buff, int size, std::string key, std::string value);

        CDMSClient();
        ~CDMSClient();
        CDMSClient(CDMSClient const&)       = delete;
        void operator=(CDMSClient const&)   = delete;

        std::string registerURL;       
        std::string statusURL;
        std::string kpiURL;
        std::string taskingURL;
        std::string seedsURL;
        std::string storeTestcaseURL;
        std::string configFileURL;
        std::string corpusFileURL;
        std::string corpusUpdateURL;
        std::string corpusSyncURL;
        std::string corpusPauseURL;
        std::string lastCorpusUpdateTimestamp;

        std::string hostname = "none";
        std::string name = "none";
        static const int UNDEFINED = -1;
        int         uid = UNDEFINED;
        int         pid = UNDEFINED;
        int        scenarioid = UNDEFINED;
        int         clusterid = UNDEFINED;

        std::chrono::milliseconds retryTime;
        int retryCount = -1;

        std::string tmpDir;
        std::string serverURL;
        std::string proxyURL;

        UDPMulticastAPI* udpSocket;
        RestClient::Connection* conn;
};

}