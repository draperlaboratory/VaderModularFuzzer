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

#include "CDMSClient.hpp"
#include "json11.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include "restclient-cpp/restclient.h"
#include "restclient-cpp/connection.h"
#include <chrono>
#include <thread>

#ifdef _WIN32
    #include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
    #include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
    #include <Windows.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <time.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using namespace vader;

/**
 * @brief Construct a new CDMSClient object
 * The constructor is private.  All access should be through getInstance().
 */
CDMSClient::CDMSClient()
{
#ifdef _WIN32
    //
    // Initialize Windows Socket API with given VERSION.
    //
    WSADATA wsaData;
    if (WSAStartup(0x0101, &wsaData)) 
    {
        perror("WSAStartup");
        return;
    }
#endif
}

/**
 * @brief Destroy the CDMSClient object
 * 
 */
CDMSClient::~CDMSClient()
{
    #ifdef _WIN32
    WSACleanup();
    #endif
}

/**
 * @brief Retrieve the one singleton instance of CDMSClient
 * 
 * @return CDMSClient* the instance
 */
CDMSClient* CDMSClient::getInstance()
{
    static CDMSClient instance; 
    return &instance;
}

/**
 * @brief Initialize the CDMS client.  Must be called before other methods
 * 
 * @param config the config interface to read configuration parameters from
 * @param pid the pid of the fuzzer
 * @param name the name of the fuzzer
 * @param hostname the hostname of the local computer
 */
void CDMSClient::init(ConfigInterface& config, int pid, std::string name, std::string hostname)
{
    //Store these parameters for later use
    this->pid = pid;
    this->name = name;
    this->hostname = hostname;

    // Initialize the Rest Interface
    if( 0 != RestClient::init() )
    {
        LOG_ERROR << "Rest Client Failed to Initialize";
    }

    //Get webserver parameters
    std::string serverURL = config.getStringParam(ConfigInterface::VMF_DISTRIBUTED_KEY,"serverURL");

    //Get timeout parameters   
    int rt = config.getIntParam(ConfigInterface::VMF_DISTRIBUTED_KEY,"retryTimeout",30000); //30s
    retryTime = std::chrono::milliseconds(rt);
    retryCount = config.getIntParam(ConfigInterface::VMF_DISTRIBUTED_KEY,"retryCount",10); //10 tries

    // Build all the Restful paths

    LOG_INFO << "Using server URL: " << serverURL;

    registerURL      = serverURL + "/CDMS/registration/register/";
    statusURL        = serverURL + "/CDMS/registration/status/";
    configFileURL    = serverURL + "/CDMS/registration/file/";
    taskingURL       = serverURL + "/CDMS/registration/tasking/";
    seedsURL         = serverURL + "/CDMS/corpus/seeds/";
    corpusFileURL    = serverURL + "/CDMS/corpus/file/";
    storeTestcaseURL = serverURL + "/CDMS/corpus/store/";
    corpusUpdateURL  = serverURL + "/CDMS/corpus/retrieve/";
    corpusSyncURL    = serverURL + "/CDMS/corpus/sync/";
    corpusPauseURL   = serverURL + "/CDMS/corpus/pause/";
    kpiURL           = serverURL + "/CDMS/kpi/update/";

    buildSocket();

    //The initial timestamp should be 0
    lastCorpusUpdateTimestamp = "0";

}
/**
 * @brief Build the C2 Multicast Socket
 *
 */
void CDMSClient::buildSocket()
{
    //Based on https://gist.github.com/hostilefork/f7cae3dc33e7416f2dd25a402857b6c6

    std::string addrString = "237.255.255.255"; 
    const char* group = addrString.c_str();
    int port = 8888;

    // create what looks like an ordinary UDP socket
    //
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw RuntimeException("Error creating socket", RuntimeException::OTHER);
    }

    // allow multiple sockets to use the same PORT number
    //
    u_int yes = 1;
    if (
        setsockopt(
            fd, SOL_SOCKET, SO_REUSEADDR, (char*) &yes, sizeof(yes)
        ) < 0
    ){
       throw RuntimeException("Error reusing socket address", RuntimeException::OTHER);
    }

    // set up destination address
    //
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // differs from sender
    addr.sin_port = htons(port);

    // bind to receive address
    //
    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
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
        throw RuntimeException("Error setting socket options", RuntimeException::OTHER);
    }

#ifdef _WIN32

    unsigned long nonBlocking = 1;

    int status = ::ioctlsocket(fd, FIONBIO, &nonBlocking);

    if (status < 0)
    {
        throw RuntimeException("Error setting socket to non-blocking", RuntimeException::OTHER);
    }

#else
    //Set to non-blocking mode
    int status = fcntl( fd, F_SETFL, O_NONBLOCK | O_NDELAY );
    if(status < 0)
    {
        throw RuntimeException("Error setting socket to non-blocking", RuntimeException::OTHER);
    }

#endif
}

/**
 * @brief Helper method to read from the multicast socket
 * 
 * This is used to support command handling.
 * 
 * @param msgbuf the buffer to read into
 * @param size the maximum allowable size
 * @return int the number of bytes read (this is 0 if there are none)
 * @throws RuntimeException if an error is encountered while reading from the socket
 */
int CDMSClient::readMulticast(char* msgbuf, int size)
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
#ifdef _WIN32

        if (WSAGetLastError() != WSAEWOULDBLOCK)
        {
            throw RuntimeException("Error reading from socket", RuntimeException::OTHER);
        }
        else
        {
            nbytes = 0;
        }
#else

        if (EWOULDBLOCK != errno )
        {
            throw RuntimeException("Error reading from socket", RuntimeException::OTHER);
        }
        else
        {
            nbytes = 0;
        }
#endif

    }

    msgbuf[nbytes] = '\0';

    return nbytes;
}

/**
 * @brief Helper method to perform an http get at the provided URL
 * 
 * @param url the URL to get from
 * @return std::string the response that was returned from the server
 * @throws RuntimeException if the server returns an error message
 */
std::string CDMSClient::doGet(std::string url)
{
    bool done = false;
    RestClient::Response r;
    char err[512] = "CMDS Connection failed"; //Typically overwritten below
    int count = 0;

    while((!done)&&(count < retryCount))
    {
        count++;
        r = RestClient::get(url);
        if(200 != r.code)
        {
            sprintf(err, "Get from Server Failed Code = %d (%s)", r.code, url.c_str());
            LOG_ERROR << err;
            LOG_ERROR << "Failed Message Body:" << r.body;
            std::this_thread::sleep_for(retryTime);
        }
        else
        {
            done = true;
        }
    }

    if (!done)
    {
        throw RuntimeException(err, RuntimeException::SERVER_ERROR);
    }

    return r.body;
}

/**
 * @brief Helper method to perform an http post to the provided URL
 * 
 * This version of the method does the post in application/json format.
 * 
 * @param url the URL to post to
 * @param json the json payload to provide in the post message
 * @return std::string the response that was returned from the server
 * @throws RuntimeException if the server returns an error message
 */
std::string CDMSClient::doPost(std::string url, std::string json)
{
    bool done = false;
    std::string response = "CMDS Connection failed";  //Typically overwritten below
    char err[512];
    int count = 0;

    while((!done)&&(count < retryCount))
    {
        count++;
        RestClient::Response r = RestClient::post(url, "application/json", json);
        if(200 != r.code)
        {
            sprintf(err, "Posting to Server Failed Code = %d; (%s)", r.code, url.c_str());
            LOG_ERROR << err;
            LOG_ERROR << "Failed Message Body:" << r.body;
            std::this_thread::sleep_for(retryTime);
        }
        else
        {
            done = true;
            response = r.body;
        }
    }

    if (!done)
    {
        throw RuntimeException(err, RuntimeException::SERVER_ERROR);
    }

    return response;
}

/**
 * @brief Helper method to perform an http post to the provided URL
 * 
 * This version of the method does the post in application/binary format
 * 
 * @param url the URL to post to
 * @param buff the binary payload to post
 * @param size the size of the payload
 * @return std::string the response that was returned from the server
 * @throws RuntimeException if the server returns an error message
 */
std::string CDMSClient::doBinaryPost(std::string url, char* buff, int size)
{
    std::string data(buff, size);
    std::string response = "";
    bool done = false;
    char err[512] = "CMDS Connection failed";  //Typically overwritten below
    int count = 0;

    while((!done)&&(count < retryCount))
    {
        count++;
        RestClient::Response r = RestClient::post(url, "application/binary", data);
        if(200 != r.code)
        {
            sprintf(err, "Posting to Server Failed Code = %d; (%s)", r.code, url.c_str());
            LOG_ERROR << err;
            LOG_ERROR << "Failed Message Body:" << r.body;
            std::this_thread::sleep_for(retryTime);
        }
        else
        {
            done = true;
            response = r.body;
        }
    }

    if (!done)
    {
        throw RuntimeException(err, RuntimeException::SERVER_ERROR);
    }

    return response;
}

/**
 * @brief Helper method to perform an http post to the provided URL with an added parameter
 * 
 * This version of the method does the post in application/binary format, and adds
 * an additional header parameter using the provided key/value pair
 * 
 * @param url the URL to post to
 * @param buff the binary payload to post
 * @param size the size of the payload
 * @param key the key for the header parameter
 * @param value the value for the header parameter
 * @return std::string the response that was returned from the server
 * @throws RuntimeException if the server returns an error message
 */
std::string CDMSClient::doBinaryPost(std::string url, char* buff, int size, std::string key, std::string value)
{
    bool done = false;
    int count = 0;
    std::string data(buff, size);
    char err[512] = "CMDS Connection failed"; //Typically overwritten below
    std::string response = "";

    while((!done)&&(count < retryCount))
    {
        count++;
        RestClient::Connection* conn = new RestClient::Connection(url);
        RestClient::HeaderFields headers;

        conn->SetHeaders(headers);
        conn->AppendHeader("Content-Type", "application/binary");
        conn->AppendHeader(key, value);
        RestClient::Response r = conn->post("/post", data);
        if(200 != r.code)
        {
            sprintf(err, "Posting to Server Failed Code = %d; (%s)", r.code, url.c_str());
            LOG_ERROR << "Failed Message Body:" << r.body;
            LOG_ERROR << err;
            std::this_thread::sleep_for(retryTime);
        }
        else
        {
            done = true;
            response = r.body;
        }
        delete conn;
    }

    if (!done)
    {
        throw RuntimeException(err, RuntimeException::SERVER_ERROR);
    }

    return response;
}

/**
 * @brief Helper method to send the registration message to the CDMS
 *
 * @param taskingComplete when true, this indicates to the server that the VMF is registering
 * because it has just completed it's tasking (as opposed to having been asked to stop).  This
 * is false for initial tasking or re-tasking after a stop command.
 */
bool CDMSClient::sendRegistration(bool taskingComplete)
{
    std::string err;

    int flag = 0;
    if(taskingComplete)
    {
        flag = 1;
    }

    json11::Json json = json11::Json::object
    {
        { "uid", uid },
        { "pid", pid },
        { "host", std::string(hostname)},
        { "name", name },
        { "taskingComplete", flag}
    };

    // Send Registration Request

    std::string response = this->doPost(registerURL, json.dump());
    auto regResp         = json11::Json::parse(response, err);

    if (!err.empty())
    {
        LOG_ERROR << "JSON parsing error: " << err;

        return false;
    }

    // Store the Values Received
    uid = regResp["uid"].int_value();
    clusterid = UNDEFINED;
    scenarioid = UNDEFINED;

    return true;
}

/**
 * @brief Helper method to send a status message to CDMS
 *
 * @param status the status to write
 * @param reason the reason for the status change (mostly useful for errors)
 */
void CDMSClient::sendRegistrationStatus(CDMSClient::StatusType status, std::string reason)
{
    LOG_INFO << "Sending status message: " << status;

    json11::Json json = json11::Json::object
    {
        { "uid", uid },
        { "status", status},
        { "reason", reason }
    };

    std::string response = this->doPost(statusURL, json.dump());

    return;
}

/**
 * @brief Helper method to send key performance metrics message to CDMS
 *
 * @param metrics the metrics to send
 */
void CDMSClient::sendKPI(json11::Json metrics)
{
    std::string response = this->doPost(kpiURL, metrics.dump());

    return;
}

/**
 * @brief Helper method to look for a tasking assignment for this client
 *
 * If the response message for this pid/hostname pair is found, then the configuration
 * values are written to the CDMSClient.  A value of false means
 * that the message was not found and the caller should try again later.
 *
 * @return true if the registration response message is found
 * @return false otherwise
 */
json11::Json CDMSClient::getTasking()
{
    std::string err;

    //Send Registration Request 

    std::string response = this->doGet(taskingURL + std::to_string(uid));
    auto tasking         = json11::Json::parse(response, err);

    if (!err.empty() )
    {
        LOG_ERROR << "JSON parsing error: " << err;
        throw RuntimeException("Unable to parse Tasking Message", RuntimeException::SERVER_ERROR);
    }

    // Retrieve high level data values from the parsed json
    int cluster   = tasking["clusterId"].int_value();
    int scenario  = tasking["scenarioId"].int_value();
    int status    = tasking["status"].int_value();

    //Check to see if this instance has been tasked to do something yet
    if (status == StatusType::TASKED)
    {
        //If this instance has been tasked, store the scenario/cluster values
        clusterid = cluster;
        scenarioid = scenario;
    }
    else
    {
        tasking = nullptr;
    }

    return tasking;
}

/**
 * @brief Helper method to retrieve the seeds for this client
 * This will either be a set of initial seed files or some portion of
 * a recently minimized common corpus.  The server will know which seeds
 * the VMF client should uses.
 * @param tags if the server sends a portion of the minimized corpus, it needs
 * to know which tags the VMF client is interested in.
 * @param getMinCorpus if true, the server will return the minimized corpus, if there
 * is one.  If false, or there is not minimized corpus, the server will return the initial
 * seeds instead.
 */
json11::Json CDMSClient::getCorpusInitialSeeds(std::string tags, bool getMinCorpus)
{
    std::string err;
    std::string flag = "false";

    //Send Seed Request 
    if(getMinCorpus)
    {
        flag = "true";
    }

    std::string response = this->doGet(seedsURL + std::to_string(scenarioid) + "?tags=" + tags +"&getMinCorpus=" + flag);
    auto        seeds    = json11::Json::parse(response, err);

    if (!err.empty())
    {
        LOG_ERROR << "JSON parsing error: " << err;
        throw RuntimeException("Unable to parse list of seeds", RuntimeException::SERVER_ERROR);
    }

    return seeds;
}


/**
* @brief Helper method to retrieve a config file
*
*/
std::string CDMSClient::getConfigFile(std::string file)
{
    LOG_DEBUG << "Getting Configuration file from URL: " << file;

    std::string data = doGet(configFileURL + std::to_string(uid) + "/" + file );

    return data;  
}


/**
* @brief Helper method to retrieve a corpus file
*
*/
std::string CDMSClient::getCorpusFile(std::string file)
{
    LOG_DEBUG << "Getting Corpus file from URL: " << file;

    std::string data = doGet(corpusFileURL + file);
    
    return data;
}

/**
 * @brief Helper method to request a corpus sync
 * 
 * This method is used in conjunction with requestPauseFuzzers to perform server
 * based corpus minimization.  The expected workflow is that the vmf that is performing
 * minimization will first pause the other fuzzing scenarios in the cluster, then
 * minimize, and then request corpus sync to indicate that minimization is complete and the
 * other fuzzers can be RESUMED (at which point they retrieve the newly minimized corpus).
 * 
 * @param files the list of files that should be used in the common corpus
 * @param atClusterLevel when true, request that the common corpus be pushed to the
 * entire cluster, when false, request only for the current scenario
 */
void CDMSClient::requestCorpusSync(std::vector<std::string> files, bool atClusterLevel)
{
    LOG_INFO << "Requesting corpus sync -- new corpus is of size " << files.size();

    json11::Json json = json11::Json::object
    {
        { "files", files }
    };

    LOG_INFO << "ABOUT TO SEND FILE LIST: " << json.dump();

    if(atClusterLevel)
    {
        //Request sync for the current cluster
        this->doPost(corpusSyncURL + std::to_string(uid) + "/" + std::to_string(clusterid),json.dump());
    }
    else
    {
        //Request sync for the current scenario
        this->doPost(corpusSyncURL + std::to_string(uid) + "/" + std::to_string(clusterid) + "/" + std::to_string(scenarioid),json.dump());
    }

}

/**
 * @brief Helper method to request the the other fuzzers in the cluster be paused
 * 
 * This is use in conjuction with requestCorpusSync to perform corpus minimization.
 * The VMF Fuzzer that wants to perform minimization should call this method prior
 * to performing minimization.  This method will send a PAUSE command to each VMF
 * scenario in the cluster that is of type "Fuzzer".
 * 
 */
void CDMSClient::requestPauseFuzzers()
{
    LOG_INFO << "Requesting pause all fuzzer scenarios";
    doGet(corpusPauseURL + std::to_string(clusterid));
}

/**
 * @brief Retrieve the list of current commands for this client
 * The caller is responsible for checking that the returned cmd ids
 * are valid commands, by comparing them with the valid command ids
 * in the enum CDMSClient::CmdType
 * 
 * @return std::vector<int> 
 */
std::vector<int> CDMSClient::getCommands()
{
    std::vector<int> cmdList;
    std::string err;

    char buff[1024];
    int read = readMulticast(buff, 1024);
    while(read>0)
    {
        std::string response(buff);
        
        auto cmd = json11::Json::parse(response, err);

        if (!err.empty())
        {
            LOG_ERROR << "JSON parsing error: " << err;
            throw RuntimeException("Unable to parse list of commands", RuntimeException::SERVER_ERROR);
        }
        else
        {
            int msgId = cmd["commandId"].int_value();
            int cid = cmd["clusterId"].int_value();
            int sid = cmd["scenarioId"].int_value();
            int uniqueid = cmd["uid"].int_value();

            //The cluster id, scenario id, and uniqueid must either match
            //the current values or be 0 (cluster or scenario wide command)
            //Otherwise this is someone else's command.
            if(((cid == clusterid)||(cid == 0))&&
               ((sid == scenarioid)||(sid == 0))&&
               ((uniqueid == uid)||(uniqueid == 0)))
            {
                LOG_DEBUG << "Received Command (my cid=" << clusterid << ", my sid="<< scenarioid <<", my uid=" << uid << "):" << msgId;
                cmdList.push_back(msgId);
            }
            else
            {
                LOG_DEBUG << "Not my command" << cmd.dump();
            }
        }

        //Check for another message
        read = readMulticast(buff, 1024);
    }

    return cmdList;
}

/**
 * @brief Sends an interesting test case to the server to add to the common corpus
 * 
 * @param buff the test case buffer
 * @param size the size of the test case (in bytes)
 * @param tags the list of tags associated with this test case
 */
void CDMSClient::sendTestCase(char* buff, int size, std::string tags)
{
    std::string fullURL  = storeTestcaseURL + std::to_string(clusterid) + "/" + std::to_string(scenarioid) + "/" + std::to_string(uid) + +"/" + std::to_string(size);
    std::string response = this->doBinaryPost(fullURL, buff, size, "tags", tags);
}

/**
 * @brief Retrieves the common corpus for this cluster
 * Unlike getCorpusUpdates, this retrieves the entire corpus for this cluster, 
 * without timestamp filtering, and including test csaes that were generated
 * by this vmf fuzzer.  Test cases will be filtered by the provided tag list.
 * Use an empty string to retrieve all tags.
 * 
 * @param tags the tags to retrieve
 * @return json11::Json the json list of test cases
 */
json11::Json CDMSClient::getCorpus(std::string tags)
{
    std::string err;

    json11::Json json = json11::Json::object
    {
        { "timestamp", 0 },
        { "tags", tags }, 
        { "ignoreVmfId", 1 }  //retrieve whole corpus
    };

    //Send Corpus Request
    std::string fullURL = corpusUpdateURL + std::to_string(uid);
    std::string response = this->doPost(fullURL, json.dump());
    auto updateData = json11::Json::parse(response, err);

    if (!err.empty())
    {
        LOG_ERROR << "JSON parsing error: " << err;
        throw RuntimeException("Unable to parse list of corpus files", RuntimeException::SERVER_ERROR);
    }

    return updateData;
}

/**
 * @brief Retrieves the list of new interesting test cases from the common corpus
 * This retrieves any new corpus updates since this method was last called.  It will
 * exclude any test cases that were generated by this vmf fuzzer.  Test cases will be 
 * filtered by the provided tag list.  Use an empty string to retrieve all tags.
 * 
 * @param tags the tags to retrieve
 * @return json11::Json the json list of test cases
 */
json11::Json CDMSClient::getCorpusUpdates(std::string tags)
{
    std::string err;

    json11::Json json = json11::Json::object
    {
        { "timestamp", lastCorpusUpdateTimestamp },
        { "tags", tags }, 
        { "ignoreVmfId", 0 }  //exclude test cases from from this uid
    };

    //Send Corpus Update Request
    std::string fullURL = corpusUpdateURL + std::to_string(uid);
    std::string response = this->doPost(fullURL, json.dump());
    auto updateData = json11::Json::parse(response, err);

    if (!err.empty())
    {
        LOG_ERROR << "JSON parsing error: " << err;
        throw RuntimeException("Unable to parse list of corpus update data", RuntimeException::SERVER_ERROR);
    }

    //Retrieve timestamp for next time
    lastCorpusUpdateTimestamp = updateData["timestamp"].string_value();

    return updateData;

}

/**
 * @brief Returns the hostname associated with the CDMSClient
 * This is the hostname of the webserver
 * 
 * @return std::string the name
 */
std::string  CDMSClient::getHostname()
{
    return hostname;
}

/**
 * @brief Returns the name associated with the CDMSClient
 * This is the name of the client
 * 
 * @return std::string the name
 */
std::string  CDMSClient::getName()
{
    return name;
}


/**
 * @brief Returns the current process id 
 * 
 * @return int the process id, or 0 if the sendRegistration method has not been called
 */
int CDMSClient::getPid()
{
    return pid;
}

/**
 * @brief Returns the current cluster id 
 * 
 * @return int the cluster id, or 0 if there is no active tasking
 */
int CDMSClient::getClusterId()
{
    return clusterid;
}

/**
 * @brief Returns the current scenario id
 * 
 * @return int the scenario id, or 0 if there is no active tasking
 */
int CDMSClient::getScenarioId()
{
    return scenarioid;
}

/**
 * @brief Returns the unique identifier associated with this vmf instance
 * 
 * @return int the uid
 */
int CDMSClient::getUniqueId()
{
    return uid;
}

/**
 * @brief Helper method to create new test cases from a json list of test cases
 * Each test case is retrieved from the CDMS server, using the provided URL,
 * and the mutator id is set to -1
 * 
 * @param storage the reference to storage
 * @param json the json to parse
 * @param testCaseKey the key for writing the test case
 * @param mutatorIdKey the key for writing the mutator id (this will be set to -1)
 */
void CDMSClient::createNewTestCases(StorageModule& storage, json11::Json json, int testCaseKey, int mutatorIdKey)
{
    auto fileList    = json["files"].array_items();
    int  size        = fileList.size();

    LOG_INFO << "Corpus Update retrieved new test cases from the server; " << size;

    for(int i=0; i<size; i++)
    {
        auto fileJson = fileList[i];

        LOG_DEBUG << "Getting Corpus File from URL: " << fileJson.string_value();
        std::string     contents    = getCorpusFile(fileJson.string_value());   
        StorageEntry*   entry       = storage.createNewEntry();
        char*           buff        = entry->allocateBuffer(testCaseKey, contents.length());

        contents.copy(buff, contents.length());

        //A mutator id of SERVER_MUTATOR_ID will indicate that this is a server provided test case,
        //as opposed to one that is generated internally within this VMF instance
        entry->setValue(mutatorIdKey, SERVER_MUTATOR_ID);
    }
}

/**
 * @brief Helper method to convert a vector of tags into a formatted tag list
 * 
 * This provides a property formatted parameter for sendTestCase amd getCorpusUpdates.
 * 
 * @param tags the tags to use
 * @return std::string the list formatted for use in communicating with the server
 */
std::string CDMSClient::formatTagList(std::vector<std::string> tags)
{
    std::string tagList = "";

    int numTags = tags.size();
    for(int i=0; i<numTags; i++)
    {
        //Add the next tag name
        tagList += tags[i];

        //Add a comma if this is not the last value
        if(i+1 < numTags) 
        {
            tagList += ",";
        }
    }

    return tagList;
}


