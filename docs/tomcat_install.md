# Contents
* [Installing Apache Tomcat](#installing-apache-tomcat)
    + [Installing Java](#installing-java)
    + [Setting Up Tomcat As a Service](#setting-up-tomcat-as-a-service)
        + [Create a Tomcat User](#create-a-tomcat-user)
        + [Download and Extract Tomcat](#download-and-extract-tomcat)
        + [Configure Tomcat to Execute as a Service](#configure-tomcat-to-execute-as-a-service)
        + [Enable the Web Management Interface](#enable-the-web-management-interface)
    + [Setting up Tomcat without Admin Privileges](#setting-up-tomcat-without-admin-privileges)
        + [Installing Tomcat in a Local Directory](#installing-tomcat-in-a-local-directory)
        + [Starting and Stopping Tomcat Manually](#starting-and-stopping-tomcat-manually)
* [Installing and Configuring CDMS](#installing-and-configuring-cdms)
    + [Running the Tomcat Manager App](#running-the-tomcat-manager-app)
        + [Deploying from External IP Addresses](#deploying-from-external-ip-addresses)
    + [Deploying the CDMS War File](#deploying-the-cdms-war-file)
        + [Configuring CDMS Database and Storage Directory](#configuring-cdms-database-and-storage-directory)
        + [Configuring a Different Data Directory](#configuring-a-different-data-directory)
        + [Setting Up the CDMS Database](#setting-up-the-cdms-database)



# Installing Apache Tomcat
Tomcat can be installed as a service, which is available to all users on the machine and is always running, or as a standalone application that must be started and stopped each time it is used.  To install Tomcat as a service, admin priviledges are needed.

The service based installation is more convenient when using CDMS, because you don't have to start Tomcat manually each time (and multiple users are supported).  However, the installation itself is simpler with a standalone installation.

Both installations require Java 17 or later.  Note: Though Apache Tomcat 9.0 only requires Java 8 or later, CMDS is compiled using Java 17.

* [Installing Java](#installing-java)
* [Setting Up Tomcat As a Service (Admin Required)](#setting-up-tomcat-as-a-service)
* [Setting up Tomcat without Admin Privileges](#setting-up-tomcat-without-admin-privileges)

## Installing Java
First you will need to install Java 17 or later on the system (this does require admin priviledges).

Check to see if Java is already on your machine using the following command.
```bash
java -version
```

Output like the following indicates that Java 17 is installed.
```bash
openjdk 17.0.7 2023-04-18
OpenJDK Runtime Environment (build 17.0.7+7-Ubuntu-0ubuntu118.04)
OpenJDK 64-Bit Server VM (build 17.0.7+7-Ubuntu-0ubuntu118.04, mixed mode, sharing)
```

If Java 17 or later is not already installed, enter the following commands
```bash
sudo apt update
sudo apt install openjdk-17-jdk
```

Confirm that Java has been properly installed using the `java -version` command (see directions above).

## Setting Up Tomcat As a Service

If you have admin privileges, you may prefer to install Tomcat as a service.  We recommend downloading and extract Tomcat rather than attempting to use the installer, as we have seen problems with the installer on Ubuntu.

These directions are based on these [installation instructions](https://linuxize.com/post/how-to-install-tomcat-9-on-ubuntu-20-04/).

### Create a Tomcat User

First create a new user and group with the home directory `/opt/tomcat`.  This user will be used to run the Tomcat service:
```bash
sudo useradd -m -U -d /opt/tomcat -s /bin/false tomcat
```

### Download and Extract Tomcat
Download the latest Tomcat 9.x release from the Apache Tomcat download page.  In these directions replace XXX with the actual version of Tomcat that you downloaded:
https://tomcat.apache.org/download-90.cgi

Extract the tar file to the /opt/tomcat directory:
```bash
sudo tar -xf /tmp/apache-tomcat-XXX.tar.gz -C /opt/tomcat/
```

Create a symbolic link to this installation, so that you can more easily update Tomcat later.  Simply update the symbolic link after extracting the newer version.
```bash
sudo ln -s /opt/tomcat/apache-tomcat-XXX /opt/tomcat/latest
```
Give the tomcat user ownership of the `/opt/tomcat` directory:
```bash
sudo chown -R tomcat: /opt/tomcat
```

Make all of the shell scripts within `/opt/tomcat` executable:
```bash
sudo sh -c 'chmod +x /opt/tomcat/latest/bin/*.sh'
```

### Configure Tomcat to Execute as a Service
You will need to create a unit file named `tomcat.service` within `/etc/systemd/system/`.  Paste in the following configuration information, updating JAVA_HOME if Java was installed in a different location.
```
[Unit]
Description=Tomcat 9 servlet container
After=network.target

[Service]
Type=forking

User=tomcat
Group=tomcat

Environment="JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64"
Environment="JAVA_OPTS=-Djava.security.egd=file:///dev/urandom -Djava.awt.headless=true"

Environment="CATALINA_BASE=/opt/tomcat/latest"
Environment="CATALINA_HOME=/opt/tomcat/latest"
Environment="CATALINA_PID=/opt/tomcat/latest/temp/tomcat.pid"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh

[Install]
WantedBy=multi-user.target
```

Use the following commands to inform the operating system that a new unit file should be loaded, and to start the Tomcat service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tomcat
```
Confirm that the Tomcat Service is now running
```bash
sudo systemctl status tomcat
```

The output should indicate that Tomcat is loaded with a status of active, for example:
```
tomcat.service - Apache Tomcat Web Application Container
   Loaded: loaded (/etc/systemd/system/tomcat.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2023-06-15 12:44:10 EDT; 5s ago
```

### Enable the Web Management Interface
Tomcat includes a web based management interface, which must be first enabled by creating at least one user with permissions to use this interface.

Open the Tomcat users file located at `/opt/tomcat/latest/conf/tomcat-users.xml`, and add a new user to the `<tomcat-users>` section.  The example below creates one new user, admin, with manager-gui and admin-gui roles.

```
<tomcat-users>
    <user username="admin" password="password" roles="manager-gui, admin-gui"/>
</tomcat-users>
```

Restart Tomcat to add the new user:
```bash
sudo systemctl restart tomcat
```

## Setting up Tomcat without Admin Privileges

These directions are based on these [installation instructions](https://csns.cysun.org/wiki/content/cysun/course_materials/tomcat_without_admin#:~:text=Start%20and%20Stop%20the%20Server,%2Fbin%2Fshutdown.sh)

### Installing Tomcat in a Local Directory
Download the latest Tomcat 9.x release from the Apache Tomcat download page.  In these directions replace XXX with the actual version of Tomcat that you downloaded:
https://tomcat.apache.org/download-90.cgi

Extract the tar file to a local directory:
```bash
tar -xf apache-tomcat-XXX.tar.gz
```

If multiple users will be running tomcat, you will need to change the ports in `apache-tomcat-XXX/conf/server.xml` file, to avoid a conflict.  Change port 8080 to another port number.

Open the Tomcat users file located at `apache-tomcat-XXX/conf/tomcat-users.xml`, and add a new user to the `<tomcat-users>` section.  The example below creates one new user, admin, with manager-gui and admin-gui roles.

```
<tomcat-users>
    <user username="admin" password="password" roles="manager-gui, admin-gui"/>
</tomcat-users>
```

### Starting and Stopping Tomcat Manually
Use the following command to start the Tomcat server.  This command will need to be run again each time you start Tomcat:
```bash
cd apache-tomcat-XXX/bin
./startup.sh
```  

To shutdown the server when you are done fuzzing, use the following command:
```bash
cd apache-tomcat-XXX/bin
./shutdown.sh
```

# Installing and Configuring CDMS
## Running the Tomcat Manager App

Open a web browser on the computer that you installed Tomcat on and navigate to the main Tomcat page. 
For a local installation using the default port of 8080, this will be: http://127.0.0.1:8080.  If you configured Tomcat with a port other than 8080, replace 8080 with the port that you used. A top level Tomcat webpage should appear.  

If you are accessing Tomcat from a different computer, you will need to both replace 127.0.0.1 with the hostname of the computer you installed Tomcat on and follow the additional instructions in [Deploying from External IP Addresses](#deploying-from-external-ip-addresses), below.

To run a the browser on a computer other than the client computer, you may be able to use port forwarding:
   ```bash
	ssh -L 8080:localhost:8080 username@servername.domain
   ```
If the main Tomcat page does not appear, there is something wrong with your Tomcat installation.

### Deploying from External IP Addresses
***Skip this section if you are are accessing Tomcat from the computer that it is installed on***

By default Tomcat only allows the "Manager App" to be run from localhost (for obvious security reasons).  If you want to be able to access it from another comuter, you will need to add the IP address of the other computer to the Tomcat configuration file (see directions below).

Open `tomcat/latest/webapps/manager/META-INF/context.xml`.  You should see a section like the following
```xml
<Context antiResourceLocking="false" privileged="true" >
<!--
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" />
-->
</Context>
```

Comment in this section and add your IP address to the list.  For example, to add access from IP 33.33.33.33:

```xml
<Context antiResourceLocking="false" privileged="true" >
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1|33.33.33.33" />
</Context>
```

## Deploying the CDMS War File

The CMDS application, like all tomcat applications, is contained within a .war file that is deployed to the webserver.  To deploy the .war file:
1.  Click on the "Manager App" button in the upper right hand corner of the top level Tomcat webpage.  
2. Enter the crendentials of the user that you configured in the `tomcat-users.xml` file.
3. Click `Choose File` and select the pre-built CDMS.war file that was included along with your VMF release.  
4. Click `Deploy` to deploy the CDMS application.

After deployment, if you installed Tomcat as a service, you will be able to access the application at http://127.0.0.1:8080/CDMS/.  

## Configuring CDMS Database and Storage Directory
CDMS needs a data directory to use for its database as well as for storage of other server data (primarily test cases). 
The default directory is `/opt/cdms`.  

If you want to use a different directory, see Configuring a Different Data Directory below.  If you installed Tomcat as a standalone application, you will have to configure a different data directory (because standard users do not have access to /opt).

### Configuring a Different Data Directory

***Skip this section to use /opt/cdms as your data directory.***
 
Perform the following steps after deploying the .WAR file:
1.	Create a local data directory to use for CDMS data.  You must have read and write access to this directory.
2.	Edit tomcat/webapps/CDMS/META-INF/context.xml.  Change the following line to reflect the cdms.db file that you just created -- `url="jdbc:sqlite:/opt/cdms/cdms.db"`
4.	Edit tomcat/webapps/CDMS/WEB-INF/web.xml.  Modify the following entry to change /opt/cdms to your local data directory:
    <context-param>
      <param-name>storagePath</param-name>
      <param-value>/opt/cdms</param-value>
    </context-param>

### Setting Up the CDMS Database
1. Copy into your data directory the provided empty CDMS database.  This is included with the pre-built copy of CDMS, or may be located in the source code at server/CDMS/WebContent/WEB-INF/install/emptycdms.db.
2. Rename the `emptycdms.db` file to cdms.db
3. If you are running tomcat as a service, make sure that the tomcat user has permissions to read and write to both the data directory and cdms.db.

Restart tomcat, and go to http://127.0.0.1:8080/CDMS/, you should now see the CDMS UI.
