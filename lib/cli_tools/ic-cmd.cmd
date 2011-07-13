REM ###########################################################################

REM #

REM # Licensed Materials - Property of IBM

REM #

REM # (C) COPYRIGHT International Business Machines Corp. 2009

REM #

REM # All Rights Reserved.

REM #

REM # US Government Users Restricted Rights - Use, duplication or

REM # disclosure restricted by GSA ADP Schedule Contract with IBM Corp.

REM #

REM #############################################################################

if not exist "%JAVA_HOME%\bin\java.exe" goto showhelp

	SET CL_CLASSPATH=.;%cd%\lib\commons-cli-1.2.jar;%cd%\lib\DeveloperCloud_CMD_Tool.jar;%cd%\lib\commons-logging-1.1.1.jar;%cd%\lib\commons-codec-1.3.jar;%cd%\lib\commons-httpclient-3.1.jar;%cd%\lib\DeveloperCloud_API_Client_JAR.jar;%cd%\lib\commons-beanutils-1.6.1.jar;%cd%\lib\commons-digester-1.8.jar;%cd%\lib\commons-lang-2.3.jar;%cd%\lib\commons-collections-3.2.1.jar

	call "%JAVA_HOME%\bin\java" -Djava.util.logging.config.file=logging.properties -cp %CL_CLASSPATH% com.ibm.cloud.cmd.tool.Command %*

	goto end

	

:showhelp

	echo You don't have JAVA installed or the environment variable JAVA_HOME is not set correctly. Please install Java version version 1.5.x and set the JAVA_HOME environment variable if it's already installed. 

	

:end