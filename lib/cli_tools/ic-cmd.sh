#!/bin/sh
############################################################################
#
# Licensed Materials - Property of IBM
#
# (C) COPYRIGHT International Business Machines Corp. 2009
#
# All Rights Reserved.
#
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#
#############################################################################
if [ -f ${JAVA_HOME}/bin/java ]; then

	LANG=en_US
	declare workpath=`pwd`
	declare -a libs=`ls ./lib/`
	
	CL_CLASSPATH=""
	for i in ${libs[@]}
	do
	 if [ ${i##.*}=".jar" ] ; then
	   if [ -z "${CL_CLASSPATH}" ] ; then
	     CL_CLASSPATH=${workpath}/lib/${i}
	   else
	     CL_CLASSPATH=${workpath}/lib/${i}:$CL_CLASSPATH
	   fi
	 fi
	done
	
	export CL_CLASSPATH
	
	${JAVA_HOME}/bin/java -Djava.util.logging.config.file=logging.properties -cp ${CL_CLASSPATH} com.ibm.cloud.cmd.tool.Command $*

else
	echo You don't have JAVA installed or the environment variable JAVA_HOME is not set correctly. Please install Java version version 1.5.x and set the JAVA_HOME environment variable if it's already installed. 
fi
