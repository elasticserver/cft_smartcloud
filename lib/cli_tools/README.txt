						Command Line Tool
							---- IBM Smart Business Development & Test on the IBM Cloud
Version 1.4.1.CC20110505-2046 March 2011
---------------
Changes:
1. Add an option in command ic-describe-images, -y --ignoreAdditionalInfo to ignore the additional information. With this 
   option, it won't download the parameters.xml from RAM. 

Version 1.4.0.CC20110112-2159 January 2011
---------------
Changes:
1.Add command ic-update-instance
2.Add command ic-attach-volume & ic-detach-volume

Version 1.3.0.CC20101207-1012 November 2010
---------------
Changes:
1. Add DataCenterDownException in several commands.
	
Version 1.2.0.20101019-0015 October 2010
---------------
Changes:
1. Add command ic-clone-volume
2. Add parameter -e/--isMiniEphemeral for ic-create-instance to support provision an instance with minimal ephemeral storage
3. Support multiple addresses attached in one instance
                        
Version 1.1.3.20101012-0333 October 2010
---------------
Changes:
1. Increase the value of the so_timeout

Version 1.1.2.20100906-0202 September 2010
---------------                            
Changes:
1. Update DeveloperCloud_API_Client_JAR.jar.
   Correct the business logic in createInstance.

Version 1.1.1.20100829-2101 August 2010
---------------                            
Changes:
1. Update DeveloperCloud_API_Client_JAR-javadoc.jar.

Version 1.1.0.20100623-1406 June 2010
---------------
Changes:
1. Add command and parameters to support Vlan
    1) ic-describe-vlans
    2) ic-allocate-address
    3) ic-create-instance
2. Add commands ic-describe-image-agreement.