smartcloud
===

Provides support for interacting with IBM SmartCloud API and CLI tools

Installation
===

from rubygems.org:

    gem install cft_smartcloud

locally:

    rake build
    gem install pkg/[name of generated gem]

Setup
===

Please set up SMARTCLOUD_USERNAME and SMARTCLOUD_PASSWORD in your .bash_profile

    export SMARTCLOUD_USERNAME=[your username]
    export SMARTCLOUD_PASSWORD=[your password]

You can now also supply the username and password on the command line using -u and -p
Use `smartcloud help` to get a list of all optoins.


Using the console
== 

    script/console
    >> @smartcloud.display_instances
    >> @smartcloud.display_volumes(:Location => 101)
    >> @smartcloud.display_instances(:Location => 82, :Name => "namematch")
    >> @smartcloud.poll_for_volume_state(12345, :unmounted)

  The console predefines the @smartcloud instance variable that is set up
  from the environment variables SMARTCLOUD_USERNAME and SMARTCLOUD_PASSWORD
  automatically (it's created at the bottom of smartcloud.rb)

Using the commandline 
== 

To see a list of methods:

    smartcloud help

Examples:

      smartcloud display_volumes
      smartcloud display_volumes Location=82 State=MOUNTED
      smartcloud display_instances
      smartcloud delete_instances 12345 12346 12347
      smartcloud display_images Name="Red Hat"
      smartcloud display_instances Name="Red Hat" Location=82

The 'display_*' methods are intended to generate pretty human readable 
displays, while the describe methods will return pretty-formatted hashes,
or singular values.

To save time when dealing with large responses, such as the describe_images
call, you can save a response in its native XML format:

      smartcloud display_images -S /tmp/images.xml

You can then replay the response, using filters on it

      smartcloud display_images Name='Red Hat' -R /tmp/images.xml



RestClient vs CurlHttpClient
===
Sometimes RestClient and friends have trouble communicating with certain API's such as 
IBM SmartCloud, returning 500 errors. We found in some cases the only thing that truly
works is pure curl (not even libcurl ruby wrappers). Therefore there is a provided 
simple CurlHttpClient library which emulates the RestClient interface, and wraps 
command line calls to curl.

The choice of client is determined inside of config.yml

Versioning
== 

This project uses the jeweler gem for packaging. See the tasks:

    rake version:bump:...
    rake build

Screencast
===

http://www.youtube.com/cohesiveft#p/u/0/-WdSHP2iwDM (somewhat outdated)

Copyright
== 

Copyright (c) 2011 CohesiveFT. See LICENSE for details.
