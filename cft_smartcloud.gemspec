# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{cft_smartcloud}
  s.version = "0.2.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["yan", "cohesive"]
  s.date = %q{2011-11-16}
  s.description = %q{CohesiveFT Ruby Interface for IBM SmartCloud and 'smartcloud' command line helper.}
  s.email = %q{yan.pritzker@cohesiveft.com}
  s.executables = ["cft_smartcloud", "smartcloud"]
  s.extra_rdoc_files = [
    "LICENSE",
     "README.md"
  ]
  s.files = [
    ".gitignore",
     "CHANGELOG",
     "LICENSE",
     "README.md",
     "Rakefile",
     "VERSION",
     "bin/cft_smartcloud",
     "bin/smartcloud",
     "cft_smartcloud.gemspec",
     "lib/config/config.yml",
     "lib/hash_fix.rb",
     "lib/mime-types-1.16/History.txt",
     "lib/mime-types-1.16/Install.txt",
     "lib/mime-types-1.16/Licence.txt",
     "lib/mime-types-1.16/Manifest.txt",
     "lib/mime-types-1.16/README.txt",
     "lib/mime-types-1.16/Rakefile",
     "lib/mime-types-1.16/lib/mime/types.rb",
     "lib/mime-types-1.16/lib/mime/types.rb.data",
     "lib/mime-types-1.16/mime-types.gemspec",
     "lib/mime-types-1.16/setup.rb",
     "lib/mime-types-1.16/test/test_mime_type.rb",
     "lib/mime-types-1.16/test/test_mime_types.rb",
     "lib/mock_smartcloud.rb",
     "lib/rest-client-1.6.3/README.rdoc",
     "lib/rest-client-1.6.3/Rakefile",
     "lib/rest-client-1.6.3/VERSION",
     "lib/rest-client-1.6.3/bin/restclient",
     "lib/rest-client-1.6.3/history.md",
     "lib/rest-client-1.6.3/lib/rest-client.rb",
     "lib/rest-client-1.6.3/lib/rest_client.rb",
     "lib/rest-client-1.6.3/lib/restclient.rb",
     "lib/rest-client-1.6.3/lib/restclient/abstract_response.rb",
     "lib/rest-client-1.6.3/lib/restclient/exceptions.rb",
     "lib/rest-client-1.6.3/lib/restclient/net_http_ext.rb",
     "lib/rest-client-1.6.3/lib/restclient/payload.rb",
     "lib/rest-client-1.6.3/lib/restclient/raw_response.rb",
     "lib/rest-client-1.6.3/lib/restclient/request.rb",
     "lib/rest-client-1.6.3/lib/restclient/resource.rb",
     "lib/rest-client-1.6.3/lib/restclient/response.rb",
     "lib/restclient_fix.rb",
     "lib/slop-2.3.1/.gemtest",
     "lib/slop-2.3.1/.gitignore",
     "lib/slop-2.3.1/.yardopts",
     "lib/slop-2.3.1/CHANGES.md",
     "lib/slop-2.3.1/LICENSE",
     "lib/slop-2.3.1/README.md",
     "lib/slop-2.3.1/Rakefile",
     "lib/slop-2.3.1/lib/slop.rb",
     "lib/slop-2.3.1/slop.gemspec",
     "lib/slop-2.3.1/test/commands_test.rb",
     "lib/slop-2.3.1/test/helper.rb",
     "lib/slop-2.3.1/test/option_test.rb",
     "lib/slop-2.3.1/test/slop_test.rb",
     "lib/smartcloud.rb",
     "lib/smartcloud_logger.rb",
     "lib/xml-simple-1.0.12/lib/xmlsimple.rb",
     "rdoc/classes/ConfigTable.html",
     "rdoc/classes/ConfigTable/BoolItem.html",
     "rdoc/classes/ConfigTable/ExecItem.html",
     "rdoc/classes/ConfigTable/Item.html",
     "rdoc/classes/ConfigTable/MetaConfigEnvironment.html",
     "rdoc/classes/ConfigTable/PackageSelectionItem.html",
     "rdoc/classes/ConfigTable/PathItem.html",
     "rdoc/classes/ConfigTable/ProgramItem.html",
     "rdoc/classes/ConfigTable/SelectItem.html",
     "rdoc/classes/Enumerable.html",
     "rdoc/classes/Errno.html",
     "rdoc/classes/Errno/ENOTEMPTY.html",
     "rdoc/classes/File.html",
     "rdoc/classes/FileOperations.html",
     "rdoc/classes/Hash.html",
     "rdoc/classes/HookScriptAPI.html",
     "rdoc/classes/IBMSmartCloud.html",
     "rdoc/classes/Installer.html",
     "rdoc/classes/Installer/Shebang.html",
     "rdoc/classes/MIME.html",
     "rdoc/classes/MIME/InvalidContentType.html",
     "rdoc/classes/MIME/Type.html",
     "rdoc/classes/MIME/Types.html",
     "rdoc/classes/MockSmartCloud.html",
     "rdoc/classes/Net.html",
     "rdoc/classes/Net/HTTP.html",
     "rdoc/classes/RestClient.html",
     "rdoc/classes/RestClient/AbstractResponse.html",
     "rdoc/classes/RestClient/Exception.html",
     "rdoc/classes/RestClient/ExceptionWithResponse.html",
     "rdoc/classes/RestClient/Exceptions.html",
     "rdoc/classes/RestClient/MaxRedirectsReached.html",
     "rdoc/classes/RestClient/Payload.html",
     "rdoc/classes/RestClient/Payload/Base.html",
     "rdoc/classes/RestClient/Payload/Multipart.html",
     "rdoc/classes/RestClient/Payload/Streamed.html",
     "rdoc/classes/RestClient/Payload/UrlEncoded.html",
     "rdoc/classes/RestClient/RawResponse.html",
     "rdoc/classes/RestClient/Redirect.html",
     "rdoc/classes/RestClient/Request.html",
     "rdoc/classes/RestClient/RequestFailed.html",
     "rdoc/classes/RestClient/Resource.html",
     "rdoc/classes/RestClient/Response.html",
     "rdoc/classes/RestClient/ResponseForException.html",
     "rdoc/classes/RestClient/SSLCertificateNotVerified.html",
     "rdoc/classes/RestClient/ServerBrokeConnection.html",
     "rdoc/classes/SetupError.html",
     "rdoc/classes/SmartcloudLogger.html",
     "rdoc/classes/TestMIME.html",
     "rdoc/classes/ToplevelInstaller.html",
     "rdoc/classes/ToplevelInstallerMulti.html",
     "rdoc/classes/XmlSimple.html",
     "rdoc/classes/XmlSimple/Cache.html",
     "rdoc/created.rid",
     "rdoc/files/README_rdoc.html",
     "rdoc/files/lib/hash_fix_rb.html",
     "rdoc/files/lib/mime-types-1_16/lib/mime/types_rb.html",
     "rdoc/files/lib/mime-types-1_16/setup_rb.html",
     "rdoc/files/lib/mime-types-1_16/test/test_mime_type_rb.html",
     "rdoc/files/lib/mime-types-1_16/test/test_mime_types_rb.html",
     "rdoc/files/lib/mock_smartcloud_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/rest-client_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/rest_client_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/abstract_response_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/exceptions_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/net_http_ext_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/payload_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/raw_response_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/request_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/resource_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient/response_rb.html",
     "rdoc/files/lib/rest-client-1_6_3/lib/restclient_rb.html",
     "rdoc/files/lib/restclient_fix_rb.html",
     "rdoc/files/lib/smartcloud_logger_rb.html",
     "rdoc/files/lib/smartcloud_rb.html",
     "rdoc/files/lib/xml-simple-1_0_12/lib/xmlsimple_rb.html",
     "rdoc/fr_class_index.html",
     "rdoc/fr_file_index.html",
     "rdoc/fr_method_index.html",
     "rdoc/index.html",
     "rdoc/rdoc-style.css",
     "script/console",
     "test/helper.rb"
  ]
  s.homepage = %q{http://github.com/cohesive/cft_smartcloud}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{CohesiveFT IBM SmartCloud API Gem}
  s.test_files = [
    "test/helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end

