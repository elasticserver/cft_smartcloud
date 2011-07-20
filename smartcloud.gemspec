# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{smartcloud}
  s.version = "0.1.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["yan"]
  s.date = %q{2011-07-20}
  s.description = %q{IBM SmartCloud API Gem}
  s.email = %q{yan.pritzker@cohesiveft.com}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".gitignore",
     "CHANGELOG",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "VERSION",
     "lib/cli_tools/README.txt",
     "lib/cli_tools/ic-add-keypair.cmd",
     "lib/cli_tools/ic-add-keypair.sh",
     "lib/cli_tools/ic-allocate-address.cmd",
     "lib/cli_tools/ic-allocate-address.sh",
     "lib/cli_tools/ic-attach-volume.cmd",
     "lib/cli_tools/ic-attach-volume.sh",
     "lib/cli_tools/ic-clone-image.cmd",
     "lib/cli_tools/ic-clone-image.sh",
     "lib/cli_tools/ic-clone-volume.cmd",
     "lib/cli_tools/ic-clone-volume.sh",
     "lib/cli_tools/ic-cmd.cmd",
     "lib/cli_tools/ic-cmd.sh",
     "lib/cli_tools/ic-create-instance.cmd",
     "lib/cli_tools/ic-create-instance.sh",
     "lib/cli_tools/ic-create-password.cmd",
     "lib/cli_tools/ic-create-password.sh",
     "lib/cli_tools/ic-create-volume.cmd",
     "lib/cli_tools/ic-create-volume.sh",
     "lib/cli_tools/ic-delete-image.cmd",
     "lib/cli_tools/ic-delete-image.sh",
     "lib/cli_tools/ic-delete-instance.cmd",
     "lib/cli_tools/ic-delete-instance.sh",
     "lib/cli_tools/ic-delete-volume.cmd",
     "lib/cli_tools/ic-delete-volume.sh",
     "lib/cli_tools/ic-describe-address-offerings.cmd",
     "lib/cli_tools/ic-describe-address-offerings.sh",
     "lib/cli_tools/ic-describe-addresses.cmd",
     "lib/cli_tools/ic-describe-addresses.sh",
     "lib/cli_tools/ic-describe-image-agreement.cmd",
     "lib/cli_tools/ic-describe-image-agreement.sh",
     "lib/cli_tools/ic-describe-image.cmd",
     "lib/cli_tools/ic-describe-image.sh",
     "lib/cli_tools/ic-describe-images.cmd",
     "lib/cli_tools/ic-describe-images.sh",
     "lib/cli_tools/ic-describe-instance.cmd",
     "lib/cli_tools/ic-describe-instance.sh",
     "lib/cli_tools/ic-describe-instances.cmd",
     "lib/cli_tools/ic-describe-instances.sh",
     "lib/cli_tools/ic-describe-keypair.cmd",
     "lib/cli_tools/ic-describe-keypair.sh",
     "lib/cli_tools/ic-describe-keypairs.cmd",
     "lib/cli_tools/ic-describe-keypairs.sh",
     "lib/cli_tools/ic-describe-location.cmd",
     "lib/cli_tools/ic-describe-location.sh",
     "lib/cli_tools/ic-describe-locations.cmd",
     "lib/cli_tools/ic-describe-locations.sh",
     "lib/cli_tools/ic-describe-request.cmd",
     "lib/cli_tools/ic-describe-request.sh",
     "lib/cli_tools/ic-describe-vlans.cmd",
     "lib/cli_tools/ic-describe-vlans.sh",
     "lib/cli_tools/ic-describe-volume-offerings.cmd",
     "lib/cli_tools/ic-describe-volume-offerings.sh",
     "lib/cli_tools/ic-describe-volume.cmd",
     "lib/cli_tools/ic-describe-volume.sh",
     "lib/cli_tools/ic-describe-volumes.cmd",
     "lib/cli_tools/ic-describe-volumes.sh",
     "lib/cli_tools/ic-detach-volume.cmd",
     "lib/cli_tools/ic-detach-volume.sh",
     "lib/cli_tools/ic-extend-reservation.cmd",
     "lib/cli_tools/ic-extend-reservation.sh",
     "lib/cli_tools/ic-generate-keypair.cmd",
     "lib/cli_tools/ic-generate-keypair.sh",
     "lib/cli_tools/ic-release-address.cmd",
     "lib/cli_tools/ic-release-address.sh",
     "lib/cli_tools/ic-remove-keypair.cmd",
     "lib/cli_tools/ic-remove-keypair.sh",
     "lib/cli_tools/ic-restart-instance.cmd",
     "lib/cli_tools/ic-restart-instance.sh",
     "lib/cli_tools/ic-save-instance.cmd",
     "lib/cli_tools/ic-save-instance.sh",
     "lib/cli_tools/ic-set-default-key.cmd",
     "lib/cli_tools/ic-set-default-key.sh",
     "lib/cli_tools/ic-update-instance.cmd",
     "lib/cli_tools/ic-update-instance.sh",
     "lib/cli_tools/ic-update-keypair.cmd",
     "lib/cli_tools/ic-update-keypair.sh",
     "lib/cli_tools/lib/DeveloperCloud_API_Client_JAR.jar",
     "lib/cli_tools/lib/DeveloperCloud_CMD_Tool.jar",
     "lib/cli_tools/lib/commons-beanutils-1.6.1.jar",
     "lib/cli_tools/lib/commons-cli-1.2.jar",
     "lib/cli_tools/lib/commons-codec-1.3.jar",
     "lib/cli_tools/lib/commons-collections-3.2.1.jar",
     "lib/cli_tools/lib/commons-digester-1.8.jar",
     "lib/cli_tools/lib/commons-httpclient-3.1.jar",
     "lib/cli_tools/lib/commons-lang-2.3.jar",
     "lib/cli_tools/lib/commons-logging-1.1.1.jar",
     "lib/cli_tools/logging.properties",
     "lib/cli_tools/manifest.rmd",
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
     "lib/smartcloud.rb",
     "lib/smartcloud_logger.rb",
     "lib/xml-simple-1.0.12/lib/xmlsimple.rb",
     "script/console",
     "smartcloud",
     "smartcloud.gemspec",
     "test/helper.rb"
  ]
  s.homepage = %q{http://github.com/cohesive/smartcloud}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{IBM SmartCloud API Gem}
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

