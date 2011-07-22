#!/usr/bin/env ruby
#####################################################################################
# Copyright (c) 2011, Cohesive Flexible Technologies, Inc.
# This copyrighted material is the property of Cohesive Flexible Technologies and
# is subject to the license terms of the product it is contained within, whether 
# in text or compiled form.  It is licensed under the terms expressed in the 
# accompanying README and LICENSE files.
# 
# This program is AS IS and WITHOUT ANY WARRANTY; without even the implied warranty 
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#####################################################################################

class MockSmartCloud
  def create_instance(*args)
    describe_instance
  end

  def describe_image(*args)
    {"CreatedTime"=>"2011-02-25T01:22:57.000Z", "Owner"=>"SYSTEM", "SupportedInstanceTypes"=>{"InstanceType"=>{"Label"=>"Bronze 32 bit", "ID"=>"BRZ32.1/2048/60*175", "Price"=>{"Rate"=>"0.21", "PricePerQuantity"=>"1", "UnitOfMeasure"=>"UHR  ", "CountryCode"=>"897", "CurrencyCode"=>"USD"}}}, "Name"=>"CohesiveFT VPN-Cubed Datacenter Connect V2.0.0 - BYOL (TOR)", "Location"=>"101", "ProductCodes"=>{"ProductCode"=>"caondc13bV97Kg5TLyGNodD9or7gA"}, "Documentation"=>"https://www-147.ibm.com/cloud/enterprise/ram.ws/RAMSecure/artifact/{974E595E-566E-87E3-A483-AC0FC468C4D9}/1.0/GettingStarted.html", "ID"=>"20016530", "Manifest"=>"https://www-147.ibm.com/cloud/enterprise/ram.ws/RAMSecure/artifact/{974E595E-566E-87E3-A483-AC0FC468C4D9}/1.0/parameters.xml", "Description"=>"CohesiveFT VPN-Cubed 2.0.0 UL - for TOR datacenter", "State"=>"AVAILABLE", "Visibility"=>"PUBLIC", "Platform"=>"Red Hat Enterprise Linux/5.4"}
  end

  def describe_instance(*args)
    {"Instance" => {"Status"=>"NEW", "PrimaryIP"=>{"IP"=>{}, "Hostname"=>{}, "Type"=>"DYNAMIC"}, "ImageID"=>"20015391", "DiskSize"=>"60", "Owner"=>"smartes@cohesiveft.com", "RequestID"=>{"name"=>"sir_19_rhel5532-bit-1zGS", "content"=>"102271"}, "Name"=>"DELETEsir_19_rhel5532-bit-1zGS", "ProductCodes"=>{}, "KeyName"=>"si-tempkey-rhel5532-bit-1zGS-eDY4T", "Location"=>"101", "LaunchTime"=>"2011-07-07T22:13:49.891Z", "Volumes"=>{}, "ID"=>"101971", "MiniEphemeral"=>"false", "Software"=>{"Application"=>{"Version"=>"5.5", "Name"=>"Red Hat Enterprise Linux", "Type"=>"OS"}}, "IP"=>{}, "InstanceType"=>"COP32.1/2048/60", "Hostname"=>{}}}
  end

  def create_volume(*args)
    true
  end

  def describe_volume(*args)
    {:ID => "12345", :State => "5", :Name => "foobar"}
  end

  def clone_volume(*args)
    true
  end

  def restart_instance(*args)
    true
  end

  def delete_instance(*args)
    true
  end

  def poll_for_volume_state(*args)
    true
  end

  def poll_for_instance_state(*args)
    true
  end
end
