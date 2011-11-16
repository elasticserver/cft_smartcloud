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

Dir["#{File.dirname(__FILE__)}/**/**"].each {|dir| $LOAD_PATH << dir }
$LOAD_PATH << File.dirname(__FILE__)

require 'tempfile'
require 'logger'
require 'cgi'
require 'rest_client'
require 'yaml'
require 'restclient_fix'
require 'hash_fix'
require 'xmlsimple'
require 'smartcloud_logger'

IBM_TOOLS_HOME=File.join(File.dirname(__FILE__), "cli_tools") unless defined?(IBM_TOOLS_HOME)

# Encapsulates communications with IBM SmartCloud via REST
class IBMSmartCloud

  attr_accessor :logger

  def initialize(opts={})
    # For handling errors
    @retries = (opts[:retries] || 120).to_i
    @sleep_interval = (opts[:sleep_interval] || 30).to_i
    
    @username = opts[:username] || ENV['SMARTCLOUD_USERNAME'] || raise(RuntimeError, "Please specify username in an option or as ENV variable SMARTCLOUD_USERNAME")
    @password = opts[:password]|| ENV['SMARTCLOUD_PASSWORD'] || raise(RuntimeError, "Please specify password in an option or as ENV variable SMARTCLOUD_PASSWORD")
    @logger = opts[:logger] || SmartcloudLogger.new(STDOUT)
    @debug = opts[:debug] || false

    @config = YAML.load_file(File.join(File.dirname(__FILE__), "config/config.yml"))
    @states = @config["states"]

    @api_url = (opts[:api_url] || @config["api_url"]).to_s.dup # gotta dup it because the option string is frozen
    @api_url.gsub!("https://", "https://#{CGI::escape(@username)}:#{CGI::escape(@password)}@")

    RestClient.timeout = 120 # ibm requests can be very slow
    RestClient.log = @logger if @debug
  end

  class << self
    @config = YAML.load_file(File.join(File.dirname(__FILE__), "config/config.yml"))
    attr_reader :method_help
    attr_reader :method_help_supplemental
    attr_reader :config
  end

  def self.args(method, args, extra_help={})
    @method_help||={}
    @method_help_supplemental||={}
    @method_help[method.to_s] = args
    @method_help_supplemental[method.to_s] = extra_help
  end

  def help(method=nil)
    if method
      args = (self.class.method_help[method.to_s]) 
      if !(self.respond_to?(method))
        return "Sorry, I don't know method: #{method}"
      end

        args = args && args.map do |arg|
          if arg.is_a?(Hash)
            # If an argument is required, just list it
            if arg.values.first==:req
              arg.keys.first.to_s 
            # If it's optional, list it in brackets
            elsif arg.values.first==:opt
              "[#{arg.keys.first.to_s}]"
            # If there is an array of options, list them
            else 
              "#{arg.keys.first.to_s}=>#{arg.values.first.inspect}"
            end
          else
            arg
          end
        end.join(", ")

        extra_help = self.class.method_help_supplemental[method.to_s] || ""

        puts %{=== #{method.to_s}#{'(' + args + ')' if args}#{extra_help + "\n" if extra_help}}
    else
      methods = public_methods - Object.public_methods - ['post','get','put','delete','logger','logger=','help']
      methods.each {|m| help(m)}
      nil
    end
  end

  # Get a list of data centers
  def describe_locations
    get("/locations").Location
  end

  def describe_location(location_id)
    get("/locations/#{location_id}").Location
  end

  def display_locations
    log = describe_locations.map {|loc| "#{loc.ID.ljust(4)} | #{loc.Location.ljust(15)} | #{loc.Name}"}.join("\n")
    logger.info "\n#{log}"
  end

  # Create an instance. The instance_params hash can follow
  # CLI-style attribute naming. I.e. "image-id" or "data-center"
  # or API-style (imageID, location). If the CLI-style params are
  # provided, they will be remapped to the correct API params.
  args :create_instance, [:instance_params_hash], %{
    Available hash keys: :name, :imageID, :instanceType, :location, :publicKey, :ip, :volumeID, 
                         :ConfigurationData, :vlanID, :antiCollocationInstance, :isMiniEphemeral

    Example: smartcloud "create_instance(:name => 'MyTest', :instanceType=>'COP32.1/2048/60', ...)"
  }
  def create_instance(instance_params)
    param_remap = { "name" => "name",
      "image-id" => "imageID",
      "instance-type" => "instanceType",
      "data-center" => "location",
      "key-name" => "publicKey",
      "ip-address-id" => "ip",
      "volume-id" => "volumeID",
      "configuration" => "ConfigurationData",
      "vlan-id" => "vlanID",
      "antiCollocationInstance" => "antiCollocationInstance",
      "isMiniEphemeral" => "isMiniEphemeral"
    }

    # api does not take description
    instance_params.delete("description")

    # configuration data has to be changed from a string like
    # <configuration>{contextmanager:test-c3-master.cohesiveft.com,clustername:TEST_poc_pk0515,role:[nfs-client-setup|newyork_master_refdata_member|install-luci|rhel-openlikewise-client-setup|join-domain],hostname:r550n107}</configuration> 
    # to a standard list of POST params like
    # contextmanager=test-c3-mager&clustername=TEST...
    configuration_data = instance_params.delete("configuration") || instance_params.delete("ConfigurationData") 
    if configuration_data
      if configuration_data =~ /\s+/
        logger.warn "<configuration> tag should not contain spaces! Correct format looks like: <configuration>{foo:bar,baz:quux}</configuration>. Spaces will be removed."
      end
      configuration_data.delete!("{}") # get rid of curly braces
      config_data_params = configuration_data.split(",").map{|param| param.split(":")} # split each foo:bar into key and value
      config_data_params.each {|k,v| instance_params[k]=v} # add it into the standard instance params array
    end

    result = post "/instances", instance_params, param_remap
    result.Instance
  end

  # Find a location by its name. Assumes locations have unique names (not verified by ibm docs)
  args :get_locations_by_name, [:name]
  def get_location_by_name(name)
    locations = describe_locations
    locations.detect {|loc| loc.Name == name}
  end

  # find all ip address offerings. If a location is specified, give the offering for the location
  # assumption: only one offering per location. This is assumed, not verified in docs.
  args :describe_address_offerings, [{:location => :opt}]
  def describe_address_offerings(location=nil)
    response=get("/offerings/address").Offerings
    if location
      response.detect {|offering| offering.Location.to_s == location.to_s}
    else
      response
    end
  end

  # Allocate IP address. Offering ID is optional. if not specified, will look up offerings
  # for this location and pick one
  args :allocate_address, [{:location => :req}, {:offering_id => :opt}, {:foo => [:bar, :baz, :quux]}]
  def allocate_address(location, offering_id=nil)
    if offering_id.nil?
      offering_id = describe_address_offerings(location).ID
    end
    post("/addresses", :offeringID => offering_id, :location => location).Address
  end


  args :describe_address, [:address_id]
  def describe_address(address_id)
    address = get("/addresses/#{address_id}").Address
    address["State"] = @config.states.ip[address.State]
    address
  end

  # Launches a clone image call from CLI
  args :clone_image, [:name, :description, :image_id]
  def clone_image(name, description, image_id)
    post("/offerings/image/#{image_id}", :name => name, :description => description).ImageID
  end

  # Export an image to a volume
  # NOTE: This is THEORETICAL and has not been tested - because the api server throws 500
  # on all requests
  args :export_image, [{:name=>:req}, {:size => ['Small','Medium','Large']}, {:image_id => :req}]
  def export_image(name, size, image_id, location)
    # Note we figure out the correct size based on the name and location
    storage_offering=describe_storage_offerings(location, size)

    response = post("/storage", :name => name, :description => description, :size => storage_offering.Capacity, :offeringID => storage_offering.ID, :imageID => image_id)
    response.Volume.ID
  end

  # Launches a clone request and returns ID of new volume
  # TODO: the API call does not work, we have to use the cli for now
  args :clone_volume, [:name, :source_disk_id]
  def clone_volume(name, source_disk_id)
    result = post("/storage", :name => name, :sourceDiskID => source_disk_id, :type => 'clone')
    result.Volume.ID
  end

  args :attach_volume, [:instance_id, :volume_id]
  def attach_volume(instance_id, volume_id)
    put("/instances/#{instance_id}", :volumeID => volume_id, :attach => true)
  end

  args :detach_volume, [:instance_id, :volume_id]
  def detach_volume(instance_id, volume_id)
    put("/instances/#{instance_id}", :volumeID => volume_id, :detach => true)
  end

  # Delete the volume
  args :delete_volume, [:vol_id]
  def delete_volume(vol_id)
    delete("/storage/#{vol_id}")
    true
  end

  args :delete_volumes, [:volume_ids], %{
    Example: smartcloud "delete_volumes(12345,12346,12347)"
  }
  def delete_volumes(*vol_id_list)
    threads=[]
    vol_id_list.each {|vol| 
      threads << Thread.new { logger.info "Sending delete request for: #{vol}..."; delete_volume(vol); logger.info "Finished delete request for #{vol}" }
    }
    threads.each(&:join)
    true
  end

  # generates a keypair and returns the private key
  args :generate_keypair, [{:name=>:req}, {:publicKey=>:opt}], %{ 
    If publicKey parameter is given, creates a key with that public key, and returns nothing. 
    If public key is omitted, generates a new key and returns the pirvate key.
  }
  def generate_keypair(name, publicKey=nil)
    options = {:name => name}
    options[:publicKey] = publicKey if publicKey
    response = post("/keys", options)
    if publicKey
      true
    else
      response.PrivateKey.KeyMaterial
    end
  end

  args :remove_keypair, [:name]
  def remove_keypair(name)
    delete("/keys/#{name}")
    true
  end

  args :describe_key, [:name]
  def describe_key(name)
    get("/keys/#{name}").PublicKey
  end

  args :update_key, [:name, :publicKey]
  def update_key(name, key)
    put("/keys/#{name}", :publicKey => key)
  end

  # If address_id is supplied, will return info on that address only
  args :describe_addresses, [{:address_id=>:opt}]
  def describe_addresses(address_id=nil)
    response = arrayize(get("/addresses").Address)
    response.each do |a|
      a["State"] = @states["ip"][a.State.to_i]
    end
    if address_id
      response = response.detect {|address| address.ID.to_s == address_id.to_s}
    end
    response
  end

  def display_addresses
    addresses = describe_addresses

    logger.info "\nID     | Loc  | State      | IP \n" + addresses.map {|a| 
      a.ID.ljust(6) + " | " + a.Location.ljust(4) + " | " + (a.State[0..9].ljust(10) rescue '?'.ljust(10)) + " | " + (a.IP.to_s || "")
    }.join("\n")
  end

  # Allows you to poll for a specific storage state
  # ex: storage_state_is?("123456", "UNMOUNTED")
  # storage state string can be given as a string or symbol
  args :describe_addresses, [{:address_id=>:req}, {:state_string=>%w(new attached etc...)}]
  def address_state_is?(address_id, state_string)
    v = describe_addresses(address_id)
    v.State.to_s == state_string.to_s.upcase
  end

  def describe_keys
    arrayize(get("/keys").PublicKey)
  end

  def describe_unused_keys
    describe_keys.select {|key| key.Instances == {}}
  end

  def display_keys 
    logger.info "\nKeyName".ljust(50) + "  | Instance ID's\n" +  describe_keys.map {|key| key.KeyName.strip.ljust(50) + " | " + (key.Instances.empty? ? '[]' : key.Instances.InstanceID.inspect  )}.join("\n")
  end

  args :supported_instance_types, [:image_id]
  def supported_instance_types(image_id)
    img=describe_image(image_id)
    arrayize(img.SupportedInstanceTypes.InstanceType).map(&:ID)
  end
  # NOTE: doesn't seem to be supported
  # def describe_vlans
  #   get("/offerings/vlan").Vlan
  # end

  # Optionally supply a location to get offerings filtered to a particular location
  # Optionally supply a name (Small, Medium, Large) to get the specific offering
  args :describe_volume_offerings, [{:location => :opt}, {:name => :opt}]
  args :describe_storage_offerings, [{:location => :opt}, {:name => :opt}]
  def describe_storage_offerings(location=nil, name=nil)
    response = get("/offerings/storage")
    if location
      filtered_by_location = response.Offerings.select {|o| o.Location.to_s == location.to_s}
      if name
        filtered_by_location.detect {|o| o.Name == name}
      else
        filtered_by_location
      end
    else
      response.Offerings
    end
  end

  alias describe_volume_offerings describe_storage_offerings

  # Create a volume. offering_id is optional and will be determined automatically
  # for you based on the location and volume size.
  #
  # ex: create_volume("yan", 61, "Small", "20001208", 61)
  #
  # NOTE: storage area id is not currently supported by IBM (according to docs)
  args :create_volume, [{:name => :req},{:location_id => :req},{:size => ['Small','Medium','Large']}, {:offering_id => :opt}, {:format => :opt}]
  def create_volume(name, location, size, offering_id=nil, format="EXT3")

    # figure out the offering ID automatically based on location and size
    if offering_id.nil?
      logger.debug "Looking up volume offerings based on location: #{location} and size: #{size}"
      offering_id = describe_volume_offerings(location, size).ID
    end

    logger.debug "Creating volume...please wait."
    result = post("/storage", :format => format, :location => location, :name => name, :size => size, :offeringID => offering_id)
    result.Volume.ID
  end

  # Optionally takes a volume id, if none supplied, will show all volumes
  args :describe_storage, [{:volume_id => :opt}]
  def describe_storage(volume_id=nil)
    response = volume_id ? get("/storage/#{volume_id}") : get("/storage")

    arrayize(response.Volume).each do |v|
      v["State"] = @states["storage"][v.State.to_i]
    end
  end

  alias describe_volumes describe_storage
  alias describe_volume describe_storage

  # This does a human-usable version of describe_volumes with the critical info (name, id, state)
  # Optionally takes a filter (currently supports state). i.e. display_volumes(:state => :mounted)
  args :display_volumes, [{:filters => :opt}], %{
    Example filters: {:Name => "match-name", :Location => 101}
  }
  def display_volumes(filter={})
    vols = describe_volumes
    vols = filter_and_sort(vols, filter)

    log = "\nVolume | State      | Loc  | Name\n"
    volsz = vols.map {|vol| vol.ID.ljust(6) + " | " + (vol.State[0..9].ljust(10) rescue '?'.ljust(10)) + " | " + vol.Location.ljust(4) + " | " + vol.Name }.join("\n")
    log << volsz
    logger.info log
    true
  end
  
  alias display_storage display_volumes

  # Allows you to poll for a specific storage state
  # ex: storage_state_is?("123456", "UNMOUNTED")
  # storage state string can be given as a string or symbol
  args :storage_state_is?, [{:volume_id => :req}, {:state_string => %w(mounted unmounted etc...)}]
  def storage_state_is?(volume_id, state_string)
    v = describe_storage(volume_id)
    v = v.first if v.is_a?(Array)

    @last_storage_state||={}
    if @last_storage_state[volume_id.to_s] != v.State
      logger.debug "Volume: #{volume_id}; Current State: #{v.State}; Waiting for: #{state_string.to_s.upcase} " # log it every time it changes
    end
    @last_storage_state[volume_id.to_s] = v.State

    if v.State.to_s == state_string.to_s.upcase
      v
    else
      false
    end

  end

  args :instance_state_is?, [{:instance_id=> :req}, {:state_string => %w(active stopping etc...)}]
  def instance_state_is?(instance_id, state_string)
    v = describe_instance(instance_id)

    @last_instance_state||={}
    if @last_instance_state[instance_id.to_s] != v.Status
      logger.debug "Instance: #{instance_id}; Current State: #{v.Status}; Waiting for: #{state_string.to_s.upcase}" # log it every time it changes
    end
    @last_instance_state[instance_id.to_s] = v.Status

    if v.Status.to_s == state_string.to_s.upcase
      v
    else
      false
    end
  end

  # Polls until volume state is matched. When it is, returns entire volume descriptor hash.
  args :poll_for_volume_state, [{:volume_id => :req}, {:state_string => %w(mounted unmounted etc...)}]
  def poll_for_volume_state(volume_id, state_string, polling_interval=5)
    logger.debug "Polling for volume #{volume_id} to acquire state #{state_string} (interval: #{polling_interval})..."
    while(true)
      descriptor = storage_state_is?(volume_id, state_string)
      return descriptor if descriptor
      sleep(polling_interval)
    end
  end

  # Polls until instance state is matched. When it is, returns entire instance descriptor hash.
  args :poll_for_instance_state, [{:instance_id => :req}, {:state_string => %w(active stopped etc...)}]
  def poll_for_instance_state(instance_id, state_string, polling_interval=5)
    logger.debug "Polling for instance #{instance_id} to acquire state #{state_string} (interval: #{polling_interval})..."
    while(true)
      descriptor = instance_state_is?(instance_id, state_string)
      return descriptor if descriptor
      sleep(polling_interval)
    end
  end

  # Deletes many instances in a thread
  args :delete_instances, [:instance_ids], %{
    Example: smartcloud "delete_instances(12345,12346,12347)"
  }
  def delete_instances(*instance_ids)
    threads=[]
    instance_ids.each {|id| logger.info "Sending delete request for: #{id}..."; threads << Thread.new { delete_instance(id) }; logger.info "Finished delete request for #{id}" }
    threads.each(&:join)
    true
  end

  args :rename_instance, [:instance_id, :new_name]
  def rename_instance(instance_id, new_name)
    put("/instances/#{instance_id}", :name => new_name)
  end

  args :delete_instance, [:instance_id]
  def delete_instance(instance_id)
    delete("/instances/#{instance_id}")
    true
  end
  
  args :restart_instance, [:instance_id]
  def restart_instance(instance_id)
    put("/instances/#{instance_id}", :state => "restart")
    true
  end

  args :describe_instance, [:instance_id]
  def describe_instance(instance_id)
    response = get("instances/#{instance_id}").Instance
    response["Status"] = @states["instance"][response.Status.to_i]
    response
  end

  # You can filter by any instance attributes such as
  # describe_instances(:name => "FOO_BAR", :status => 'ACTIVE')
  # in the case of status you can also use symbols like :status => :active
  args :describe_instances, [:filters => :opt]
  def describe_instances(filters={})
    instances = arrayize(get("instances").Instance)
    
    instances.each do |instance|
      instance["Status"] = @states["instance"][instance.Status.to_i]
    end

    filters[:order] ||= "LaunchTime"
    instances = filter_and_sort(instances, filters)
  end

  # Same as describe_instances except prints a human readable summary
  # Also takes an :order param, examples:
  # display_instances(:order => "Name") or :order => "LaunchTime"
  #

  args :display_instances, [:filters => :opt], %{
    Example: smartcloud "display_instances(:name=>'matchMe')"
  }
  def display_instances(filters={})
    instances = describe_instances(filters)

    log = %{#{"Started".ljust(18)} | #{"Instance".ljust(8)} | #{"Image".ljust(9)} | #{"Loc".ljust(3)} | #{"Status".ljust(10)} | #{"KeyName".ljust(15)} | #{"IP".ljust(15)} | #{"Volume".ljust(6)} | Name\n}
    log << instances.map do |ins|
      ip = (ins.IP && ins.IP.to_s) || ""
      ip = (ip.strip == "") ? "[NONE]" : ip.strip
      "#{DateTime.parse(ins.LaunchTime).strftime("%Y-%m-%d %I:%M%p")} | #{ins.ID.ljust(8)} | #{ins.ImageID.ljust(9)} | #{ins.Location.ljust(3)} | #{ins.Status[0..9].ljust(10)} | #{(ins.KeyName || "").strip[0..14].ljust(15)} | #{ip.ljust(15)} | #{(ins.Volume && ins.Volume || "").ljust(6)} | #{ins.Name}" 
    end.join("\n")
    logger.info "\n#{log}"
  end


  args :describe_image, [:image_id]
  def describe_image(image_id)
    image = get("offerings/image/#{image_id}").Image
    image["State"] = @states["image"][image.State.to_i]
    image 
  end

  args :describe_images, [:filters => :opt]
  def describe_images(filters={})
    images = arrayize(get("offerings/image/").Image)
    images.each {|img| img["State"] = @states["image"][img.State.to_i]}
    filters[:order] ||= "Location"
    images = filter_and_sort(images, filters)
  end

  def describe_manifest(image_id)
    get("offerings/image/#{image_id}/manifest").Manifest
  end

  args :display_images, [:filters => :opt]
  def display_images(filters={})
    images = describe_images(filters)

    log = images.map do |i|
      types = arrayize(i.SupportedInstanceTypes.InstanceType).map(&:ID).join(", ") rescue "[INSTANCE TYPE UNKNOWN]"
      "#{i.ID} | #{i.Location} | #{i.Name} | #{types}" 
    end.join("\n")
    logger.info "\n#{log}"
  end

  def delete(path)
    rescue_and_retry_errors do
      output = RestClient.delete File.join(@api_url, path), :accept => :response
      response = XmlSimple.xml_in(output, {'ForceArray' => nil})
    end
  end

  def put(path, params={}, param_remap={})
    rescue_and_retry_errors do
      param_string = make_param_string(params, param_remap)
      output = RestClient.put File.join(@api_url, path), param_string, :accept => :response
      response = XmlSimple.xml_in(output, {'ForceArray' => nil})
    end
  end

  def get(path)
    rescue_and_retry_errors do
      output = RestClient.get File.join(@api_url, path), :accept => :response
      response = XmlSimple.xml_in(output, {'ForceArray' => nil})
    end
  end

  def post(path, params={}, param_remap=nil)
    rescue_and_retry_errors do
      param_string = make_param_string(params, param_remap)
      output = RestClient.post File.join(@api_url, path), param_string, :accept => :response
      response = XmlSimple.xml_in(output, {'ForceArray' => nil})
    end
  end

  private

  # Custom exception matcher
  def timeouts_and_500s
    m = Module.new 
    (class << m; self; end).instance_eval do
      define_method(:===) do |e|
        [RestClient::RequestTimeout, Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, Errno::ETIMEDOUT, 
        EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].include?(e.class)|| e.message =~ /500/
      end
    end
    m
  end
  
  # rest client error details are in the response so we want to
  # display that as the error, otherwise we lose that info
  def rescue_and_retry_errors(&block)
    block.call
  rescue timeouts_and_500s => e
      is_500 = e.message =~ /500/

      @retries -= 1
      if @retries >= 0
        logger.warn e.message
        logger.warn "Caught #{is_500 ? "500" : "Timeout"} Error from cloud API server. Server is down or malfunctioning. Will sleep #{@sleep_interval}s and retry. Retries remaining: #{@retries}..."
        sleep(@sleep_interval)
        retry
      else
        logger.warn "Reached maximum retry limit for this error. Aborting."
        raise e
      end
  rescue => e
    if e.respond_to?(:response) 
      raise "#{e.message} - #{e.response}" 
    else
      raise e
    end
  end

  def make_param_string(params, param_remap) 
    param_string = params.map do |k,v| 
      k=k.to_s # symbol keys turn to string

      # logger.debug "Removing all spaces from parameters, smartcloud API does not allow spaces."
      # v = v.gsub(/\\s+/,'') # remove all spaces! smartcloud does not like spaces in params
      if param_remap && param_remap[k]
        k = param_remap[k]
      end

      "#{CGI.escape(k)}=#{CGI.escape(v.to_s)}"
    end.compact.join("&")
  end

  def filter_and_sort(instances=[], filters={})
    order_by = filters.delete(:order) 

    filters.each do |filter, value|
      value = value.to_s.upcase if (filter==:status || filter==:state)
      if filter == :name || filter == :Name
        instances = instances.select {|inst| inst.send(filter.to_s.capitalize) =~ /#{value}/}
      else
        instances = instances.select {|inst| inst.send(filter.to_s.capitalize) == value.to_s}
      end
    end

    instances = instances.sort_by{|ins| 
      if ins.has_key?(order_by) 
        order_by_value = ins.send(order_by) 
        integer_sort = order_by_value.to_i
        # If we are trying to sort by an integer field, i.e. 41.to_s=="41" then sort by the integer
        # version of it, otherwise sort by the original string
        order_by_value = (order_by_value == integer_sort.to_s) ? integer_sort : order_by_value
      else
        0 
      end
    }
    if order_by == "LaunchTime"
      instances = instances.reverse
    end
    
    instances
  end

  def arrayize(array_or_object)
    return [] unless array_or_object
    array_or_object.is_a?(Array) ? array_or_object : [array_or_object]
  end

end

# predefine an instance for convenience
@smartcloud = IBMSmartCloud.new
