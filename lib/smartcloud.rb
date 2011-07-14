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

IBM_TOOLS_HOME=File.join(File.dirname(__FILE__), "cli_tools") unless defined?(IBM_TOOLS_HOME)

# Encapsulates communications with IBM SmartCloud via REST
class IBMSmartCloud

  attr_accessor :logger

  def initialize(username, password, logger=nil, debug=false)
    @username = username
    @password = password
    @logger = logger || Logger.new(STDOUT)
    @debug = debug

    @config = YAML.load_file(File.join(File.dirname(__FILE__), "config/config.yml"))
    @states = @config["states"]

    @api_url = @config["api_url"]
    @api_url.gsub!("https://", "https://#{CGI::escape(username)}:#{CGI::escape(password)}@")

    RestClient.timeout = 120 # ibm requests can be very slow
    RestClient.log = @logger if @debug
  end

  def help
    puts [public_methods - Object.public_methods].join("\n")
  end

  # Get a list of data centers
  def describe_locations
    get("/locations").Location
  end

  def display_locations
    log = describe_locations.map {|loc| "#{loc.ID} #{loc.Location}"}.join("\n")
    logger.info "\n#{log}"
  end

  # Create an instance. The instance_params hash can follow
  # CLI-style attribute naming. I.e. "image-id" or "data-center"
  # or API-style (imageID, location). If the CLI-style params are
  # provided, they will be remapped to the correct API params.
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
    # <configuration>{contextmanager:baml-c3-master.cohesiveft.com,clustername:BAML_poc_pk0515,role:[nfs-client-setup|newyork_master_refdata_member|install-luci|rhel-openlikewise-client-setup|join-domain],hostname:r550n107}</configuration> 
    # to a standard list of POST params like
    # contextmanager=baml-c3-mager&clustername=BAML...
    configuration_data = instance_params.delete("configuration") || instance_params.delete("ConfigurationData") 
    if configuration_data
      if configuration_data =~ /\s+/
        logger.warn "<configuration> tag should not contain spaces! Correct format looks like: <configuration>{foo:bar,baz:quux}</configuration>. Spaces will be removed."
      end
      configuration_data.delete!("{}") # get rid of curly braces
      config_data_params = configuration_data.split(",").map{|param| param.split(":")} # split each foo:bar into key and value
      config_data_params.each {|k,v| instance_params[k]=v} # add it into the standard instance params array
    end

    post "/instances", instance_params, param_remap
  end

  # Find a location by its name. Assumes locations have unique names (not verified by ibm docs)
  def get_location_by_name(name)
    locations = describe_locations
    locations.detect {|loc| loc.Name == name}
  end

  # find all ip address offerings. If a location is specified, give the offering for the location
  # assumption: only one offering per location. This is assumed, not verified in docs.
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
  def allocate_address(location, offering_id=nil)
    if offering_id.nil?
      offering_id = describe_address_offerings(location).ID
    end
    post("/addresses", :offeringID => offering_id, :location => location).Address
  end

  def describe_address(address_id)
    address = get("/addresses/#{address_id}").Address
    address["State"] = @config.states.ip[address.State]
    address
  end

  # Launches a clone image call from CLI
  def clone_image(name, description, image_id)
    post("/offerings/image/#{image_id}", :name => name, :description => description).ImageID
  end

  # Launches a clone request and returns ID of new volume
  # TODO: the API call does not work, we have to use the cli for now
  def clone_volume(name, source_disk_id, location=nil)
    # result = post("/storage", :name => name, :SourceDiskID => source_disk_id)
    # result.Volume.ID
    create_password_file
    result = run_ibm_tool("ic-clone-volume.sh -n #{name} -S #{source_disk_id}")
    result =~ /ID : (.*)/
    return $1 # grab the id of the created volume
  end

  # Delete the volume
  def delete_volume(vol_id)
    delete("/storage/#{vol_id}")
    true
  end

  # generates a keypair and returns the private key
  def generate_keypair(name)
    response = post("/keys", :name => name)
    response.PrivateKey.KeyMaterial
  end

  def remove_keypair(name)
    delete("/keys/#{name}")
    true
  end

  def describe_key(name)
    get("/keys/#{name}").PublicKey
  end

  # If address_id is supplied, will return info on that address only
  def describe_addresses(address_id=nil)
    response = get("/addresses").Address
    response.each do |a|
      a["State"] = @states["ip"][a.State.to_i]
    end
    if address_id
      response = response.detect {|address| address.ID.to_s == address_id.to_s}
    end
    response
  end

  # Allows you to poll for a specific storage state
  # ex: storage_state_is?("123456", "UNMOUNTED")
  # storage state string can be given as a string or symbol
  def address_state_is?(address_id, state_string)
    v = describe_addresses(address_id)
    v.State.to_s == state_string.to_s.upcase
  end

  def describe_keys
    get("/keys").PublicKey
  end

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
  def describe_volume_offerings(location=nil, name=nil)
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

  # Create a volume. offering_id is optional and will be determined automatically
  # for you based on the location and volume size.
  #
  # ex: create_volume("yan", 61, "Small", "20001208", 61)
  #
  # NOTE: storage area id is not currently supported by IBM (according to docs)
  def create_volume(name, location, size, offering_id=nil, format="EXT3")

    # figure out the offering ID automatically based on location and size
    if offering_id.nil?
      logger.debug "Looking up volume offerings based on location: #{location} and size: #{size}"
      offering_id = describe_volume_offerings(location, size).ID
    end

    result = post("/storage", :format => format, :location => location, :name => name, :size => size, :offeringID => offering_id)
    result.Volume.ID
  end

  # Optionally takes a volume id, if none supplied, will show all volumes
  def describe_storage(volume_id=nil)
    response = volume_id ? get("/storage/#{volume_id}") : get("/storage")

    if response.Volume.is_a?(Array)
      response.Volume.each do |v|
        v["State"] = @states["storage"][v.State.to_i]
      end
    elsif response.Volume
      response.Volume["State"] = @states["storage"][response.Volume.State.to_i]
    else
      return []
    end

    response.Volume
  end

  alias describe_volumes describe_storage
  alias describe_volume describe_storage

  # This does a human-usable version of describe_volumes with the critical info (name, id, state)
  # Optionally takes a filter (currently supports state). i.e. display_volumes(:state => :mounted)
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
  def storage_state_is?(volume_id, state_string)
    v = describe_storage(volume_id)

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
  def poll_for_volume_state(volume_id, state_string, polling_interval=5)
    logger.debug "Polling for volume #{volume_id} to acquire state #{state_string} (interval: #{polling_interval})..."
    while(true)
      descriptor = storage_state_is?(volume_id, state_string)
      return descriptor if descriptor
      sleep(polling_interval)
    end
  end

  # Polls until instance state is matched. When it is, returns entire instance descriptor hash.
  def poll_for_instance_state(instance_id, state_string, polling_interval=5)
    logger.debug "Polling for instance #{instance_id} to acquire state #{state_string} (interval: #{polling_interval})..."
    while(true)
      descriptor = instance_state_is?(instance_id, state_string)
      return descriptor if descriptor
      sleep(polling_interval)
    end
  end

  # Deletes many instances in a thread
  def delete_instances(instance_ids)
    instance_ids.each {|id| delete_instance(id) }
  end


  def delete_instance(instance_id)
    delete("/instances/#{instance_id}")
    true
  end
  
  def restart_instance(instance_id)
    put("/instances/#{instance_id}", :state => "restart")
    true
  end

  def describe_instance(instance_id)
    response = get("instances/#{instance_id}").Instance
    response["Status"] = @states["instance"][response.Status.to_i]
    response
  end

  # You can filter by any instance attributes such as
  # describe_instances(:name => "FOO_BAR", :status => 'ACTIVE')
  # in the case of status you can also use symbols like :status => :active
  def describe_instances(filters={})
    instances = get("instances").Instance
    
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
  def display_instances(filters={})
    instances = describe_instances(filters)

    log = %{#{"Started".ljust(24)} | #{"Instance".ljust(8)} | #{"Image".ljust(9)} | #{"Location".ljust(8)} | #{"Status".ljust(10)} | #{"IP".ljust(15)} | Name\n} 
    log << instances.map do |ins|
      "#{ins.LaunchTime} | #{ins.ID.ljust(8)} | #{ins.ImageID.ljust(9)} | #{ins.Location.ljust(8)} | #{ins.Status[0..9].ljust(10)} | #{(ins.IP.strip=="" ? '[NONE]' : ins.IP.strip).to_s.ljust(15)} | #{ins.Name}"
    end.join("\n")
    logger.info "\n#{log}"
  end


  def describe_image(image_id)
    image = get("offerings/image/#{image_id}").Image
    image["State"] = @states["image"][image.State.to_i]
    image 
  end

  def describe_images(filters={})
    images = get("offerings/image/").Image
    images.each {|img| img["State"] = @states["image"][img.State.to_i]}
    filters[:order] ||= "Location"
    images = filter_and_sort(images, filters)
  end

  def display_images(filters={})
    images = describe_images(filters)

    log = images.map do |i|
      types = arrayize(i.SupportedInstanceTypes.InstanceType).map(&:ID).join(", ") rescue "[INSTANCE TYPE UNKNOWN]"
      "#{i.ID} | #{i.Location} | #{i.Name} | #{types}" 
    end.join("\n")
    logger.info "\n#{log}"
  end

  def delete(path)
    output = RestClient.delete File.join(@api_url, path), :accept => :response
    response = XmlSimple.xml_in(output, {'ForceArray' => nil})
  rescue => e
    raise_restclient_error(e)
  end

  def put(path, params={}, param_remap={})
    param_string = make_param_string(params, param_remap)
    output = RestClient.put File.join(@api_url, path), param_string, :accept => :response
    response = XmlSimple.xml_in(output, {'ForceArray' => nil})
  rescue => e
    raise_restclient_error(e)
  end

  def get(path)
    output = RestClient.get File.join(@api_url, path), :accept => :response
    response = XmlSimple.xml_in(output, {'ForceArray' => nil})
  rescue => e
    raise_restclient_error(e)
  end

  def post(path, params={}, param_remap=nil)
    param_string = make_param_string(params, param_remap)
    output = RestClient.post File.join(@api_url, path), param_string, :accept => :response
    response = XmlSimple.xml_in(output, {'ForceArray' => nil})
    response
  rescue => e
    raise_restclient_error(e)
  end

  # rest client error details are in the response so we want to
  # display that as the error, otherwise we lose that info
  def raise_restclient_error(e)
    if e.respond_to?(:response) && !e.is_a?(RestClient::RequestTimeout)
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

  protected

  def filter_and_sort(instances=[], filters={})
    order_by = filters.delete(:order) 

    filters.each do |filter, value|
      value = value.to_s.upcase if (filter==:status || filter==:state)
      instances = instances.select {|inst| inst.send(filter.to_s.capitalize) == value.to_s}
    end

    instances = instances.sort_by{|ins| ins.has_key?(order_by) ? ins.send(order_by) : 0 }
    if order_by == "LaunchTime"
      instances = instances.reverse
    end
    
    instances
  end

  def arrayize(array_or_object)
    return [] unless array_or_object
    array_or_object.is_a?(Array) ? array_or_object : [array_or_object]
  end

  # TODO: all methods below here can be nuked once CLI tools are removed
  def run_ibm_tool(command)
    cmd = "cd #{IBM_TOOLS_HOME} && ./#{command} -u #{@username} -w #{passphrase} -g #{password_file}"
    logger.debug cmd
    output = if @debug
      IBMMockResponseGenerator.respond(command)
    else
      `#{cmd}` 
    end

    logger.debug output

    if output =~ /ErrorMessage : (.*)/
      raise $1 # raise the error message matched above
    else
      return output
    end
  end
 
  def create_password_file
    # if no passphrase or password file is supplied, we'll generate it
    run_ibm_tool("ic-create-password.sh -u #{@username} -p #{@password}")
  end

  def password_file
    @password_file ||= "/tmp/smrtcloud-pwfile-#{Time.now.to_i.to_s}"
  end

  def passphrase
    @passphrase ||= Time.now.to_i.to_s
  end
  # End CLI tool helpers 
  
  

end

# predefine an instance for convenience
@smartcloud = IBMSmartCloud.new(ENV['SMARTCLOUD_USERNAME'], ENV['SMARTCLOUD_PASSWORD']) if ENV['SMARTCLOUD_USERNAME'] && ENV['SMARTCLOUD_PASSWORD']
