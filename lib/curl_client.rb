class CurlHttpClient
  # For compatibility with RestClient
  class << self
    attr_accessor :timeout
    attr_accessor :log

    @timeout ||= 120
  end

  def self.logger; @logger ||= Logger.new(STDOUT); end

  def self.get(url)
    handle_output(curl(url))
  end

  def self.post(url, data, options={}) 
    handle_output(curl(%{ #{url} -d "#{data}" }))
  end

  def self.put(url, data, options={}) 
    handle_output(curl(%{ #{url} -XPUT -d #{data} }))
  end

  def self.delete(url, options={}) 
    handle_output(curl(%{ #{url} -XDELETE}))
  end

  def self.curl(cmd)
    @log.debug "curl #{cmd}" if @log
    `curl -s --insecure --connect-timeout #{@timeout} #{cmd} 2>&1`
  end

  def self.handle_output(output)
    if output =~ /^Error/
      logger.error output
      raise output
    else
      output
    end
  end
end
