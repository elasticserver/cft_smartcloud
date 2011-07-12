# Enables modification of timeout in RestClient
module RestClient

  class << self
    attr_accessor :timeout
  end

  def self.get(url, headers={}, &block)
    Request.execute(:method => :get, :url => url, :headers => headers, :timeout => @timeout, &block)
  end

  def self.post(url, payload, headers={}, &block)
    Request.execute(:method => :post, :url => url, :payload => payload, :headers => headers, :timeout => @timeout, &block)
  end

  def self.patch(url, payload, headers={}, &block)
    Request.execute(:method => :patch, :url => url, :payload => payload, :headers => headers, :timeout => @timeout, &block)
  end

  def self.put(url, payload, headers={}, &block)
    Request.execute(:method => :put, :url => url, :payload => payload, :headers => headers, :timeout => @timeout, &block)
  end

  def self.delete(url, headers={}, &block)
    Request.execute(:method => :delete, :url => url, :headers => headers, :timeout => @timeout, &block)
  end
  
end

