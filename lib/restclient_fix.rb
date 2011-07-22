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

