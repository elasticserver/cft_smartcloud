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

class SmartcloudLogger < Logger
  def format_message(severity, timestamp, foobar, message) 
    message = message.to_s 
    
    "#{timestamp.strftime("%b %d %H:%M:%S")} #{severity}: #{message}\n"
  end 

end
