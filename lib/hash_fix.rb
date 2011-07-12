#####################################################################################
# Copyright (c) 2010, Cohesive Flexible Technologies, Inc.
# This copyrighted material is the property of Cohesive Flexible Technologies and
# is subject to the license terms of the product it is contained within, whether 
# in text or compiled form.  It is licensed under the terms expressed in the 
# accompanying README and LICENSE files.
# 
# This program is AS IS and WITHOUT ANY WARRANTY; without even the implied warranty 
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#####################################################################################

class Hash
  def method_missing(meth, *args, &block)
    if args.size == 0
      dashed = meth.to_s.gsub(/_/, '-')
      self[meth] || self[dashed] || self[dashed.to_sym] || super(meth, *args, &block) rescue nil
    end
  end
end

module Enumerable
  def dups
    inject({}) {|h,v| h[v]=h[v].to_i+1; h}.reject{|k,v| v==1}.keys
  end
end