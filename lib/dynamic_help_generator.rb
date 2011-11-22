module DynamicHelpGenerator

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def help_for(method, args, extra_help="")
      @method_help||={}
      @method_help_supplemental||={}
      @method_help[method.to_s] = args
      @method_help_supplemental[method.to_s] = extra_help
    end

    attr_reader :method_help
    attr_reader :method_help_supplemental
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

        puts %{  * #{method.to_s}#{'(' + args + ')' if args}#{extra_help}}
    else
      # These verbs help us figure out what 'group' the method belongs to
      verbs = %w(describe display create get allocate clone export attach detach delete generate update remove restart rename)
      verb_noun = /(#{verbs.join('|')})_(.*)(s|es)?/ # we're going to remove the verb and trailing 's'

      methods = public_methods - Object.public_methods - ['post','get','put','delete','logger','logger=','help']

      # Group methods by the noun they operate on 
      methods_grouped_by_noun = methods.inject({}) do |h, method| 
        method_name, verb, noun = *(method.match(verb_noun))
        if method_name.nil?
          # match failed
          method_name = method
          noun = "misc"
        end
        synonyms = {
          :keypair => :key,
          :address_offering => :address,
          :location_by_name => :location,
          :storage_offering => :storage,
          :volume => :storage,
          :volume_offering => :storage,
        }
        noun.gsub!(/s$/,'') unless noun =~ /address/
        if synonyms.keys.include?(noun.to_sym)
          noun = synonyms[noun.to_sym].to_s
        end
        h[noun] ||= []
        h[noun] << method_name
        h
      end
      methods_grouped_by_noun.keys.sort.each do |noun|
        methods = methods_grouped_by_noun[noun]
        next unless methods
        puts "== #{noun.capitalize} ==\n\n"
        methods.sort.each {|m| help(m)}
        puts
      end
      nil
    end
  end
end
