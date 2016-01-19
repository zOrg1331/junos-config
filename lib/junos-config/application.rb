module JunosConfig
  class Application
    attr_accessor :raw,
                  :config,
                  :name,
                  :target
    
    def initialize(config, raw, shift)
      @config = config
      @raw    = raw
      @name   = raw.match(/^\ {#{shift}}application (\S+)\ \{$/)[1]

      m = raw.match(/^\ {#{shift+4}}protocol (\S+);$/m)
      proto = m[1] if m
      m = raw.match(/^\ {#{shift+4}}destination\-port (\S+);$/m)
      dst_port = m[1] if m

      @target = (proto and dst_port) ? "#{proto}/#{dst_port}," : ""
      raw.scan(/^(\ {#{shift+4}}term (\S+) protocol (\S+) source\-port (\S+) destination\-port (\S+);)$/).collect do |x|
        @target += "#{x[2]}/#{x[4]},"
      end
      raw.scan(/^(\ {#{shift+4}}term (.*) protocol (\S+) destination\-port (\S+);)$/).collect do |x|
        @target += "#{x[2]}/#{x[3]},"
      end
      @target.chomp!(',')
    end
    
    def to_s
      (@target.size > 0) ? @target : @name
    end
    
    def list_of_objects
      [self]
    end
    
    def details
      "#{name}: #{raw}"
    end
    
  end

  class ApplicationSet
    attr_accessor :raw,
                  :config,
                  :name,
                  :applications
    
    def initialize(config, raw, shift)
      @config = config
      @raw    = raw
      @name   = raw.match(/^\ {#{shift}}application\-set (\S+)\ \{$/)[1]
      @applications = raw.scan(/^(\ {#{shift+4}}application (\S+);)$/).collect do |x|
        config.application(x[1])
      end
    end
    
    def to_s
      @name
    end    
    
    def list_of_objects
      applications
    end
    
  end

end

class String
  
  def list_of_objects
    [self]
  end
  
  def details
    to_s
  end
end
