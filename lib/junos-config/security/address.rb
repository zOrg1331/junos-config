module JunosConfig
  module Security
    class Address
      attr_accessor :raw,
                    :config,
                    :name,
                    :ip
    
      def initialize(config, raw, shift)
        @config = config
        @raw    = raw
        m = raw.match(/^\ {#{shift}}address (\S+)\ (\S+);/)
        @name = m[1]
        @ip = m[2]
      end
    end
  end
end
