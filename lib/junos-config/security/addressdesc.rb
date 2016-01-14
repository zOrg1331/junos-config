module JunosConfig
  module Security
    class AddressDesc
      attr_accessor :raw,
                    :config,
                    :name,
                    :ip,
                    :desc
    
      def initialize(config, raw, shift)
        @config = config
        @raw    = raw
        m = raw.match(/^\ {#{shift}}address (\S+) \{$.*?\}$/m)
        @name = m[1]
        m = raw.match(/^\ {#{shift + 4}}description\ (.*)\;/)
        @desc = m[1] if m
        m = raw.match(/^\ {#{shift + 4}}(\d\S+)\;/)
        @ip = m[1] if m
      end
    end
  end
end
