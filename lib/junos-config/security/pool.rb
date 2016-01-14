module JunosConfig
  module Security
    class Pool
      attr_accessor :raw,
                    :config,
                    :name,
                    :ip,
                    :port
    
      def initialize(config, raw)
        @config = config
        @raw    = raw
        m = raw.match(/^\ {12}pool (\S+)\ \{/)
        @name = m[1]
        if raw.match(/^\ {16}address \{/)
          m = raw.match(/^\ {16}address \{$.*?\ {20}(\S+);/m)
          @ip = m[1]
        else
          m = raw.match(/^\ {16}address (\S+);/)
          @ip = m[1] if m
          m = raw.match(/^\ {16}address (\S+) port (\S+);/)
          @ip = m[1] if m
          @port = m[2] if m
        end
      end
    end
  end
end
