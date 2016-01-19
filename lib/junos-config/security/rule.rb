module JunosConfig
  module Security
    class Rule
      attr_accessor :raw,
                    :config,
                    :name,
                    :src_addr,
                    :dst_addr,
                    :dst_port,
                    :action,
                    :target_pool,
                    :target_pool_ip,
                    :target_pool_port
    
      def initialize(config, raw)
        @config = config
        @raw    = raw
        m = raw.match(/^\ {16}rule (\S+)\ \{/)
        @name = m[1]

        m = raw.match(/^\ {24}source\-address (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @src_addr = s
        end

        m = raw.match(/^\ {24}destination\-address (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @dst_addr = s
        end

        m = raw.match(/^\ {24}destination\-port (\S+);/)
        @dst_port = m[1] if m

        m = raw.match(/^(\ {20}then\ \{$.*?^\ {20}\})/m)
        action_sect = m[1]
        
        if action_sect.match(/^\ {24}source-nat \{/)
          @action = "snat"

          m = action_sect.match(/^\ {24}source-nat \{$(.*?)^\ {24}\}/m)
          action_payload = m[1]

          if action_payload.include?("off")
            @target_pool = "off"
          elsif action_payload.include?("interface")
            @target_pool = "interface"
          elsif action_payload.match(/^\ {28}pool\ \{/)
            m = action_payload.match(/^\ {28}pool\ \{$.*?^\ {32}(\S+);/m)
            @target_pool = m[1]
          end
        elsif action_sect.match(/^\ {24}destination\-nat\ /)
          m = action_sect.match(/^\ {24}destination\-nat\ pool\ (\S+);/)
          @action = "dnat"
          @target_pool = m[1]
        elsif action_sect.match(/^\ {24}static-nat \{/)
          @action = "stnat"

          m = action_sect.match(/^\ {24}static-nat \{$(.*?)^\ {24}\}/m)
          action_payload = m[1]

          m = action_payload.match(/^\ {28}prefix \{$(.*?)^\ {28}\}/m)
          prefix = m[1]

          m = prefix.match(/^\ {32}(\d\S+);/)
          @target_pool = m[1]
        end

        @target_pool_ip = @target_pool
        @target_pool_port = ""
        @config.config.pools.each do |p|
          if p.name == @target_pool
            @target_pool_ip = p.ip
            @target_pool_port = p.port
            break
          end
        end
      end
    end
  end
end
