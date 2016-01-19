module JunosConfig
  module Security
    class Nat
      attr_accessor :raw,
                    :config,
                    :pools,
                    :rulesets,
                    :priv_pub_map,
                    :pub_priv_map
      
      def initialize(config, raw)
        @config    = config
        @raw       = raw

        @pools = raw.scan(/^(\ {12}pool\ \S+ \{$.*?^\ {12}\})$/m).collect do |x|
          Security::Pool.new self, x[0]
        end

        @rulesets = raw.scan(/^(\ {12}rule\-set\ \S+ \{$.*?^\ {12}\})$/m).collect do |x|
          Security::Ruleset.new self, x[0]
        end

        @priv_pub_map = {}
        @pub_priv_map = {}
        @rulesets.each do |rs|
          rs.rules.each do |r|
            next if not r.dst_addr
            @priv_pub_map[r.target_pool_ip] = r.dst_addr[0]
            @pub_priv_map[r.dst_addr[0]] = r.target_pool_ip
          end
        end
      end
    end
  end
end
