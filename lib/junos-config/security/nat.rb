module JunosConfig
  module Security
    class Nat
      attr_accessor :raw,
                    :config,
                    :pools,
                    :rulesets
      
      def initialize(config, raw)
        @config    = config
        @raw       = raw

        @pools = raw.scan(/^(\ {12}pool\ \S+ \{$.*?^\ {12}\})$/m).collect do |x|
          Security::Pool.new self, x[0]
        end

        @rulesets = raw.scan(/^(\ {12}rule\-set\ \S+ \{$.*?^\ {12}\})$/m).collect do |x|
          Security::Ruleset.new self, x[0]
        end
      end

      def pool_ip_from_name(name)
        @pools.each do |p|
          return p.ip if p.name == name
        end
        return name
      end

      def pool_port_from_name(name)
        @pools.each do |p|
          return p.port if p.name == name
        end
        return ""
      end
    end
  end
end
