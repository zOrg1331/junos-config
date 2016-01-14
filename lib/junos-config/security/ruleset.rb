module JunosConfig
  module Security
    class Ruleset
      attr_accessor :raw,
                    :config,
                    :name,
                    :from_zone,
                    :from_int,
                    :to_zone,
                    :to_int,
                    :rules
    
      def initialize(config, raw)
        @config = config
        @raw    = raw
        m = raw.match(/^\ {12}rule\-set (\S+)\ \{/)
        @name = m[1]

        m = raw.match(/^\ {16}from zone (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @from_zone = s
        end

        m = raw.match(/^\ {16}from interface (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @from_int = s
        end

        m = raw.match(/^\ {16}to zone (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @to_zone = s
        end

        m = raw.match(/^\ {16}to interface (.*);/)
        if m
          s = m[1].split(" ")
          s = s.slice(1,s.length-2) if s.length > 1
          @to_int = s
        end

        @rules = raw.scan(/^(\ {16}rule\ \S+ \{$.*?^\ {16}\})$/m).collect do |x|
          Security::Rule.new self, x[0]
        end
      end
    end
  end
end
