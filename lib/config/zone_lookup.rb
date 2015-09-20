require 'yaml'
module Config
  class ZoneLookup
    def initialize(zone_hash)
      @zone_hash = zone_hash
    end

    def zone_for(component)
      @zone_hash.find { |zone, components| components.include?(component) }[0]
    end
  end
end