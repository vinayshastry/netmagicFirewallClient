require 'yaml'
module Config
  class ZoneLookup
  	def initialize(file)
  		@zone_hash = YAML.load_file(file)
  	end

  	def zone_for(component)
  		@zone_hash.find{ |zone, components| components.include?(component) }[0]
  	end
  end
end