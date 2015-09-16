require './lib/security/netmagic/firewall'
require './lib/config/security_config'
require './lib/config/zone_lookup'
require 'json'
require 'yaml'

def add_rule(dependency, ip_hash, zone_lookup)
	src_zone = zone_lookup.zone_for(dependency["src_vm"])
	dest_zone = zone_lookup.zone_for(dependency["dest_vm"])

	src_ip = ip_hash[dependency["src_vm"]]["ip"]
	dest_ip_ports = ip_hash[dependency["dest_vm"]]
	dest_ip = dest_ip_ports["ip"]

	firewall = Security::Netmagic::Firewall.new(Config::SecurityConfig.new)

	puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
	dest_ip_ports["ports"].each do |port|
		firewall.add_rule(src_zone, src_ip, dest_zone, dest_ip, port, dependency["rule_number"])		
	end

	# puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
	# firewall.delete_rule("5", "WEB-Zone", "APP-Zone")
	# puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
end

# dependency_json = File.read("config/dependency_lookup.json")
# dependency_hash = JSON.parse(dependency_json)
dependencies = YAML.load_file("config/dependencies_lookup.yml")["dependencies"]
ip_hash = YAML.load_file("config/ip_lookup.yml")

zone_lookup = Config::ZoneLookup.new("config/zone_lookup.yml")

for dependency in dependencies
	add_rule(dependency, ip_hash, zone_lookup)
end