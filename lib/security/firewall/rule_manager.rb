require './lib/security/firewall/netmagic_client'
require './lib/config/security_config'
require './lib/config/zone_lookup'
require 'json'
require 'yaml'
module Security
	module Firewall
		class RuleManager
			def add_rule(dependency, ip_hash, zone_lookup)
				src_zone = zone_lookup.zone_for(dependency["src_vm"])
				dest_zone = zone_lookup.zone_for(dependency["dest_vm"])

				src_ip = ip_hash[dependency["src_vm"]]["ip"]
				dest_ip_ports = ip_hash[dependency["dest_vm"]]
				dest_ip = dest_ip_ports["ip"]

				firewall = Security::Firewall::NetmagicClient.new(Config::SecurityConfig.new)

				dependency_specific_existing_rules = firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
				puts "[DEBUG] dependency_specific_existing_rules =>#{dependency_specific_existing_rules}"

				rule_numbers = generate_rule_numbers(dependency_specific_existing_rules, dest_ip_ports["ports"].count)

				dest_ip_ports["ports"].each_with_index do |port, i|
					firewall.add_rule(src_zone, src_ip, dest_zone, dest_ip, port, rule_numbers[i])
				end

				puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
				# firewall.delete_rule("5", "WEB-Zone", "APP-Zone")
				# puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }
			end

			def generate_rule_numbers(dependency_specific_existing_rules, count)
				existing_rule_numbers = dependency_specific_existing_rules.map { |rule| rule["ruleno"] }
				missing_rule_numbers = (2001..9999).to_a - existing_rule_numbers #rule number between 2001 to 9999 are considered as explicitly added rules in netmagic
				missing_rule_numbers[0..count]
			end
		end
	end
end

# dependency_json = File.read("config/dependency_lookup.json")
# dependency_hash = JSON.parse(dependency_json)
dependencies = YAML.load_file("config/dependencies_lookup.yml")["dependencies"]
ip_hash = YAML.load_file("config/ip_lookup.yml")

zone_lookup = Config::ZoneLookup.new("config/zone_lookup.yml")

for dependency in dependencies
	add_rule(dependency, ip_hash, zone_lookup)
end