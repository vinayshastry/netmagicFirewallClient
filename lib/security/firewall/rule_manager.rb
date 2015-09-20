require './lib/security/firewall/netmagic_client'
require './lib/config/security_config'
require './lib/config/zone_lookup'
require 'json'
require 'yaml'

module Security
  module Firewall
    class RuleManager
      def initialize(firewall_client)
        @firewall_client = firewall_client
      end

      # takes the rules grouped by route. in the form:
      # [
      # {
      #   "srcIpZone" => "src_zone",
      #   "destIpZone" => "dest_zone",
      #   "rules" : [
      #         {"sourceIp" => "x.x.x.x", "destinationIp" => "y.y.y.y", "destPort" => 123},
      #         ....
      #     ]
      # },
      # {
      #   "srcIpZone" => "some_other_src_zone",
      #   "destIpZone" => "some_other_dest_zone",
      #   "rules" : [
      #         ....
      #     ]
      # },
      # ...
      # ]
      # done so as to avoid too much network calls to find out apt rule numbers; for a route(from a source zone to a dest zone)
      # getting rules associated to a route in one place will help in bulk generation of rule numbers
      private def add_rules(route_grouped_rules)
        for route_grouped_rule in route_grouped_rules do
          src_zone = route_grouped_rule['srcIpZone']
          dest_zone = route_grouped_rule['destIpZone']
          existing_rules = @firewall_client.get_rules.select { |rule| rule['srcIpZone'] == src_zone && rule['destIpZone'] == dest_zone }
          rule_numbers = generate_rule_numbers(existing_rules, route_grouped_rule['rules'].count)

          route_grouped_rule["rules"].each_with_index.map do |rule, i|
            begin
              @firewall_client.add_rule(src_zone, rule['sourceIp'], dest_zone, rule['destinationIp'], rule['destPort'], rule_numbers[i])
            rescue => e
              "<Response success='Failure'>#{e.inspect}</Response>"
            end
          end
        end
      end

      def sync_rules(dependencies, ip_lookup, zone_lookup)
        compiled_rules = compile_rules(dependencies, ip_lookup, zone_lookup)

        compiled_rules_set = compiled_rules.uniq
        existing_rules_set = trim_unwanted_keys(get_configured_rules.uniq)

        new_rules_set = compiled_rules_set - existing_rules_set
        obsolete_rules_set = existing_rules_set - compiled_rules_set

        add_rules(group_by_route(new_rules_set))
        # delete_rules(obsolete_rules_set)

        {:added => new_rules_set, :removed => obsolete_rules_set}
      end

      # def delete_rules(unwanted_rules_set)
      # end

      # done so that can be consumed by add rule
      private def group_by_route(rules)
        group_by_fields = ["srcIpZone", 'destIpZone']

        rules.group_by { |hash| hash.values_at(*group_by_fields) }.inject([]) do |route_grouped_rules, (zones, route_rules)|
          route_grouped_rule = {
              'srcIpZone' => zones[0],
              'destIpZone' => zones[1],
              'rules' => route_rules
          }
          route_grouped_rules << route_grouped_rule
        end
      end

      private def get_configured_rules
        @firewall_client.get_rules.select { |rule| rule["ruleno"] > 2000 && rule["ruleno"] < 10000 }
      end

      # needed as the compiled rules don't contain the mentioned keys and we don't want it to come up as differentiating factor when we apply '-' operator
      private def trim_unwanted_keys(existing_rules)
        for rule in existing_rules do
          rule.delete_if { |key| ["ruleno", "ruletype", "fwCompId", "protocol"].any? { |unwanted_key| unwanted_key == key } }
        end
      end

      private def compile_rules(dependencies, ip_lookup, zone_lookup)
        dependencies.inject([]) do |deps_to_rule, dependency|
          dependency.to_hash
          deps_to_rule << convert_dependency_to_rule(dependency, ip_lookup, zone_lookup)
          # we get an array from convert_dependency_to_rule and that results in array of array of hashes; whereas an array of hashes is expected
          deps_to_rule.flatten
        end
      end

      private def convert_dependency_to_rule(dependency, ip_lookup, zone_lookup)
        dependency.inject([]) do |rules, (src_component, dest_components)|
          dest_components.each do |dest_component|
            src_zone = zone_lookup.zone_for(src_component)
            dest_zone = zone_lookup.zone_for(dest_component)
            next if src_zone == dest_zone

            src_ip = ip_lookup[src_component]["ip"]
            dest_ip_ports = ip_lookup[dest_component]

            get_port_specific_rules(dest_ip_ports, dest_zone, rules, src_ip, src_zone)
          end

          rules
        end
      end

      private def get_port_specific_rules(dest_ip_ports, dest_zone, rules, src_ip, src_zone)
        for port in dest_ip_ports["ports"] do
          rules << {"srcIpZone" => src_zone, "destIpZone" => dest_zone,
                    "sourceIp" => src_ip, "destinationIp" => dest_ip_ports["ip"], "destPort" => port
          }
        end

        rules
      end

      private def generate_rule_numbers(existing_rules, count)
        existing_rule_numbers = existing_rules.map { |rule| rule["ruleno"] }
        missing_rule_numbers = (2001..9999).to_a - existing_rule_numbers #rule number between 2001 to 9999 are considered as explicitly added rules set in netmagic
        missing_rule_numbers[0..count]
      end

    end
  end
end