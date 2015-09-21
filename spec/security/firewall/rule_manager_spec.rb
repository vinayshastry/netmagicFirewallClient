require "nokogiri"
require "./lib/security/firewall/rule_manager"
require "./lib/security/firewall/netmagic_client"
require "./lib/config/zone_lookup"

RSpec.configure do |config|
  config.mock_framework = :rspec
end

describe "RuleManager" do
  $debug = true

  it "syncs by adding new rules with firewall client" do
    nm_client_mock = spy("nm_client")
    expect(nm_client_mock).to receive('get_rules').and_return([])
    rule_manager = Security::Firewall::RuleManager.new(nm_client_mock)

    dependencies = [{"src_comp1" => ["dest_comp1", "dest_comp2"], "src_comp2" => ["dest_comp3"]}]

    src_ip = "10.12.213.4"
    dest_ip = "10.12.213.1"
    ip_lookup = {
        "src_comp1" => {"ip" => src_ip, "ports" => [123, 412]},
        "dest_comp1" => {"ip" => dest_ip, "ports" => [123, 687]},
        "dest_comp2" => {"ip" => "10.12.213.2", "ports" => [456]},
        "src_comp2" => {"ip" => "10.11.12.13", "ports" => [123]},
        "dest_comp3" => {"ip" => "20.21.22.23", "ports" => [234]}
    }

    src_zone = "zone1"
    dest_zone = "zone2"
    zone_lookup = Config::ZoneLookup.new({src_zone => ["src_comp1", "dest_comp2"], dest_zone => ["dest_comp1"], "zone3" => ["src_comp2"], "zone4" => ["dest_comp3"]})
    successful_response = "<Response success='Success'></Response>"

    expect(nm_client_mock).to receive('add_rule').with(src_zone, src_ip, dest_zone, dest_ip, 123, 2001).and_return(successful_response)
    expect(nm_client_mock).to receive('add_rule').with(src_zone, src_ip, dest_zone, dest_ip, 687, 2002).and_return(successful_response)
    expect(nm_client_mock).to receive('add_rule').with("zone3", "10.11.12.13", "zone4", "20.21.22.23", 234, 2001).and_return(successful_response)

    synced_rules = rule_manager.sync_rules(dependencies, ip_lookup, zone_lookup)

    expected_rules_to_be_added = [
        {"srcIpZone" => "zone1", "destIpZone" => "zone2", "sourceIp" => "10.12.213.4", "destinationIp" => "10.12.213.1", "destPort" => 123},
        {"srcIpZone" => "zone1", "destIpZone" => "zone2", "sourceIp" => "10.12.213.4", "destinationIp" => "10.12.213.1", "destPort" => 687},
        {"srcIpZone" => "zone3", "destIpZone" => "zone4", "sourceIp" => "10.11.12.13", "destinationIp" => "20.21.22.23", "destPort" => 234},
    ]

    expect(synced_rules[:added]).to eq(expected_rules_to_be_added)
  end

  it "syncs by removing obsolete rules with firewall client" do
    nm_client_mock = spy("nm_client")
    src_ip = "10.12.213.4"
    dest_ip = "10.12.213.1"
    src_zone = "zone1"
    dest_zone = "zone2"

    already_existing_rule = {"ruleno" => 2001, "ruletype" => "accept", "fwCompId" => 19588, "protocol" => "tcp",
                             "srcIpZone" => src_zone, "destIpZone" => dest_zone, "sourceIp" => src_ip, "destinationIp" => dest_ip, "destPort" => 123}
    obsolete_rule = {"ruleno" => 2002, "ruletype" => "accept", "fwCompId" => 19588, "protocol" => "tcp",
                     "srcIpZone" => "zone3", "destIpZone" => "zone4", "sourceIp" => "10.11.12.13", "destinationIp" => "20.21.22.23", "destPort" => 123}

    expect(nm_client_mock).to receive('get_rules').and_return([already_existing_rule, obsolete_rule])
    rule_manager = Security::Firewall::RuleManager.new(nm_client_mock)

    dependencies = [{"src_comp1" => ["dest_comp1", "dest_comp2"]}]

    ip_lookup = {"src_comp1" => {"ip" => src_ip, "ports" => [123, 412]},
                 "dest_comp1" => {"ip" => dest_ip, "ports" => [123]},
                 "dest_comp2" => {"ip" => "10.12.213.2", "ports" => [456]},
    }

    zone_lookup = Config::ZoneLookup.new({src_zone => ["src_comp1"], dest_zone => ["dest_comp1", "dest_comp2"]})
    successful_response = "<Response success='Success'></Response>"

    expect(nm_client_mock).to receive('add_rule').with(src_zone, src_ip, dest_zone, "10.12.213.2", 456, 2002).and_return(successful_response)
    expect(nm_client_mock).to receive('delete_rule').with(2002, "zone3", "zone4").and_return(successful_response)

    synced_rules = rule_manager.sync_rules(dependencies, ip_lookup, zone_lookup)

    expected_rules_to_be_removed = [
        {"srcIpZone" => "zone3", "destIpZone" => "zone4", "sourceIp" => "10.11.12.13", "destinationIp" => "20.21.22.23", "destPort" => 123},
    ]

    expect(synced_rules[:removed]).to eq(expected_rules_to_be_removed)
  end
end