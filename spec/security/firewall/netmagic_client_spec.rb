require "nokogiri"
require "./lib/security/firewall/netmagic_client"

describe "NetmagicClient" do
	$debug = true
	if ENV["NETMAGIC_API_KEY"] && ENV["NETMAGIC_SECRET_CODE"] && ENV["NETMAGIC_FIREWALL_ID"]
		it "adds verifies and deletes a rule" do
			nm_client = Security::Firewall::NetmagicClient.new(Config::SecurityConfig.new)
			src_zone = "WEB-Zone"
			dest_zone = "APP-Zone"
			existing_rule_count = nm_client.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }.count

			response_body = nm_client.add_rule(src_zone, "10.10.13.2", dest_zone, "10.10.18.2", "22", "5")
			expect(Nokogiri::XML(response_body).xpath("//Response/@success").first.value).to eq("Success")

			after_add__rule_count = nm_client.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }.count
			expect(after_add__rule_count - existing_rule_count).to eq(1)

			nm_client.delete_rule("5", src_zone, dest_zone)
			after_del__rule_count = nm_client.get_rules.select{ |rule| rule["srcIpZone"] == src_zone && rule["destIpZone"] == dest_zone }.count
			expect(after_del__rule_count).to eq(existing_rule_count)
		end
	end
end