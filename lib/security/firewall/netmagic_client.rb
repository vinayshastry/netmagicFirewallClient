require 'net/http'
require './lib/security/signature'
require './lib/http/client'
require './lib/config/security_config'
require 'cgi'
require 'nokogiri'

module Security
	module Firewall
		API_VERSION = "1.0"
		class NetmagicClient
				include Http::Client
			def initialize(config)
				@config = config
				credentials = config.get_api_credentials
				@signature = Signature.new(credentials["api_key"], credentials["secret_code"])
			end

			def get_rules
				puts "========= Get Rules ========="
				response_body = get(uri_for("multitier/firewallrules/#{get_component_id}"), "application/json")
				rules = JSON.parse(response_body)["Response"]["Rules"].first["Rule"]
				puts "No. of rules: #{rules.length}"
				rules
			end

			def get_component_id
				unless @component_id
					puts "========= Get Component Id ========="
					response_body = get(uri_for("devices/cust/device/#{@config.get_firewall_id}"))
					@component_id = Nokogiri::XML(response_body).xpath("//CloudComponent/cloud_app_component_id").text
				end
				@component_id
			end

			def delete_rule(rule_number, source_zone, destination_zone)
				puts "========= Delete Rules ========="
				delete(uri_for("multitier/#{get_component_id}/#{rule_number}", "srczone" => source_zone, "destzone" => destination_zone))
			end

			def add_rule(source_zone, source_ip, destination_zone, destination_ip, destination_port, rule_number)
				rule = {"Request" => { "Parameters" => { 
										"ruletype" => "accept",
										"srcIpZone" => source_zone,
										"sourceIp" => source_ip,
										"destIpZone" => destination_zone,
										"destinationIp" => destination_ip, 
										"destPort" => destination_port,
										"protocol" => "tcp",
										"ruleno" => rule_number,
										"fwCompId" => get_component_id
									} 
							}
						}
				puts("========= Add Rules =========")
				post(uri_for("multitier/firewall/addeditrule"), to_xml(rule))
			end

			def uri_for(url, params = nil)
				additional_params = params ? "&#{to_query(params)}" : ""
				URI("#{@config.get_netmagic_base_url}/api/#{API_VERSION}/#{url}?#{to_query(credential_params({"version" => API_VERSION}))}#{additional_params}")
			end


			def to_xml(params)
				if Hash === params
					return params.map do |k, v|
						"<#{k}>#{to_xml(v)}</#{k}>"
					end.join
				else
					params
				end
			end

			def credential_params(params)
				params, signature = @signature.generate(params)
				{"timeStamp" => params["timeStamp"], "apiKey" => params["apiKey"], "signature" => signature}
			end

			def to_query(params)
				params.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
			end
		end
	end
end