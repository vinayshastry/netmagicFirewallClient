require 'net/http'
require './lib/security/signature'
require './lib/config/security_config'
require 'cgi'
require 'nokogiri'

module Security
	module Netmagic
		API_VERSION = "1.0"
		class Firewall
			def initialize(config)
				@config = config
				credentials = config.get_api_credentials
				@signature = Signature.new(credentials["api_key"], credentials["secret_code"])
			end

			def get_rules
				response_body = get("multitier/firewallrules/#{get_component_id}", "application/json")
				rules = JSON.parse(response_body)["Response"]["Rules"].first["Rule"]
				puts "No. of rules: #{rules.length}"
				rules
			end

			def get_component_id
				unless @component_id
					response_body = get("devices/cust/device/#{@config.get_firewall_id}")
					@component_id = Nokogiri::XML(response_body).xpath("//CloudComponent/cloud_app_component_id").text
				end
				@component_id
			end

			def delete_rule(rule_number, source_zone, destination_zone)
				uri = uri_for("multitier/#{get_component_id}/#{rule_number}", "srczone" => source_zone, "destzone" => destination_zone)
				delete_req = Net::HTTP::Delete.new(uri)
				delete_req['Accept'] = "application/xml"
				delete_req['Content-Type'] = "application/xml"
				res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') {|http|
					  http.request(delete_req)
				}

				if res.code == "200"
					res.body
				else
					raise "Error with DELETE, uri: #{uri}, code: #{res.code}, body: #{res.body}"
				end

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
				response_body = post("multitier/firewall/addeditrule", to_xml(rule))
				puts response_body
			end

			def uri_for(url, params = nil)
				additional_params = params ? "&#{to_query(params)}" : ""
				URI("#{@config.get_netmagic_base_url}/api/#{API_VERSION}/#{url}?#{to_query(credential_params({"version" => API_VERSION}))}#{additional_params}")
			end	

			def post(url, request_body)
				uri = uri_for(url)

				puts "[DEBUG] uri => #{uri.inspect}"
				puts "[DEBUG] request_body => #{request_body.inspect}"
				post_req = Net::HTTP::Post.new(uri)
				post_req['Content-Type'] = "application/xml"
				post_req['Accept'] = "application/xml"
				post_req.body = request_body
				res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') {|http|
					  http.request(post_req)
				}

				puts "[DEBUG] res.code => #{res.code}"
				if res.code == "200" || res.code == "201"
					res.body
				else
					raise "Error with POST, uri: #{uri}, req_body: #{request_body}, code: #{res.code}, body: #{res.body}"
				end

			end

			def get(url, content_type =nil)
				uri = uri_for(url)

				puts "[DEBUG] uri => #{uri.inspect}"
				get_req = Net::HTTP::Get.new(uri)
				get_req['Accept'] = content_type || "application/xml"
				get_req['Content-Type'] = content_type || "application/xml"
				res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') {|http|
					  http.request(get_req)
				}

				if res.code == "200"
					res.body
				else
					raise "Error with GET, uri: #{uri}, code: #{res.code}, body: #{res.body}"
				end
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

firewall = Security::Netmagic::Firewall.new(Config::SecurityConfig.new)
puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == "WEB-Zone" && rule["destIpZone"] == "APP-Zone" }

firewall.delete_rule("5", "WEB-Zone", "APP-Zone")
puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == "WEB-Zone" && rule["destIpZone"] == "APP-Zone" }
\
firewall.add_rule("WEB-Zone", "10.10.13.2", "APP-Zone", "10.10.18.2", "22", "5")
puts firewall.get_rules.select{ |rule| rule["srcIpZone"] == "WEB-Zone" && rule["destIpZone"] == "APP-Zone" }