require 'hmac-sha1'
require 'json'
require 'base64'
require 'cgi'
require './lib/config/security_config'

class Signature
  def initialize(api_key, secret_code)
    @api_key = api_key
    @secret_code = secret_code
  end

  def generate(params)
  	puts "[DEBUG] params => #{params.inspect}"
  	params["apiKey"] = @api_key
  	params["timeStamp"] ||= Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")
  	puts "[DEBUG] params => #{params.inspect}"
  	base_string = params.sort.map{ |k, v| "#{k}#{v}" }.join("")
  	hmac = HMAC::SHA1.new(@secret_code)
  	hmac.update(base_string)
	[params, CGI.escape(Base64.encode64(hmac.digest).chomp)]
  end
end