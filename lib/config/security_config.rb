module Config
  class SecurityConfig
    def get_api_credentials
      {"api_key" => ENV["NETMAGIC_API_KEY"], "secret_code" => ENV["NETMAGIC_SECRET_CODE"]}
    end

    def get_netmagic_base_url
      "https://webservices.simplicloud.com/NetMagic_API_SERVER-0.1"
    end

    def get_firewall_id
      ENV["NETMAGIC_FIREWALL_ID"]
    end
  end
end
