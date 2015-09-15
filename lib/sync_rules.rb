require 'lib/config'
require 'net/http'

class FirewallRuleManager
  def sync
    all_rule = Config::SecurityConfig.new.get_all_rules
  end
end

FirewallRuleManager.sync
