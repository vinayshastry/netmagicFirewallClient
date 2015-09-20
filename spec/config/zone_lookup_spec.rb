require 'config/zone_lookup'

describe "ZoneLookup" do
  it "gets zone for a component" do
    zone_lookup = Config::ZoneLookup.new(YAML.load_file("spec/data/zone_lookup.yml"))
    expect(zone_lookup.zone_for("dummy_component1")).to eq("dummy_zone")
  end
end
