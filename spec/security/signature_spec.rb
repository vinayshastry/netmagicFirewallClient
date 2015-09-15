require 'security/signature'

describe "Signature" do
  it "should generate signature using params" do
    signature = Signature.new("key", "secret_key")
    time = "2015-09-15 11:48:43 +0530"
    params, sign_str = signature.generate("timestamp" => time, "version" => "1.0")

    expect(params["apiKey"]).to eq("key")
    puts "[DEBUG] sign_str => #{sign_str.inspect}"
    expect(sign_str.to_s).to eq('UZ3akK%2BrqP0ZQMSbfdPLNWVrVO8%3D')
  end
end
