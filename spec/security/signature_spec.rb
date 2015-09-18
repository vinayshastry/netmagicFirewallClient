require 'security/signature'

describe "Signature" do
  it "should generate signature using params" do
    signature = Signature.new("key", "secret_key")
    time = "2015-09-15T11:48:43.345Z"
    params, sign_str = signature.generate("timeStamp" => time, "version" => "1.0")

    expect(params["apiKey"]).to eq("key")
    expect(sign_str.to_s).to eq('aGS0kFzuCs0FqDJfwYPo2THXJH0%3D')
  end
end
