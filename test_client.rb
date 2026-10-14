require "minitest/autorun"
require_relative "lib/bastion"
class ClientTest < Minitest::Test
 def test_webhook
  body = '{"text":"fraud 🚨"}'; secret='secret'; timestamp=12345
  signature="t=#{timestamp},v1=#{OpenSSL::HMAC.hexdigest('SHA256',secret,"#{timestamp}.#{body}")}"
  assert Bastion.verify_webhook(secret,body,signature,now:timestamp)
  refute Bastion.verify_webhook(secret,body+' ',signature,now:timestamp)
  refute Bastion.verify_webhook(secret,body,signature,now:timestamp+301)
 end
 def test_endpoint_validation
  assert_raises(ArgumentError) { Bastion.new(site_key:'public',secret:'secret',endpoint:'http://example.com') }
 end
end
