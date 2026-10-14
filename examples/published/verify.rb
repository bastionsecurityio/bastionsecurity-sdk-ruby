require 'bastion'

def verify_request(request)
  client = Bastion.new(
    site_key: ENV.fetch('BASTION_SITE_KEY'),
    secret: ENV.fetch('BASTION_SECRET_KEY'),
    endpoint: ENV.fetch('BASTION_ENDPOINT', 'https://api.bastionsecurity.io/api/antibot')
  )
  decision = client.verify(request)
  { allowed: decision['action'] == 'allow', decision: decision }
end
# Bastion::Error stops approval; handle it in your application.
