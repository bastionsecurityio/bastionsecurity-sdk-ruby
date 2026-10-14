require_relative 'lib/bastion'
require 'digest'
c=JSON.parse(File.read(ENV.fetch('BASTION_QA_SESSION','/tmp/bastion-sdk-qa-session.json')))
raise 'Local QA only' unless c['endpoint'].match?(/\Ahttp:\/\/(localhost|127\.0\.0\.1):/)
def check(value);raise 'Assertion failed' unless value;end
client=Bastion.new(site_key:c['site_key'],secret:c['secret'],endpoint:c['endpoint'])
fp=client.fingerprint({canvas_hash:'ruby-sdk-e2e',platform:'MacIntel',user_agent:'Mozilla/5.0 Chrome/130.0',language:'en-US',languages:['en-US']})
check(fp['token'] && fp['expires_at'])
request={token:fp['token'],context:{event_type:'login',account_id:'ruby-sdk-e2e',login_succeeded:false},idempotency_key:SecureRandom.uuid}
decision=client.verify(request);check(client.verify(request)['request_id']==decision['request_id']);check(decision['signals'].is_a?(Array))
check(client.classify(fp['token'],{event_type:'signup',account_id:'ruby-sdk-classify'})['request_id'])
check(client.track('checkout',{account_id:'ruby-sdk-track',order_amount:4,payment_hash:'ruby-test-card'},token:fp['token'])['request_id'])
result=client.batch([request.merge(idempotency_key:SecureRandom.uuid),{context:{event_type:'unsupported',account_id:'invalid'}}]);check(result['accepted']==1 && result['results'][1]['status']==400)
begin;Bastion.new(site_key:c['site_key'],secret:'wrong',endpoint:c['endpoint']).verify(request);raise 'Invalid auth accepted';rescue Bastion::Error=>e;check(e.status==401);end
challenge=client.create_challenge(difficulty:4);nonce=0
nonce+=1 until Digest::SHA256.hexdigest(challenge['prefix']+nonce.to_s(36)).start_with?('0'*challenge['difficulty'])
check(client.verify_challenge(challenge['challenge_id'],nonce.to_s(36))['valid'])
begin;client.verify_challenge(challenge['challenge_id'],nonce.to_s(36));raise 'Replay accepted';rescue Bastion::Error=>e;check(e.status==400);end
puts 'PASS: Ruby SDK real fingerprint, scoring, deduplication, classify/track, partial batch, auth failure and proof/replay checks.'
