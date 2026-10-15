require 'bastion'
require 'json'
require 'digest'
require 'time'

begin
  mode, input, extra = ARGV
  output = nil
  status = 0
  if mode == 'webhook'
    raise ArgumentError, 'Usage: webhook raw-body.json signature.txt' unless input && extra
    raw = File.binread(input)
    signature = File.read(extra).strip
    raise ArgumentError, 'Invalid or stale webhook signature' unless Bastion.verify_webhook(ENV.fetch('BASTION_WEBHOOK_SECRET'), raw, signature)
    output = { verified: true, event: JSON.parse(raw) }
  else
    raise ArgumentError, 'Usage: verify telemetry.json order.json | batch requests.json | challenge | webhook raw-body.json signature.txt' unless %w[verify batch challenge].include?(mode)
    client = Bastion.new(site_key: ENV.fetch('BASTION_SITE_KEY'), secret: ENV.fetch('BASTION_SECRET_KEY'), endpoint: ENV.fetch('BASTION_ENDPOINT', 'https://api.bastionsecurity.io/api/antibot'))
    case mode
    when 'verify'
      raise ArgumentError, 'Usage: verify telemetry.json order.json' unless input && extra
      telemetry, order = JSON.parse(File.read(input)), JSON.parse(File.read(extra))
      raise ArgumentError, 'Complete buildRequest() telemetry with a stable idempotency_key is required' unless telemetry['idempotency_key'] && !telemetry['idempotency_key'].to_s.empty? && (telemetry['browser_receipt'] || %w[token fingerprint].all? { |key| telemetry[key] && !telemetry[key].to_s.empty? })
      amount = order['amount']
      raise ArgumentError, 'Trusted order needs customerId, paymentId, and a finite nonnegative amount' unless %w[customerId paymentId].all? { |key| order[key].is_a?(String) && !order[key].empty? } && amount.is_a?(Numeric) && amount.finite? && amount >= 0
      request = telemetry.select { |key, _| %w[browser_receipt token fingerprint behavior environment idempotency_key].include?(key) }
      request['context'] = {event_type: 'checkout', account_id: order['customerId'], order_amount: amount, payment_hash: order['paymentId']}
      decision = client.verify(request)
      output = {allowed: decision['action'] == 'allow', decision: decision}
    when 'batch'
      raise ArgumentError, 'Usage: batch requests.json' unless input
      requests = JSON.parse(File.read(input))
      raise ArgumentError, 'Batch needs 1–50 server-owned requests, each with a stable idempotency_key' unless requests.is_a?(Array) && (1..50).cover?(requests.length) && requests.all? { |r| r['idempotency_key'].is_a?(String) && !r['idempotency_key'].empty? }
      output = client.batch(requests)
      output['results'].each { |item| item['allowed'] = item['success'] == true && item.dig('decision', 'action') == 'allow' }
      status = 2 if output['results'].any? { |item| !item['success'] }
    when 'challenge'
      challenge = client.create_challenge(difficulty: 4)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + [60, Time.iso8601(challenge['expires_at']).to_f - Time.now.to_f].min
      nonce = 0
      until Digest::SHA256.hexdigest(challenge['prefix'] + nonce.to_s(36)).start_with?('0' * challenge['difficulty'])
        raise ArgumentError, 'Proof solver deadline reached' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        nonce += 1
      end
      result = client.verify_challenge(challenge['challenge_id'], nonce.to_s(36))
      raise ArgumentError, 'Proof was rejected' unless result['valid']
      output = result.merge('fulfillment_authorized' => false)
    end
  end
  puts JSON.pretty_generate(output)
  exit status
rescue StandardError => error
  warn "Example failed: #{error.message}"
  exit 1
end
