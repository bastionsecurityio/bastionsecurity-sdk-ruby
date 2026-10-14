require "json"
require "net/http"
require "openssl"
require "uri"
require "securerandom"

module Bastion
  class Error < StandardError
    attr_reader :status, :response
    def initialize(message, status = 0, response = nil)
      super(message)
      @status, @response = status, response
    end
  end

  def self.verify_webhook(secret, raw_body, signature, tolerance: 300, now: Time.now.to_i)
    parts = signature.split(",").map(&:strip)
    timestamp = parts.find { |p| p.match?(/\At=\d+\z/) }&.delete_prefix("t=")
    return false if secret.empty? || !timestamp || tolerance < 0 || (now - timestamp.to_i).abs > tolerance
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{raw_body}")
    parts.any? { |p| p.match?(/\Av1=[0-9a-f]{64}\z/) && OpenSSL.fixed_length_secure_compare(expected, p.delete_prefix("v1=")) }
  end

  class Client
    DEFAULT_ENDPOINT = "https://api-production-761a5.up.railway.app/api/antibot"
    def initialize(site_key:, secret:, endpoint: DEFAULT_ENDPOINT, timeout: 15, retries: 2)
      uri = URI(endpoint)
      unless uri.scheme == "https" || (uri.scheme == "http" && ["localhost", "127.0.0.1", "[::1]"].include?(uri.host))
        raise ArgumentError, "Bastion requires HTTPS except on localhost"
      end
      raise ArgumentError, "Invalid API endpoint" if uri.userinfo || uri.query || uri.fragment
      raise ArgumentError, "Valid site credentials are required" if [site_key, secret].any? { |v| v.empty? || v.match?(/[\r\n]/) }
      @endpoint = endpoint.chomp("/")
      @endpoint += "/api/antibot" if ["", "/"].include?(uri.path)
      @endpoint += "/antibot" if uri.path.chomp("/") == "/api"
      @site_key, @secret = site_key, secret
      @timeout, @retries = [[timeout, 1].max, 30].min, [[retries, 0].max, 3].min
    end
    def verify(request)
      body = request.transform_keys(&:to_s)
      body["idempotency_key"] ||= SecureRandom.uuid
      post("/verify", body)
    end
    def classify(token, context, **telemetry)
      verify(telemetry.merge(token: token, context: context))
    end
    def track(event, data, token: nil)
      verify(token: token, context: data.merge(event_type: event))
    end
    def fingerprint(fingerprint, behavior: nil)
      post("/verify/fingerprint", {fingerprint: fingerprint, behavior: behavior})
    end
    def batch(events)
      post("/verify/batch", {events: events.map { |e| {"idempotency_key" => SecureRandom.uuid}.merge(e.transform_keys(&:to_s)) }})
    end
    def create_challenge(difficulty: 4)
      post("/verify/challenge", {difficulty: difficulty})
    end
    def verify_challenge(challenge_id, nonce)
      post("/verify/challenge/verify", {challenge_id: challenge_id, nonce: nonce})
    end
    private
    def post(path, body)
      payload = JSON.generate(body)
      safe = body["idempotency_key"] || (body[:events] && body[:events].all? { |e| e["idempotency_key"] })
      attempt = 0
      loop do
        begin
          uri = URI("#{@endpoint}#{path}")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = http.read_timeout = @timeout
          req = Net::HTTP::Post.new(uri.request_uri)
          req["Content-Type"], req["X-Site-Key"], req["X-Secret-Key"] = "application/json", @site_key, @secret
          req.body = payload
          resp = http.request(req)
          begin
            data = JSON.parse(resp.body)
          rescue JSON::ParserError
            raise Error.new("API returned invalid JSON", resp.code.to_i)
          end
          raise Error.new(data.is_a?(Hash) ? data["message"].to_s : "API request failed", resp.code.to_i, data) unless resp.is_a?(Net::HTTPSuccess)
          raise Error.new("Invalid API response", resp.code.to_i, data) unless data.is_a?(Hash) && data["success"] != false
          return data.fetch("data", data)
        rescue Error => error
          raise if !safe || attempt >= @retries || (error.status > 0 && error.status != 429 && error.status < 500)
        rescue Timeout::Error, IOError, SystemCallError, SocketError => error
          raise Error.new("API request could not reach the server") if !safe || attempt >= @retries
        end
        sleep(0.25 * 2 ** attempt)
        attempt += 1
      end
    end
  end
end
