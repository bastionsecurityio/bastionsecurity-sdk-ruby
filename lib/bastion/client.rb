require "json"
require "net/http"
require "openssl"
require "uri"

module Bastion
  class Client
    DEFAULT_ENDPOINT = "https://api.bastionsecurity.io"

    def initialize(site_key:, secret:, endpoint: DEFAULT_ENDPOINT, timeout: 10)
      @site_key = site_key
      @secret = secret
      @endpoint = endpoint.chomp("/")
      @timeout = timeout
    end

    def classify(token)
      body = JSON.generate({ token: token })
      post("/v1/classify", body)
    end

    def track(event, data = {})
      body = JSON.generate({
        event: event,
        data: data,
        site_key: @site_key,
        ts: (Time.now.to_f * 1000).to_i,
      })
      post("/v1/events", body)
    end

    private

    def post(path, body)
      uri = URI("#{@endpoint}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      req = Net::HTTP::Post.new(uri.path)
      req["Content-Type"] = "application/json"
      req["X-Bastion-Site-Key"] = @site_key
      req["X-Bastion-Signature"] = sign(body)
      req.body = body

      resp = http.request(req)
      raise "Bastion API error: #{resp.code}" unless resp.is_a?(Net::HTTPSuccess)

      JSON.parse(resp.body)
    end

    def sign(data)
      OpenSSL::HMAC.hexdigest("SHA256", @secret, data)
    end
  end
end
