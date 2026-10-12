# Bastion Security Ruby SDK

Official Ruby SDK for [Bastion Security](https://bastionsecurity.io) — real-time bot detection and fraud prevention.

## Installation

```ruby
gem "bastionsecurity"
```

## Usage

```ruby
require "bastion"

client = Bastion.new(
  site_key: "pk_live_your_site_key",
  secret: "sk_live_your_secret_key",
)

# Classify a token from the frontend SDK
result = client.classify("token-from-frontend")
puts "#{result['verdict']} — score #{result['score']}"

# Track a server-side event
client.track("purchase", { amount: 49.99, user_id: "usr_123" })
```

## API

### `Bastion.new(site_key:, secret:, endpoint: nil, timeout: 10)`

### `client.classify(token) -> Hash`

### `client.track(event, data = {}) -> Hash`

## License

MIT — © 2024 Bastion Security
