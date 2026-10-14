require_relative "lib/bastion/version"

Gem::Specification.new do |s|
  s.name        = "bastionsecurity"
  s.version     = Bastion::VERSION
  s.summary     = "Bastion Security Ruby SDK"
  s.description = "Official Ruby SDK for Bastion Security — real-time bot detection and fraud prevention"
  s.authors     = ["Bastion Security"]
  s.homepage    = "https://bastionsecurity.io"
  s.license     = "MIT"
  s.files       = Dir["lib/**/*.rb"]
  s.required_ruby_version = ">= 3.0"
  s.metadata    = {
    "source_code_uri" => "https://github.com/bastionsecurityio/bastionsecurity-sdk-ruby",
  }
end
