require_relative "bastion/client"
require_relative "bastion/version"

module Bastion
  def self.new(**kwargs)
    Client.new(**kwargs)
  end
end
