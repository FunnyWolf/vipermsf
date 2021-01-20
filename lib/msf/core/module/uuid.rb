# toybox
require "uuid"
module Msf::Module::UUID
  #
  # Attributes
  #

  # @!attribute [r] uuid
  #   A unique identifier for this module instance
  attr_reader :uuid

  protected

  #
  # Attributes
  #

  # @!attribute [w] uuid
  attr_writer :uuid


  #
  # Instance Methods
  #

  def generate_uuid
    # toybox
    uuid_intent= UUID.new
    self.uuid = uuid_intent.generate
  end
end