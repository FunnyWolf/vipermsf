# toybox
require 'rex/text'
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
    begin
      uuid_intent= UUID.new
      self.uuid = uuid_intent.generate
    rescue Exception => e
      self.uuid = Rex::Text.rand_text_alphanumeric(16).downcase
    end
  end
end