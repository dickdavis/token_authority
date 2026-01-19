require "rails_helper"

RSpec.describe TokenAuthority do
  it "has a version number" do
    expect(TokenAuthority::VERSION).not_to be_nil
  end
end
