# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Instrumentation do
  # Test class that extends (for class methods)
  let(:test_module) do
    Module.new do
      extend TokenAuthority::Instrumentation

      def self.test_operation(value)
        instrument("test_event", input: value) do |payload|
          payload[:output] = value * 2
          value * 2
        end
      end
    end
  end

  # Test class that includes (for instance methods)
  let(:test_instance_class) do
    Class.new do
      include TokenAuthority::Instrumentation

      def test_operation(value)
        instrument("test_event", input: value) do |payload|
          payload[:output] = value * 2
          value * 2
        end
      end
    end
  end

  describe "when extended (class methods)" do
    context "when instrumentation is enabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(true)
      end

      it "emits an instrumentation event" do
        expect {
          test_module.test_operation(21)
        }.to instrument("token_authority.test_event")
          .with_payload(input: 21)
      end

      it "returns the result of the block" do
        result = test_module.test_operation(21)
        expect(result).to eq(42)
      end

      it "allows the block to modify the payload" do
        expect {
          test_module.test_operation(21)
        }.to instrument("token_authority.test_event")
          .with_payload(output: 42)
      end

      context "when the block raises an exception" do
        let(:failing_module) do
          Module.new do
            extend TokenAuthority::Instrumentation

            def self.failing_operation
              instrument("test_event") { raise StandardError, "test error" }
            end
          end
        end

        it "includes error info in the payload" do
          expect {
            failing_module.failing_operation
          }.to raise_error(StandardError, "test error")
            .and instrument("token_authority.test_event")
            .with_payload(error: "StandardError: test error")
        end

        it "re-raises the exception" do
          expect {
            failing_module.failing_operation
          }.to raise_error(StandardError, "test error")
        end
      end
    end

    context "when instrumentation is disabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(false)
      end

      it "does not emit an instrumentation event" do
        expect {
          test_module.test_operation(21)
        }.not_to instrument("token_authority.test_event")
      end

      it "still executes the block and returns the result" do
        result = test_module.test_operation(21)
        expect(result).to eq(42)
      end

      it "still passes the payload hash to the block" do
        capturing_module = Module.new do
          extend TokenAuthority::Instrumentation

          def self.captured_payload
            @captured_payload
          end

          def self.capture_operation
            instrument("test_event", foo: "bar") do |payload|
              @captured_payload = payload.dup
              "result"
            end
          end
        end

        capturing_module.capture_operation
        expect(capturing_module.captured_payload).to eq({foo: "bar"})
      end
    end
  end

  describe "when included (instance methods)" do
    let(:instance) { test_instance_class.new }

    context "when instrumentation is enabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(true)
      end

      it "emits an instrumentation event" do
        expect {
          instance.test_operation(21)
        }.to instrument("token_authority.test_event")
          .with_payload(input: 21)
      end

      it "returns the result of the block" do
        result = instance.test_operation(21)
        expect(result).to eq(42)
      end
    end

    context "when instrumentation is disabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(false)
      end

      it "does not emit an instrumentation event" do
        expect {
          instance.test_operation(21)
        }.not_to instrument("token_authority.test_event")
      end

      it "still executes the block and returns the result" do
        result = instance.test_operation(21)
        expect(result).to eq(42)
      end
    end
  end
end
