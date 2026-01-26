# frozen_string_literal: true

RSpec.shared_examples "a model that validates token claims" do
  describe "validations" do
    it "does not add any errors if all provided claims are valid" do
      expect(model).to be_valid
    end

    describe "aud" do
      specify(:aggregate_failures) do
        expect(model).to validate_presence_of(:aud)
        expect(model).not_to allow_value("http://foo.bar/api").for(:aud)
      end
    end

    describe "exp" do
      specify(:aggregate_failures) do
        expect(model).to validate_presence_of(:exp)
        expect(model).not_to allow_value(5.minutes.ago.to_i).for(:exp)
      end
    end

    describe "iss" do
      specify(:aggregate_failures) do
        expect(model).to validate_presence_of(:iss)
        expect(model).not_to allow_value("http://foo.bar/").for(:iss)
      end
    end

    describe "jti" do
      it { is_expected.to validate_presence_of(:jti) }
    end
  end

  describe "callbacks" do
    describe "#revoke_token_authority_session" do
      context "when the `aud` claim is invalid" do
        it "updates the Session status to `revoked`" do
          model.aud = ""
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("revoked")
        end
      end

      context "when the `iss` claim is invalid" do
        it "updates the Session status to `revoked`" do
          model.iss = ""
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("revoked")
        end
      end

      context "when the `exp` claim is invalid" do
        it "does not update the Session status to `revoked`" do
          model.exp = ""
          model.valid?
          expect(token_authority_session.reload).not_to be_revoked_status
        end
      end

      context "when the `jti` claim is invalid" do
        it "does not update the Session status to `revoked`" do
          model.jti = ""
          model.valid?
          expect(token_authority_session.reload).not_to be_revoked_status
        end
      end
    end
  end
end
