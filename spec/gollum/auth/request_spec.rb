require 'spec_helper'

module Gollum::Auth
  describe Request do
    describe '#needs_authentication?' do
      let(:allow_guests) { false }

      def build_request(path)
        env = Rack::MockRequest.env_for("http://example.com#{path}")
        Request.new(env)
      end

      it 'is true for read requests' do
        subject = build_request '/Home'
        expect(subject.needs_authentication?(allow_guests)).to eq true
      end

      %w(create edit delete rename revert upload).each do |path|
        it "is true on #{path}" do
          subject = build_request "/#{path}"
          expect(subject.needs_authentication?(allow_guests)).to eq true
        end
      end

      context 'when guests are allowed' do
        let(:allow_guests) { true }

        it 'is false for read requests' do
          subject = build_request '/Home'
          expect(subject.needs_authentication?(allow_guests)).to eq false
        end

        %w(create edit delete rename revert upload).each do |path|
          it "is true on #{path}" do
            subject = build_request "/#{path}"
            expect(subject.needs_authentication?(allow_guests)).to eq true
          end
        end
      end
    end
  end
end