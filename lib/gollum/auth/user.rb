module Gollum::Auth
  class InvalidUserError < StandardError
  end

  class User
    attr_accessor :username, :password_encrypted, :name, :email

    # Constructor
    def initialize(attributes = {})
      attributes.each do |key, value|
        public_send("#{key}=", value)
      end

      if @name.nil? or @email.nil?
        raise(InvalidUserError, "Name and email are required")
      end

      if @username.nil? or @username !~ /\A[\w\.-]+\Z/
        raise(InvalidUserError, "Bad username format: #{@username}")
      end

      if @password_encrypted.nil? or @password_encrypted !~ /\A[0-9a-f]{64}\Z/
        raise(InvalidUserError, "Bad password format: #{@password_encrypted}")
      end
    end

    class << self
      def find_by_credentials(credentials)
        username, password = credentials
        user = find(username)
        user if user && user.valid_password?(password)
      end

      def find(username)
        all.select { |u| u.username == username }.first
      end

      def all
        @all ||= []
      end

      def delete_all
        @all = []
      end
    end

    def save!
      self.class.all << self
      self
    end

    def save
      self.class.all << self
      true
    end

    def valid_password?(password)
      Rack::Utils.secure_compare(password_digest, build_digest(password))
    end

    def password=(password)
      self.password_digest = build_digest(password.to_s) if password
    end

    private

    def build_digest(password)
      Digest::SHA256.hexdigest(password)
    end
  end
end
