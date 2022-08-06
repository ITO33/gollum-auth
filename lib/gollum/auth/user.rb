module Gollum::Auth
  class InvalidUserError < StandardError
  end

  class User
    include ActiveModel::Model

    attr_accessor :username, :password_encrypted, :name, :email

    validates_presence_of :username, :password_encrypted, :name, :email
    validates_format_of :username, with: /\A[\w\.-]+\Z/
    validates_format_of :password_encrypted, with: %r!\A[a-zA-Z0-9./]{13}\Z!

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
      save ? self : raise(InvalidUserError, error_message)
    end

    def save
      valid? ? (self.class.all << self; true) : false
    end

    def valid_password?(password)
      password.crypt(password_encrypted) == password_encrypted
    end

    def password=(password)
      self.password_encrypted = password.crypt(Utils::random_string(2)) if password
    end

    private

    def error_message
      errors.full_messages.join(', ')
    end
  end
end
