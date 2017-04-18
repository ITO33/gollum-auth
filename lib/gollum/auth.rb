require 'rack'
require 'active_model'
require 'gollum/auth/version'
require 'gollum/auth/user'

module Gollum
  module Auth
    def self.new(*args)
      App.new(*args)
    end

    class App
      def initialize(app, opts = { })
        @app = app
        @users = opts.fetch(:users, [ ]).map { |args| User.new(args) }
      end

      def call(env)
        request = Rack::Request.new(env)
        if request.path_info =~ /^\/(create|edit|delete|rename|revert|upload)(\/.*)?$/
          auth = Rack::Auth::Basic::Request.new(env)
          unless auth.provided? && auth.basic? && valid?(auth.credentials)
            return [
              401,
              { 'Content-Type' => 'text/plain', 'WWW-Authenticate' => 'Basic realm="Gollum Wiki"' },
              [ 'Not authorized' ]
            ]
          end
        end
        @app.call(env)
      end

      private

      def valid?(credentials)
        @users.any? { |u| [ u.user, u.password ] == credentials }
      end
    end
  end
end
