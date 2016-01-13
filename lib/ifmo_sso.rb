require "ifmo_sso/version"
require "devise/strategies/authenticatable"

# require "ifmo_sso/routes"

module IfmoSso

  class IfmoAuthenticatable < Devise::Strategies::Authenticatable

    SECRET = 'DoEfZDyVviWGNdUohxyEGlOrwISlwcHIwzXRyDdA'

    def valid?
      request.params[:auth_source] == 'ifmo_sso'
    end

    def _try_to_login_ifmosso(params)
      login = params[:ssoid]
      secret = SECRET

      # Make sure no one can sign in with an empty login
      return false if login.empty?

      # Calcutate hash sum
      strToHash = params[:ssoid] +
          params[:lastname] + params[:firstname] + params[:middlename] +
          params[:birthdate] + params[:gender] +
          params[:countryCode] + params[:roles] + params[:ttl] +
          secret
      strToHash = strToHash.encode ("cp1251")
      calculatedHash = (Digest::SHA1.hexdigest strToHash).upcase
      if calculatedHash != params[:hash]
        return false
      end

      true
    end


    def authenticate!

      if !_try_to_login_ifmosso(request.params)
        fail('Hash validation failed')
        return
      end

      # Extract params first
      user_params = {
          username: request.params[:ssoid],
          email: request.params[:email],
          password: request.params[:hash],
          _full_name: "#{request.params[:lastname]} #{request.params[:firstname]}"
      }

      # Get user if present in database
      resource = mapping.to.find_for_database_authentication({login: request.params[:ssoid]})

      # If no user found -- create account and approve it
      if not resource
        @user = User.new(user_params)
        @user.skip_confirmation_notification!
        if @user.save
          @user.confirm
          @user.approve!
        else
          fail(@user.errors.full_messages.join(" "))
          return
        end
        resource = @user

      # Otherwise update it with new data
      else
        # Email cannot be overwritten
        resource.email = user_params[:email]
        resource.password = user_params[:password]
        resource.username = user_params[:username]
        resource.profile.full_name = user_params[:_full_name]
        if !resource.save or !resource.profile.save
          fail([resource.errors.full_messages|| @profile.errors.full_messages].join(" "))
          return
        end
      end


      if resource
        remember_me(resource)
        success!(resource)
      end

      #
      # mapping.to.new.password = password if !encrypted && Devise.paranoid
      fail(:not_found_in_database) unless resource
    end
  end

end

module Devise
  module Models
    module IfmoAuthenticatable

# for warden, `:my_authentication`` is just a name to identify the strategy
      Warden::Strategies.add :ifmo_authenticatable, IfmoSso::IfmoAuthenticatable

# for devise, there must be a module named 'MyAuthentication' (name.to_s.classify), and then it looks to warden
# for that strategy. This strategy will only be enabled for models using devise and `:my_authentication` as an
# option in the `devise` class method within the model.
      Devise.add_module(:ifmo_authenticatable, {
            strategy: true
      })
      # noop
    end
  end
end