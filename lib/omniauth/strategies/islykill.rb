require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class Islykill
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}

      def request_phase
        options[:assertion_consumer_service_url] ||= callback_url
        runtime_request_parameters = options.delete(:idp_sso_target_url_runtime_params)

        additional_params = {}
        runtime_request_parameters.each_pair do |request_param_key, mapped_param_key|
          additional_params[mapped_param_key] = request.params[request_param_key.to_s] if request.params.has_key?(request_param_key.to_s)
        end if runtime_request_parameters

        authn_request = Onelogin::Saml::Authrequest.new
        settings = Onelogin::Saml::Settings.new(options)

        redirect(authn_request.create(settings, additional_params))
      end

      def callback_phase

puts "   ___      _ _ _                _    "
puts "  / __ __ _| | | |__   __ _  ___| | __"
puts " / /  / _` | | | '_   / _` |/ __| |/ /"
puts "/ /__| (_| | | | |_) | (_| | (__|   < "
puts " ____/ __,_|_|_|_.__/  __,_| ___|_| _ "
puts "                                      "
puts request.params
        unless request.params['token']
          raise "Islykill response missing"
        end
puts "Got a token"
        token_base64 = request.params['token']
        islykill_xml_saml_response = Base64.decode64(token_base64)

        response = Onelogin::Saml::Response.new(islykill_xml_saml_response, options)
        response.settings = Onelogin::Saml::Settings.new(options)

        @name_id = response.name_id
        @attributes = response.attributes

response.validate!

        if @name_id.nil? || @name_id.empty?
          raise "SAML response missing 'name_id'"
        end

puts "Got a name id " + @name_id

        response.validate!

        super
      rescue 
        fail!(:invalid_ticket, $!)
      rescue Onelogin::Saml::ValidationError
        fail!(:invalid_ticket, $!)
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase

          response = Onelogin::Saml::Metadata.new
          settings = Onelogin::Saml::Settings.new(options)
          Rack::Response.new(response.generate(settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname] || @attributes[:firstName],
          :last_name => @attributes[:last_name] || @attributes[:lastname] || @attributes[:lastName]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end




