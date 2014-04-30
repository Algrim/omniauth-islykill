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

        unless request.params['token']
          raise OmniAuth::Strategies::Islykill::ValidationError.new("Islykill response missing")
        end

        token_base64 = request.params['token']
        islykill_xml_saml_response = Base64.decode64(token_base64)
        signedDocument = SignedXml::Document(islykill_xml_saml_response)
        if !signedDocument.is_verified?
            raise OmniAuth::Strategies::Islykill::ValidationError.new("Islykill response not valid")
        end

        # response is valid so we extract the information using xpath
        xml_doc = REXML::Document.new(islykill_xml_saml_response)
        prefix='Response/Assertion/AttributeStatement/Attribute[@Name="'
        postfix='"]/AttributeValue'

        @attributes={
            name: REXML::XPath.first(xml_doc,"#{prefix}Name#{postfix}").text,
            kennitala: REXML::XPath.first(xml_doc,"#{prefix}UserSSN#{postfix}").text,
            provider: REXML::XPath.first(xml_doc,"#{prefix}Authentication#{postfix}").text
        }

        @name_id = REXML::XPath.first(xml_doc,"Response/Assertion/Subject/NameID/@NameQualifier").value()

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::Islykill::ValidationError.new("SAML response missing 'name_id'")
        end

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

      uid { 
        #@name_id 
        @attributes[:kennitala]
      }

      info do
        {
          :name  => @attributes[:name],          
          :kennitala => @attributes[:kennitala]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end




