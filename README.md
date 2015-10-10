# OmniAuth Islykill

This is a specific SAML strategy that handles authentication to Icelands Íslykill for OmniAuth

https://github.com/Algrim/omniauth-islykill

## Requirements

* [OmniAuth](http://www.omniauth.org/) 1.2+
* [ruby-saml](https://github.com/onelogin/ruby-saml)
* Ruby 1.9.x or Ruby 2.1.x

## Usage

Use the Islykill strategy in your Rails application:

in `Gemfile`:

```ruby
gem 'omniauth-islykill'
```

and in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
    provider :islykill,
        :assertion_consumer_service_url     => "consumer_service_url",
        :issuer                             => "Islyklar",
        :idp_sso_target_url                 => "https://innskraning.island.is/?id=consumer_service_url",
        :idp_cert                           => "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----",
        :idp_cert_fingerprint               => "E7:91:B2:E1:...",
        :name_identifier_format             => "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
end
```

For IdP-initiated SSO, users should directly access the IdP SSO target URL. Set the `href` of your application's login link to the value of `idp_sso_target_url`. For SP-initiated SSO, link to `/auth/saml`.

## Metadata

The service provider metadata used to ease configuration of the SAML SP in the IdP can be retrieved from `http://example.com/auth/saml/metadata`. Send this URL to the administrator of the IdP.

## Options

* `:assertion_consumer_service_url` - The URL at which the SAML assertion should be
  received. If not provided, defaults to the OmniAuth callback URL (typically
  `http://example.com/auth/saml/callback`). Optional.

* `:issuer` - The name of your application. Some identity providers might need this
  to establish the identity of the service provider requesting the login. **Required**.

* `:idp_sso_target_url` - The URL to which the authentication request should be sent.
  This would be on the identity provider. **Required**.

* `:idp_sso_target_url_runtime_params` - A dynamic mapping of request params that exist
  during the request phase of OmniAuth that should to be sent to the IdP after a specific
  mapping. So for example, a param `original_request_param` with value `original_param_value`,
  could be sent to the IdP on the login request as `mapped_idp_param` with value
  `original_param_value`. Optional.

* `:idp_cert` - The identity provider's certificate in PEM format. Takes precedence
  over the fingerprint option below. This option or `:idp_cert_fingerprint` must
  be present.

* `:idp_cert_fingerprint` - The SHA1 fingerprint of the certificate, e.g.
  "90:CC:16:F0:8D:...". This is provided from the identity provider when setting up
  the relationship. This option or `:idp_cert` must be present.

* `:name_identifier_format` - Used during SP-initiated SSO. Describes the format of
  the username required by this application. If you need the email address, use
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress". See
  http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for
  other options. Note that the identity provider might not support all options.
  If not specified, the IdP is free to choose the name identifier format used
  in the response. Optional.

* See the `OneLogin::Saml::Settings` class in the [Ruby SAML gem](https://github.com/onelogin/ruby-saml) for additional supported options.

## Authors

Authored by Björgvin Bæhrenz Þórðarson.

Maintained by [Björgvin Bæhrenz Þórðarson](https://github.com/Bjorgvin).

## License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.