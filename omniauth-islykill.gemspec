require File.expand_path('../lib/omniauth-islykill/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = 'omniauth-islykill'
  gem.version       = OmniAuth::ISLYKILL::VERSION
  gem.summary       = 'This is a specific SAML strategy that handles authentication to Icelands Íslykill for OmniAuth.'
  gem.description   = 'This is a specific SAML strategy that handles authentication to Icelands Íslykill for OmniAuth.'
  gem.license       = ''

  gem.authors       = ['Bjorgvin Thordarson']
  gem.email         = 'algrim.is@outlook.com'
  gem.homepage      = 'https://github.com/Algrim/omniauth-islykill'

  gem.add_runtime_dependency 'omniauth', '~> 1.2'
  gem.add_runtime_dependency 'ruby-saml', '~> 1.0'

  # added for signed xml
  gem.add_dependency "nokogiri"
  gem.add_dependency "options"
  # added for signed xml
  
  gem.files         = ['README.md', 'CHANGELOG.md'] + Dir['lib/**/*.rb']
  #gem.test_files    = Dir['spec/**/*.rb']
  gem.require_paths = ["lib"]
end
