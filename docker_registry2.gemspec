# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'registry/version'

Gem::Specification.new do |spec|
  spec.name          = 'docker_registry2'
  spec.version       = DockerRegistry2::VERSION
  spec.authors       = [
                         'Avi Deitcher https://github.com/deitch',
                         'Jonathan Hurter https://github.com/johnsudaar',
                         'Dmitry Fleytman https://github.com/dmitryfleytman',
                         'Grey Baker https://github.com/greysteil'
                       ]
  spec.summary       = 'Docker v2 registry HTTP API client'
  spec.description   = 'Docker v2 registry HTTP API client with support for token authentication'
  spec.homepage      = 'https://github.com/deitch/docker_registry2'
  spec.license       = 'MIT'

  spec.files         = %w{README.md} + Dir.glob("*.gemspec") + Dir.glob("{lib}/**/*", File::FNM_DOTMATCH).reject { |f| File.directory?(f) }
  spec.executables   = spec.files.grep(/^bin\//) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(/^(test|spec|features)\//)
  spec.require_paths = ['lib']
  spec.add_dependency 'gzip'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rubocop', '>= 0.26.0'
  spec.add_development_dependency 'rspec', '>= 3.4.0'

  spec.add_dependency 'rest-client', '>= 1.8.0'
end
