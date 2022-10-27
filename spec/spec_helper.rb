require 'bundler/setup'
Bundler.setup

require 'docker_registry2' # and any other gems you need

require_relative 'docker_registry_helper'

RSpec.configure do |config|
  # some (optional) config here
end

def within_tmpdir
  tmpdir = Dir.mktmpdir
  yield(tmpdir)
ensure
  FileUtils.remove_entry_secure tmpdir
end