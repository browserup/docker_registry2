require_relative 'spec_helper'
require 'tmpdir'

describe DockerRegistry2 do

  before(:all) do
    version = 'v2'
    $reg_helper = DockerRegistryHelper.new()
    $reg_helper.start!
    @image_name = "hello-world-#{version}"
    @registry = DockerRegistry2.connect($reg_helper.registry_url)
    @manifest = @registry.manifest @image_name, "latest"
  end

  after(:all) do
    $reg_helper.stop!
  end

  it "has tags" do
    tags = @registry.tags @image_name
    if tags == nil || tags["name"] != @image_name || tags["tags"] != ["latest"]
      raise "Bad tags"
    end
  end

  it 'gets manifest config' do
    config = @registry.get_manifest_config(@image_name, @manifest['config']['digest'])
    expect(config['rootfs']['diff_ids']).to be_a Array
  end

  it 'can add tags' do
    random_tag = ('a'..'z').to_a.shuffle[0,8].join
    @registry.tag @image_name, "latest", @image_name, random_tag

    # give the registry a chance to catch up
    sleep 1

    more_tags = @registry.tags @image_name
    unless (more_tags["tags"] - [random_tag, "latest"]).empty?
      raise "Failed to add tag"
    end

    # can we delete tags?
    @registry.rmtag @image_name, random_tag

    # give the registry a chance to catch up
    sleep 1

    even_more_tags = @registry.tags @image_name
    if even_more_tags["tags"] != ["latest"]
      raise "Failed to delete tag"
    end
  end

  it "gets a blob" do
    image_blob = @registry.blob @image_name, @manifest['config']['digest']
    layer_blob = within_tmpdir do |tmpdir|
      tmpfile = File.join(tmpdir, 'first_layer.blob')
      @registry.blob @image_name, @manifest['layers'].first['digest'], tmpfile
      filesize = File.size(tmpfile)
      expect(filesize > 0).to be_truthy
    end
  end

  it "gets a digest" do
    digest = @registry.digest @image_name, "latest"
    expect(digest).to_not be_nil
  end

  it "pulls an image" do
    expect {
      within_tmpdir {|tmpdir|
        @registry.pull @image_name, "latest", tmpdir
        expect(File.size(tmpdir) > 0).to be_truthy
      }
    }.to_not raise_error
  end

  it "uploads a blob from filepath" do
    tarball_filepath = File.join(File.dirname(__FILE__ ),'files', 'mydata.tgz')
    digest = @registry.upload_blob_from_filepath(@image_name, tarball_filepath)
    result = @registry.blob(@image_name, digest)
    expect(result).to_not be_nil
  end

  it "uploads a blob from string" do
    tarball_filepath = File.join(File.dirname(__FILE__ ),'files', 'mydata.tgz')
    response = @registry.upload_blob_from_string(@image_name, "hello world")
    digest = response.headers[:docker_content_digest]
    response = @registry.blob(@image_name, digest)
    expect(response.headers[:docker_content_digest]).to_not be_nil
  end

  it 'uploads a layer from tarball' do
    @orig_manifest = @registry.manifest @image_name, "latest"
    tarball_filepath = File.join(File.dirname(__FILE__ ),'files', 'mydata.tgz')
    @registry.append_blob(@image_name, "latest", tarball_filepath)

    @registry.append_blob('localhost:5000/bash', "latest", tarball_filepath)


    @new_manifest = @registry.manifest @image_name, "latest"
    expect(@new_manifest).to_not eq @manifest
    expect(@new_manifest.to_s.include?('digest'))
  end

end