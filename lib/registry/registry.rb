require 'fileutils'
require 'rest-client'
require 'json'
require 'gzip'
require 'digest'

class DockerRegistry2::Registry
  # @param [#to_s] base_uri Docker registry base URI
  # @param [Hash] options Client options
  # @option options [#to_s] :user User name for basic authentication
  # @option options [#to_s] :password Password for basic authentication
  # @option options [#to_s] :open_timeout Time to wait for a connection with a registry.
  #                                       It is ignored if http_options[:open_timeout] is also specified.
  # @option options [#to_s] :read_timeout Time to wait for data from a registry.
  #                                       It is ignored if http_options[:read_timeout] is also specified.
  # @option options [Hash] :http_options Extra options for RestClient::Request.execute.
  def initialize(uri, options = {})
    @uri = URI.parse(uri)
    @base_uri = "#{@uri.scheme}://#{@uri.host}:#{@uri.port}"
    @user = options[:user]
    @password = options[:password]
    @http_options = options[:http_options] || {}
    @http_options[:open_timeout] ||= options[:open_timeout] || 2
    @http_options[:read_timeout] ||= options[:read_timeout] || 5
  end

  def doget(url)
    return doreq "get", url
  end

  def doput(url, payload = nil)
    return doreq "put", url, nil, payload
  end

  def dodelete(url)
    return doreq "delete", url
  end

  def dohead(url)
    return doreq "head", url
  end

  # When a result set is too large, the Docker registry returns only the first items and adds a Link header in the
  # response with the URL of the next page. See <https://docs.docker.com/registry/spec/api/#pagination>. This method
  # iterates over the pages and calls the given block with each response.
  def paginate_doget(url)
    while url
      response = doget(url)
      yield response

      if (link = response.headers[:link])
        url = parse_link_header(link)[:next]
      else
        break
      end
    end
  end

  def search(query = '')
    all_repos = []
    paginate_doget "/v2/_catalog" do |response|
      # parse the response
      repos = JSON.parse(response)["repositories"]
      if query.strip.length > 0
        re = Regexp.new query
        repos = repos.find_all { |e| re =~ e }
      end
      all_repos += repos
    end
    all_repos
  end

  def get_manifest_config(repo, config_blob_sha)
    response = blob(repo, config_blob_sha)
    raise RegistryAppendError.new('get_manifest_config failed') unless response.headers[:docker_content_digest]
    JSON.parse(response.body)
  end

  def tags(repo, count = nil, last = "", withHashes = false, auto_paginate: false)
    #create query params
    params = []
    params.push(["last", last]) if last && last != ""
    params.push(["n", count]) unless count.nil?

    query_vars = ""
    query_vars = "?#{URI.encode_www_form(params)}" if params.length > 0

    response = doget "/v2/#{repo}/tags/list#{query_vars}"
    # parse the response
    resp = JSON.parse response
    # parse out next page link if necessary
    resp["last"] = last(response.headers[:link]) if response.headers[:link]

    # do we include the hashes?
    if withHashes
      useGet = false
      resp["hashes"] = {}
      resp["tags"].each do |tag|
        if useGet
          head = doget "/v2/#{repo}/manifests/#{tag}"
        else
          begin
            head = dohead "/v2/#{repo}/manifests/#{tag}"
          rescue DockerRegistry2::InvalidMethod
            # in case we are in a registry pre-2.3.0, which did not support manifest HEAD
            useGet = true
            head = doget "/v2/#{repo}/manifests/#{tag}"
          end
        end
        resp["hashes"][tag] = head.headers[:docker_content_digest]
      end
    end

    return resp unless auto_paginate

    while (last_tag = resp.delete("last"))
      additional_tags = tags(repo, count, last_tag, withHashes)
      resp["last"] = additional_tags["last"]
      resp["tags"] += additional_tags["tags"]
      resp["tags"] = resp["tags"].uniq
      resp["hashes"].merge!(additional_tags["hashes"]) if withHashes
    end

    resp
  end

  def manifest(repo, tag)
    # first get the manifest
    response = doget "/v2/#{repo}/manifests/#{tag}"
    parsed = JSON.parse response.body
    manifest = DockerRegistry2::Manifest[parsed]
    manifest.body = response.body
    manifest.headers = response.headers
    manifest
  end

  def blob(repo, digest, outpath = nil)
    blob_url = "/v2/#{repo}/blobs/#{digest}"
    if outpath.nil?
      response = doget(blob_url)
      DockerRegistry2::Blob.new(response.headers, response.body)
    else
      File.open(outpath, 'wb') do |fd|
        doreq('get', blob_url, fd)
      end

      outpath
    end
  end

  def digest(repo, tag)
    tag_path = "/v2/#{repo}/manifests/#{tag}"
    dohead(tag_path).headers[:docker_content_digest]
  rescue DockerRegistry2::InvalidMethod
    # Pre-2.3.0 registries didn't support manifest HEAD requests
    doget(tag_path).headers[:docker_content_digest]
  end

  def rmtag(image, tag)
    # TODO: Need full response back. Rewrite other manifests() calls without JSON?
    reference = doget("/v2/#{image}/manifests/#{tag}").headers[:docker_content_digest]

    return dodelete("/v2/#{image}/manifests/#{reference}").code
  end

  def pull(repo, tag, dir)
    # make sure the directory exists
    FileUtils.mkdir_p dir
    # get the manifest
    m = manifest repo, tag
    # puts "pulling #{repo}:#{tag} into #{dir}"
    # manifest can contain multiple manifests one for each API version
    downloaded_layers = []
    downloaded_layers += _pull_v2(repo, m, dir) if m['schemaVersion'] == 2
    downloaded_layers += _pull_v1(repo, m, dir) if m['schemaVersion'] == 1
    # return downloaded_layers
    downloaded_layers
  end

  def _pull_v2(repo, manifest, dir)
    # make sure the directory exists
    FileUtils.mkdir_p dir
    return false unless manifest['schemaVersion'] == 2
    # pull each of the layers
    manifest['layers'].each do |layer|
      # define path of file to save layer in
      layer_file = "#{dir}/#{layer['digest']}"
      # skip layer if we already got it
      next if File.file? layer_file
      # download layer
      # puts "getting layer (v2) #{layer['digest']}"
      blob(repo, layer['digest'], layer_file)
      layer_file
    end
  end

  def _pull_v1(repo, manifest, dir)
    # make sure the directory exists
    FileUtils.mkdir_p dir
    return false unless manifest['schemaVersion'] == 1
    # pull each of the layers
    manifest['fsLayers'].each do |layer|
      # define path of file to save layer in
      layer_file = "#{dir}/#{layer['blobSum']}"
      # skip layer if we already got it
      next if File.file? layer_file
      # download layer
      # puts "getting layer (v1) #{layer['blobSum']}"
      blob(repo, layer['blobSum'], layer_file)
      # return layer file
      layer_file
    end
  end

  def push(manifest, dir) end

  def upload_blob_from_filepath(repo, filepath, digest = nil)
    # init a new empty blob in the registry
    digest ||= 'sha256:' + Digest::SHA256.file(filepath).to_s
    size = File.size(filepath)
    data = File.open(filepath, "rb")
    response = prepare_upload(repo)

    uuid = response.headers[:docker_upload_uuid]
    location = response.headers[:location] + "&digest=#{digest}"

    extra_headers = {
      'Content-Length' => size,
      'Content-Type' => 'application/octet-stream'
    }
    response = doreq(:put, location, nil, data, extra_headers)
    response
  end

  def upload_blob_from_string(repo, data)
    # init a new empty blob in the registry
    digest = 'sha256:' + Digest::SHA256.hexdigest(data).to_s
    response = prepare_upload(repo)

    uuid = response.headers[:docker_upload_uuid]
    location = response.headers[:location] + "&digest=#{digest}"

    extra_headers = {
      'Content-Length' => data.length,
      'Content-Type' => 'application/octet-stream'
    }
    response = doreq(:put, location, nil, data, extra_headers)
    response
  end

  def tag(repo, tag, newrepo, newtag)
    manifest = manifest(repo, tag)

    if manifest['schemaVersion'] == 2
      doput "/v2/#{newrepo}/manifests/#{newtag}", manifest.to_json
    else
      raise DockerRegistry2::RegistryVersionException
    end
  end

  def append_tarball(repo, tag, filepath)
    layer_sha = "sha256:#{Digest::SHA256.file(filepath)}"
    uncompressed_layer_sha = "sha256:#{unzipped_sha(filepath)}"
    response = upload_blob_from_filepath(repo, filepath, layer_sha)
    raise RegistryAppendError.new('Upload layer failed') unless response.headers[:docker_content_digest]
    layer_size = File.size(filepath)
    manifest = manifest(repo, tag)
    config = get_manifest_config(repo, manifest['config']['digest'])


    layer_history = { 'created' => Time.now.utc.round(10).iso8601(9),
                      'created_by' => "/bin/sh -c #(nop) ADD file:#{uncompressed_layer_sha} in /" }

    config['rootfs']['diff_ids'] << uncompressed_layer_sha
    config['history'] << layer_history
    config['created'] = Time.now.utc.round(10).iso8601(9)
    config_serialized = config.to_json

    manifest["layers"] << { "mediaType" => "application/vnd.oci.image.layer.v1.tar+gzip",
                            "size" => layer_size,
                            "digest" => layer_sha }

    response = upload_blob_from_string(repo, config_serialized)
    raise RegistryAppendError.new('Upload layer failed') unless response.headers[:docker_content_digest]

    config_digest = response.headers[:docker_content_digest]

    new_conf = get_manifest_config(repo, config_digest)

    config_info = { "mediaType" => "application/vnd.oci.image.config.v1+json",
                    "size" => config_serialized.size,
                    "digest" => response.headers[:docker_content_digest] }

    manifest["config"] = config_info

    response = upload_manifest(repo, tag, manifest)
    raise RegistryAppendError.new('Upload layer failed') unless response.headers[:docker_content_digest]
    manifest
  end

  def upload_manifest(repo, tag, manifest)
    manifest_json = manifest.to_json
    doreq(:put, "/v2/#{repo}/manifests/#{tag}", nil, manifest_json, { 'Content-Type' => 'application/vnd.docker.distribution.manifest.v2+json' })
  end

  def copy(repo, tag, newregistry, newrepo, newtag) end

  # gets the size of a particular blob, given the repo and the content-addressable hash
  # usually unneeded, since manifest includes it
  def blob_size(repo, blobSum)
    response = dohead "/v2/#{repo}/blobs/#{blobSum}"
    Integer(response.headers[:content_length], 10)
  end

  # Parse the value of the Link HTTP header and return a Hash whose keys are the rel values turned into symbols, and
  # the values are URLs. For example, `{ next: '/v2/_catalog?n=100&last=x' }`.
  def parse_link_header(header)
    last = ''
    parts = header.split(',')
    links = Hash.new

    # Parse each part into a named link
    parts.each do |part, index|
      section = part.split(';')
      url = section[0][/<(.*)>/, 1]
      name = section[1][/rel="?([^"]*)"?/, 1].to_sym
      links[name] = url
    end

    links
  end

  def last(header)
    links = parse_link_header(header)
    if links[:next]
      query = URI(links[:next]).query
      link_key = @uri.host.eql?('quay.io') ? 'next_page' : 'last'
      last = URI::decode_www_form(query).to_h[link_key]
    end
    last
  end

  def manifest_sum(manifest)
    size = 0
    manifest["layers"].each { |layer|
      size += layer["size"]
    }
    size
  end

  private

  def prepare_upload(repo)
    doreq(:post, "/v2/#{repo}/blobs/uploads/", nil, nil, { 'Content-Length' => 0 })
  end

  def doreq(type, url, stream = nil, payload = nil, extra_headers = {})
    begin
      block = stream.nil? ? nil : proc { |response|
        response.read_body do |chunk|
          stream.write chunk
        end
      }
      h = headers(payload: payload)
      full_headers = h.merge(extra_headers)
      url = @base_uri + url unless url.start_with?('http')

      response = RestClient::Request.execute(@http_options.merge(
        method: type,
        url: url,
        headers: full_headers,
        block_response: block,
        payload: payload
      ))
    rescue RestClient::BadRequest => e
      raise DockerRegistry2::UnknownRegistryException
    rescue SocketError
      raise DockerRegistry2::RegistryUnknownException
    rescue RestClient::NotFound => error
      raise DockerRegistry2::NotFound, error
    rescue RestClient::Unauthorized => e
      header = e.response.headers[:www_authenticate]
      method = header.to_s.downcase.split(' ')[0]
      case method
      when 'basic'
        response = do_basic_req(type, url, stream, payload)
      when 'bearer'
        response = do_bearer_req(type, url, header, stream, payload)
      else
        raise DockerRegistry2::RegistryUnknownException
      end
    end
    return response
  end

  def do_basic_req(type, url, stream = nil, payload = nil)
    begin
      block = stream.nil? ? nil : proc { |response|
        response.read_body do |chunk|
          stream.write chunk
        end
      }
      response = RestClient::Request.execute(@http_options.merge(
        method: type,
        url: @base_uri + url,
        user: @user,
        password: @password,
        headers: headers(payload: payload),
        block_response: block,
        payload: payload
      ))
    rescue SocketError
      raise DockerRegistry2::RegistryUnknownException
    rescue RestClient::Unauthorized
      raise DockerRegistry2::RegistryAuthenticationException
    rescue RestClient::MethodNotAllowed
      raise DockerRegistry2::InvalidMethod
    rescue RestClient::NotFound => error
      raise DockerRegistry2::NotFound, error
    end
    return response
  end

  def do_bearer_req(type, url, header, stream = false, payload = nil)
    token = authenticate_bearer(header)
    begin
      block = stream.nil? ? nil : proc { |response|
        response.read_body do |chunk|
          stream.write chunk
        end
      }
      response = RestClient::Request.execute(@http_options.merge(
        method: type,
        url: @base_uri + url,
        headers: headers(payload: payload, bearer_token: token),
        block_response: block,
        payload: payload
      ))
    rescue SocketError
      raise DockerRegistry2::RegistryUnknownException
    rescue RestClient::Unauthorized
      raise DockerRegistry2::RegistryAuthenticationException
    rescue RestClient::MethodNotAllowed
      raise DockerRegistry2::InvalidMethod
    rescue RestClient::NotFound => error
      raise DockerRegistry2::NotFound, error
    end

    return response
  end

  def authenticate_bearer(header)
    # get the parts we need
    target = split_auth_header(header)
    # did we have a username and password?
    if defined? @user and @user.to_s.strip.length != 0
      target[:params][:account] = @user
    end
    # authenticate against the realm
    uri = URI.parse(target[:realm])
    begin
      response = RestClient::Request.execute(@http_options.merge(
        method: :get,
        url: uri.to_s, headers: { params: target[:params] },
        user: @user,
        password: @password,
      ))
    rescue RestClient::Unauthorized, RestClient::Forbidden
      # bad authentication
      raise DockerRegistry2::RegistryAuthenticationException
    rescue RestClient::NotFound => error
      raise DockerRegistry2::NotFound, error
    end
    # now save the web token
    result = JSON.parse(response)
    return result["token"] || result["access_token"]
  end

  def split_auth_header(header = '')
    h = Hash.new
    h = { params: {} }
    header.scan(/([\w]+)\=\"([^"]+)\"/) do |entry|
      case entry[0]
      when 'realm'
        h[:realm] = entry[1]
      else
        h[:params][entry[0]] = entry[1]
      end
    end
    h
  end

  def make_digest(data)
    "sha256:" + Digest::SHA256.hexdigest(data)
  end

  def unzipped_sha(filepath)
    Zlib::GzipReader.open(filepath) { |gz| return Digest::SHA256.hexdigest(gz.read) }
  end

  def headers(payload: nil, bearer_token: nil)
    headers = {}
    headers['Authorization'] = "Bearer #{bearer_token}" unless bearer_token.nil?
    headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json, application/json' if payload.nil?
    headers['Content-Type'] = 'application/vnd.docker.distribution.manifest.v2+json' unless payload.nil?
    headers
  end
end
