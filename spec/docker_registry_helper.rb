class DockerRegistryHelper
  # list all repos: http://localhost:5000/v2/_catalog

  attr_accessor :image_name, :port, :local, :network_name, :logger

  def initialize(image_name = 'registry', local = true, port= 5000, network_name = "test-registry" )
    @image_name = image_name
    @port = port
    @local = local
    @network_name = network_name
    @logger ||= Logger.new(STDOUT)
    @logger.level = Logger::INFO
  end

  def setup!
    logger.debug "--setup started--"
    sysexec "docker network create #{network_name}"
    sysexec("docker run --name #{image_name} --network=#{network_name} -d -e REGISTRY_STORAGE_DELETE_ENABLED=true -p #{port}:5000 #{image_name}:2.6")
    sysexec "docker exec #{image_name} mkdir -p /var/lib/registry/docker/registry"
    sysexec "docker cp #{Dir.pwd}/spec/registry/v2/. registry:/var/lib/registry/docker/registry/v2"
    logger.debug "--setup ended--"
  end

  def start!
    cleanup!
    setup!
  end

  def stop!
    kill_registry!
    rm_registry!
    cleanup_network!
  end

  def build_registry!
    sysexec("docker build --network=#{network_name} --build-arg registry=\"#{reg_url}\" --build-arg cachebuster=#{Time.now.to_i } --target=test -t gem-test .")
  end

  def cleanup_network!
    sysexec("docker network rm #{network_name}")
  end

  def kill_registry!
    sysexec("docker kill registry")
  end

  def rm_registry!
    sysexec("docker rm registry")
  end

  def registry_url
    url = local ? 'localhost' : 'registry'
    "http://#{url}:#{@port}"
  end

  def cleanup!
    logger.debug "--- Cleaning up started --"
    sysexec "docker kill registry"
    sysexec "docker rm registry"
    sysexec "docker network rm #{@network_name}"
    logger.debug "--- Cleaning up ended --"
  end

  def sysexec(cmd)
    logger.debug "#{cmd}"
    unless logger.level == Logger::DEBUG
      cmd = cmd + " 2> /dev/null"
    end
    system cmd
  end

end
