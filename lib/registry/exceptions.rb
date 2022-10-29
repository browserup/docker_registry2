module DockerRegistry2
  class Exception < RuntimeError
  end
  
  class RegistryAuthenticationException < Exception
  end

  class RegistryAuthorizationException < Exception
  end

  class RegistryUnknownException < Exception
  end

  class RegistrySSLException < Exception
  end

  class RegistryVersionException < Exception
  end
  
  class ReauthenticatedException < Exception
  end
  
  class UnknownRegistryException < Exception
  end

  class NotFound < Exception
  end

  class InvalidMethod < Exception
  end

  class RegistryAppendError < Exception
  end
end