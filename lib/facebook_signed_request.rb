require 'openssl'
require 'base64'

class FacebookSignedRequest
  attr_reader :params, :signature, :signed_params, :app_id, :url
  
  def initialize(signed_request,secret, app_id, url)
    @app_id = app_id
    @url    = url
    @signature, @signed_params = signed_request.to_s.split('.')
    if signed_request_is_valid?(secret, @signature, @signed_params)
      @params = JSON.parse(base64_url_decode(@signed_params))
    end
  end

private
  def signed_request_is_valid?(secret, signature, params)
    return false if secret.blank? || signature.blank? || params.blank?
    signature = base64_url_decode(signature)
    expected_signature = OpenSSL::HMAC.digest('SHA256', secret, params.tr("-_", "+/"))
    return signature == expected_signature
  end

  def base64_url_decode(str)
    str = str + "=" * (6 - str.size % 6) unless str.size % 6 == 0
    return Base64.decode64(str.tr("-_", "+/"))
  end
end
