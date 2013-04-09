require 'base64'

module MtGox
  module Request
    def get(path, version, options={})
      request(:get, path, version, options)
    end

    def post(path, version, options={})
      request(:post, path, version, options)
    end

    private

    def request(method, path, version, options)
      api_path = "/api/#{version}/#{path}"

      response = connection.send(method) do |request|
        case method
        when :get
          request.url(api_path, options)
        when :post
          request.path = api_path
          request.body = body_from_options(options)
          request.headers = headers(path, version, request.body)
        end
      end
      response.body
    end

    def headers(path, version, request)
      sig_text = ""
      if version < 2
        sig_text = request
      else
        sig_text = "#{path}\0#{request}"
      end

      signature = Base64.strict_encode64(
        OpenSSL::HMAC.digest 'sha512',
        Base64.decode64(MtGox.secret),
        sig_text
      )
      {'Rest-Key' => MtGox.key, 'Rest-Sign' => signature}
    end

    def body_from_options(options)
      add_nonce(options).collect{|k, v| "#{k}=#{v}"} * '&'
    end

    def add_nonce(options)
      options.merge!({nonce: (Time.now.to_f * 1000000).to_i})
    end
  end
end
