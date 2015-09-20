module Http
  module Client
    def post(uri, request_body)
      debug("Post uri", uri)
      debug("request_body", request_body)

      post_req = Net::HTTP::Post.new(uri)
      post_req.body = request_body

      execute(post_req)
    end

    def execute(request, content_type=nil)
      uri = request.uri
      request['Content-Type'] = content_type || "application/xml"
      request['Accept'] = content_type || "application/xml"

      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') { |http|
        http.request(request)
      }

      debug("res.code", res.code)
      if res.code == "200" || res.code == "201"
        res.body
      else
        raise "Error executing request, method:#{request.method}, uri: #{uri}, req_body: #{request.body}, code: #{res.code}, body: #{res.body}"
      end
    end

    def get(uri, content_type =nil)
      debug("Get uri", uri)
      execute(Net::HTTP::Get.new(uri), content_type)
    end

    def delete(uri)
      debug("Delete uri", uri)
      execute(Net::HTTP::Delete.new(uri))
    end

    def debug(name, variable)
      if $debug
        puts "[DEBUG] #{name} => #{variable.inspect}"
      end
    end
  end
end