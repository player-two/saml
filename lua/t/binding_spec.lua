local utils = require "utils"

describe("binding", function()
  local binding, saml
  local key, cert, authn_request

  local redirect_signature = ""

  local redirect_binding = "SAMLRequest=fVNNr9MwELz3V1i%2bN3Hy%2bkGtNqi0fFQqbdQEDlyQsTfUUmwH23mv%2fHuc0KIgQU6W7JnZmd312jFVN3Tb%2bqu%2bwI8WnEc3VWtH%2b4cNbq2mhjnpqGYKHPWcFtuPR5pGhDbWeMNNjQeUcQZzDqyXRmN02G%2fw%2bfT2eH5%2fOH19RVZLsqwIeSJsLghZpISvxEpUq2W1SJesgpXgPJ1h9BmsC%2fwNDnIY5dY8SwH2FCptcJEjHwIEbedaOGjnmfYBSZLZlCynyaJMn%2bg8pbP5F4z2ASk1873Y1fuGxrEUTQQ3ppoaIm5UXBTnAuyz5BA116Yv1wd%2bI7WQ%2bvt41m%2b%2fQY5%2bKMt8mp%2bLEqPtI%2f%2fOaNcqsHf5T5fjHxPubw8ClEnioAW3zsRrxh3OJgitu27TPqnNxqgKPBPMs469joesh0pDu%2f4d9rmpJf%2bJ3hmrmP9%2fuCRK%2bhspplUPpaCYrLdCWHAuhKxr87KzwHyYibct4HhQ6r5lIPqdC33wcPNoZ1TDrHTdMEIE7vuMj5RD6K4OS3SBKhvdM055hwvXeThejBXd7ICHuqVl2jXG%2bnsz%2fine%2bY1HDGeTx%2fPw62STXw%3d%3d&RelayState=%2f&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha512&Signature=hv2rYd1cx0UtJWEkKDpHW1kjMErZKOKU6DRoV%2fOaQEJVXCeBuNtgopP8udKsR6VKXbDCfXkb7DEMMO1jSNZ6QN1zfqWKw14LV7Xg4mwr2%2b9erQTx9Axm0nwcWPfN%2fbu7WIVYkq9vFDR%2bvHPxfle2sTml9nOVnj4rucZ6Pvn71C4nPee9MicRg56aBpEhfGKrEcRVxj3DeMwul1TS68HQt417UpMvcP8Zor49B8pN2FsQL%2f1Ao9bpgHvaBdqfG%2btnNAwzd83xzjHG1MPDASw8%2fO39ZPh1t6EfT%2fey7rILwAt%2fQQnGNzbvL8VyrFTeaunyNI4KaOKpF4W9LJOxuwe3PQ%3d%3d"

  setup(function()
    binding = require "resty.saml.binding"
    saml    = require "saml"

    authn_request = assert(utils.readfile("data/authn_request.xml"))

    local err = saml.init({ debug=true, rock_dir=assert(os.getenv("ROCK_DIR")) })
    if err then print(err) assert(nil) end

    key = assert(saml.key_read_file("data/sp.key", saml.KeyDataFormatPem))
    assert(saml.key_add_cert_file(key, "data/sp.crt", saml.KeyDataFormatCertPem))
    cert = assert(saml.key_read_file("data/sp.crt", saml.KeyDataFormatCertPem))

    stub(ngx.req, "get_method")
    stub(ngx.req, "get_post_args")
    stub(ngx.req, "get_uri_args")
    stub(ngx.req, "read_body")
  end)

  teardown(function()
    ngx.req.get_method:revert()
    ngx.req.get_post_args:revert()
    ngx.req.get_uri_args:revert()
    ngx.req.read_body:revert()
  end)

  before_each(function()
    ngx.req.get_method:clear()
    ngx.req.get_post_args:clear()
    ngx.req.get_uri_args:clear()
    ngx.req.read_body:clear()
  end)


  describe(".create_redirect()", function()

    it("errors for bad sig alg", function()
      local query_string, err = binding.create_redirect(key, { SigAlg = "alg", SAMLRequest = authn_request, RelayState = "/" })
      assert.are.equal("invalid signature algorithm", err)
      assert.is_nil(query_string)
    end)

    it("creates a full query string", function()
      local query_string, err = binding.create_redirect(key, { SigAlg = utils.xmlSecHrefRsaSha512, SAMLRequest = authn_request, RelayState = "/" })
      assert.is_nil(err)
      assert.are.equal(redirect_binding, query_string)
    end)

  end)


  describe(".parse_redirect()", function()
    local cb = function(doc) return cert end
    local cb_error = function(doc) return nil end
    local valid_args

    before_each(function()
      valid_args = {
        SAMLRequest = "fVNNr9MwELz3V1i+N3Hy+kGtNqi0fFQqbdQEDlyQsTfUUmwH23mv/Huc0KIgQU6W7JnZmd312jFVN3Tb+qu+wI8WnEc3VWtH+4cNbq2mhjnpqGYKHPWcFtuPR5pGhDbWeMNNjQeUcQZzDqyXRmN02G/w+fT2eH5/OH19RVZLsqwIeSJsLghZpISvxEpUq2W1SJesgpXgPJ1h9BmsC/wNDnIY5dY8SwH2FCptcJEjHwIEbedaOGjnmfYBSZLZlCynyaJMn+g8pbP5F4z2ASk1873Y1fuGxrEUTQQ3ppoaIm5UXBTnAuyz5BA116Yv1wd+I7WQ+vt41m+/QY5+KMt8mp+LEqPtI//OaNcqsHf5T5fjHxPubw8ClEnioAW3zsRrxh3OJgitu27TPqnNxqgKPBPMs469joesh0pDu/4d9rmpJf+J3hmrmP9/uCRK+hspplUPpaCYrLdCWHAuhKxr87KzwHyYibct4HhQ6r5lIPqdC33wcPNoZ1TDrHTdMEIE7vuMj5RD6K4OS3SBKhvdM055hwvXeThejBXd7ICHuqVl2jXG+nsz/ine+Y1HDGeTx/Pw62STXw==",
        RelayState = "/",
        SigAlg = utils.xmlSecHrefRsaSha512,
        Signature = "hv2rYd1cx0UtJWEkKDpHW1kjMErZKOKU6DRoV/OaQEJVXCeBuNtgopP8udKsR6VKXbDCfXkb7DEMMO1jSNZ6QN1zfqWKw14LV7Xg4mwr2+9erQTx9Axm0nwcWPfN/bu7WIVYkq9vFDR+vHPxfle2sTml9nOVnj4rucZ6Pvn71C4nPee9MicRg56aBpEhfGKrEcRVxj3DeMwul1TS68HQt417UpMvcP8Zor49B8pN2FsQL/1Ao9bpgHvaBdqfG+tnNAwzd83xzjHG1MPDASw8/O39ZPh1t6EfT/ey7rILwAt/QQnGNzbvL8VyrFTeaunyNI4KaOKpF4W9LJOxuwe3PQ==",
      }

      ngx.req.get_method.returns("GET")
      ngx.req.get_uri_args.returns(valid_args)
    end)

    it("errors for non-GET method", function()
      ngx.req.get_method.returns("POST")
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("method not allowed", err)
      assert.is_nil(doc)
      assert.is_nil(args)
    end)

    it("errors for bad base64 encoding", function()
      valid_args.SAMLRequest = "xml"
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("invalid base64 content", err)
      assert.is_nil(doc)
      assert.are.same(valid_args, args)
    end)

    it("errors for bad compression", function()
      valid_args.SAMLRequest = saml.base64_encode("xml")
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("data not in zlib format", err)
      assert.is_nil(doc)
      assert.are.same(valid_args, args)
    end)

    it("errors for invalid xml", function()
      valid_args.SAMLRequest = "q8jN4QIA"
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("content is not valid xml", err)
      assert.is_nil(doc)
      assert.are.same(valid_args, args)
    end)

    it("errors for invalid document", function()
      valid_args.SAMLRequest = "fVNNj9MwEL33V1i+N2nKLkhWG1S6QlRa2KjJ7oGbsWeppfgDz2S3/Hsc06IgQU62xu/NvDcz3qC0fRC7gU7uCD8GQGJn2zsU+WHLh+iEl2hQOGkBBSnR7j7fi3WxEiF68sr3fEKZZ0hEiGS84+wJIqbLlqc4Z030L0ZD/JIoW942jJISzg6IAxwcknSUkKvqZrl6t6zedus34nYtbm6/cnaXkMZJyslOREGUpdGhgLO0oYdCeVu27UML8cUoKMIp5HJZ+QfjtHHf50V/+w1C8anrmmXz0Hac7a5G9t7hYCFe0j8e7/+IwL81aLC+KlMuOI8i3kuFvF4wthnbJrLTWM9RLZDUkuTI3pRT1jVLEGP/DneN7436yT76aCX931xVVDli9PI5QwVYafqd1hEQk8m+96/7CJLSTCgOwMtJqcu6gM7Lk/pAcCa29zbIaHAcRrKgKHu8upxC933ahiM817MLo4QacSncpOPVRz3ODlSq20XpMPhIl2b8M/mot5wRXC+uz9M/UC9+AQ=="
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("document does not validate against schema", err)
      assert.is_not_nil(doc)
      assert.are.same(valid_args, args)
    end)

    it("errors when no cert is found", function()
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb_error)
      assert.are.equal("no cert", err)
      assert.is_not_nil(doc)
      assert.are.same(valid_args, args)
    end)

    it("errors for invalid signature", function()
      valid_args.Signature = "sig"
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb)
      assert.are.equal("invalid base64 content", err)
      assert.is_not_nil(doc)
    end)

    it("errors for verify failure", function()
      valid_args.Signature = "c2lnCG=="
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb)
      assert.are.equal("signature does not match", err)
      assert.is_not_nil(doc)
    end)

    it("returns the parsed document", function()
      local doc, args, err = binding.parse_redirect("SAMLRequest", cb)
      assert.is_nil(err)
      assert.is_not_nil(doc)
      assert.are.equal("ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24", saml.doc_id(doc))
    end)

  end)

  --[[
  describe(".create_post()", function()

    before_each(function()
      saml.sign_xml.returns("signed request", nil)
    end)

    it("signs a request", function()
      binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", { SAMLRequest = "request" })
      assert.spy(saml.sign_xml).was.called_with("key", utils.xmlSecHrefRsaSha512, "request", match.is_table())
    end)

    it("signs a response", function()
      binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", { SAMLResponse = "response" })
      assert.spy(saml.sign_xml).was.called_with("key", utils.xmlSecHrefRsaSha512, "response", match.is_table())
    end)

    it("aborts without a request or response", function()
      assert.has_error(function()
        binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", {})
      end, "no saml request or response")
    end)

    it("errors for signature failure", function()
      saml.sign_xml.returns(nil, "signature failed")
      local html, err = binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", { SAMLRequest = "request" })
      assert.are.equal("signature failed", err)
      assert.is_nil(html)
    end)

    it("passes the destination", function()
      local html, err = binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", { SAMLRequest = "request" })
      assert.is_nil(err)
      local action = html:match('action="(%w+)"')
      assert.are.equal("dest", action)
    end)

    it("passes a copy of the params", function()
      local params = { SAMLRequest = "request", RelayState = "relay" }
      local html, err = binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", params)
      assert.is_nil(err)
      assert.are.same({
        SAMLRequest = "request",
        RelayState = "relay",
      }, params)
    end)

    it("returns the form template", function()
      local html, err = binding.create_post("key", utils.xmlSecHrefRsaSha512, "dest", { SAMLRequest = "request" })
      assert.is_nil(err)
      assert.is_not_nil(html:find("<html>"))

      local name, value = html:match('name="([^"]+)" value="([^"]+)"')
      assert.are.equal("SAMLRequest", name)
      assert.are.equal("c2lnbmVkIHJlcXVlc3Q=", value)
    end)

  end)


  describe(".parse_post()", function()
    local input_doc = "<Response>"
    local parsed = "parsed document"
    local mngr = { cert = "" }
    local cb = function(doc) return mngr end
    local cb_error = function(doc) return nil end
    local default_args = { SAMLRequest = "PFJlc3BvbnNlPg==" }

    before_each(function()
      ngx.req.get_method.returns("POST")
      ngx.req.get_post_args.returns(default_args, nil)
      saml.create_keys_manager.returns(mngr)
      saml.verify_doc.returns(true, nil)
      saml.doc_read_memory.returns(parsed)
      saml.doc_validate.returns(true)
    end)

    it("errors for non-POST method", function()
      ngx.req.get_method.returns("GET")
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("method not allowed", err)
      assert.is_nil(doc)
      assert.is_nil(args)
    end)

    it("errors for argument retrieval", function()
      ngx.req.get_post_args.returns(nil, "bad request body")
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("bad request body", err)
      assert.is_nil(doc)
      assert.is_nil(args)
    end)

    it("errors for missing content", function()
      ngx.req.get_post_args.returns({}, nil)
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("no SAMLRequest", err)
      assert.is_nil(doc)
      assert.are.same({}, args)
    end)

    it("errors for invalid xml", function()
      saml.doc_read_memory.returns(nil)
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.spy(saml.doc_read_memory).was.called_with("<Response>")
      assert.are.equal("SAMLRequest is not valid xml", err)
      assert.is_nil(doc)
      assert.are.same(default_args, args)
    end)

    it("errors for invalid document", function()
      saml.doc_validate.returns(false)
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("document does not validate against schema", err)
      assert.are.equal(parsed, doc)
    end)

    it("errors when no cert is found", function()
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("no key manager", err)
      assert.are.equal(parsed, doc)
    end)

    it("passes args to verify function", function()
      binding.parse_post("SAMLRequest", cb)
      assert.spy(saml.verify_doc).was.called(1)
      local args = saml.verify_doc.calls[1].vals
      assert.are.same(mngr, args[1])
      assert.are.equal(parsed, args[2])
    end)

    it("errors for verify failure", function()
      saml.verify_doc.returns(false, "verify failed")
      local doc, args, err = binding.parse_post("SAMLRequest", cb)
      assert.are.equal(err, "verify failed")
      assert.are.equal(parsed, doc)
    end)

    it("errors for invalid signature", function()
      saml.verify_doc.returns(false, nil)
      local doc, args, err = binding.parse_post("SAMLRequest", cb)
      assert.are.equal(err, "invalid signature")
      assert.are.equal(parsed, doc)
    end)

    it("returns the parsed document", function()
      saml.verify_doc.returns(true, nil)
      local doc, args, err = binding.parse_post("SAMLRequest", cb)
      assert.is_nil(err)
      assert.are.equal(parsed, doc)
    end)
  end)
  ]]

end)
