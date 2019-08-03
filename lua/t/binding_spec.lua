local utils = require "utils"

local TEST_DATA_DIR = os.getenv("TEST_DATA_DIR")

describe("binding", function()
  local binding, saml
  local key, cert, authn_request

  local redirect_signature = ""

  local redirect_binding = "SAMLRequest=fVNNr9MwELz3V1i%2BN3Hy%2BkGtNqi0fFQqbdQEDlyQsTfUUmwH23mv%2FHuc0KIgQU6W7JnZmd312jFVN3Tb%2Bqu%2BwI8WnEc3VWtH%2B4cNbq2mhjnpqGYKHPWcFtuPR5pGhDbWeMNNjQeUcQZzDqyXRmN02G%2Fw%2BfT2eH5%2FOH19RVZLsqwIeSJsLghZpISvxEpUq2W1SJesgpXgPJ1h9BmsC%2FwNDnIY5dY8SwH2FCptcJEjHwIEbedaOGjnmfYBSZLZlCynyaJMn%2Bg8pbP5F4z2ASk1873Y1fuGxrEUTQQ3ppoaIm5UXBTnAuyz5BA116Yv1wd%2BI7WQ%2Bvt41m%2B%2FQY5%2BKMt8mp%2BLEqPtI%2F%2FOaNcqsHf5T5fjHxPubw8ClEnioAW3zsRrxh3OJgitu27TPqnNxqgKPBPMs469joesh0pDu%2F4d9rmpJf%2BJ3hmrmP9%2FuCRK%2BhspplUPpaCYrLdCWHAuhKxr87KzwHyYibct4HhQ6r5lIPqdC33wcPNoZ1TDrHTdMEIE7vuMj5RD6K4OS3SBKhvdM055hwvXeThejBXd7ICHuqVl2jXG%2Bnsz%2Fine%2BY1HDGeTx%2FPw62STXw%3D%3D&RelayState=%2F&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512&Signature=k0%2BbynPfqT5eg6QqV5nJ0sK6%2Bxun8kMkaUJY4a1BtgF7Y8PJgxghPLFt2EaSeQKsNGnkWW1j7ex2iudWZgX0UkpHiZwyro6l45OMkTBL5CIwaO1jvQIzhIlJkOIw1c8jE0Wpy5M8Rf4GOxl94YOgfbF%2F8JvJgU8OJxk1CW1OFgU8ds9ZhjXaXsAOSFZ6Cg5GozkCprjwbL0TjdgVNXwb6hFMQo1DGsoScIdX64orHC4pjhkdayT2zT9Hnm3S98pM8T3G1G3wCivGYiomRWRGvEE3vm4GkeRplaG%2FqbZwyFyY5yNhqhTkfHDi59249G26mKYp8auOm9onfNSyTXkhtg%3D%3D"

  setup(function()
    binding = require "resty.saml.binding"
    saml    = require "saml"

    authn_request = assert(utils.readfile(TEST_DATA_DIR .. "authn_request.xml"))

    local err = saml.init({ data_dir=assert(os.getenv("DATA_DIR")) })
    if err then print(err) assert(nil) end

    key = assert(saml.key_read_file(TEST_DATA_DIR .. "sp.key", saml.KeyDataFormatPem))
    assert(saml.key_add_cert_file(key, TEST_DATA_DIR .. "sp.crt", saml.KeyDataFormatCertPem))
    cert = assert(saml.key_read_file(TEST_DATA_DIR .. "sp.crt", saml.KeyDataFormatCertPem))

    if not _G.ngx then
      _G.ngx = { req = {} }
    end
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
        SAMLRequest = "nZLPT8IwFIDv/BVN72NjER0vMIIQIwnqAtODtzqqNOna2feG8t/bTSAkEg7emr4f3/deOxx/l5ptpUNlzYj3uhFn47QzRFHqCiY1bcxSftYSiflEg9AERrx2BqxAhWBEKRGogNXkYQFxNwKBKB35dvykpLpcUzlLtrCas5eDStyozGcjrtZB0hwRazk3SMKQj0a9QRBdB/FNHvegH8FV/5WzmfdURlDbYENUQRhqWwi9sUiQRMkgRLScZXvcrTJrZT4uu739JiHc53kWZE+rnLPJYcapNViX0q2k26pCPi8X58FJKApswVu1lu7RU0Z86XV3bF96jPG0w1j7ANDO7NiddaWgy5bNjd/Ue5sK0pCiHU/PqgzDk+ZHWAWN1HyWWa2K3T+Y5IRB5cl+PVrbr6mTgvyU5GrJQ/+nwr+fKv0B",
        RelayState = "/",
        SigAlg = utils.xmlSecHrefRsaSha512,
        Signature = "i+YCidTVfm/Sza2nkBEx+489RWiEI56SV/XJRC9d1hK0dFh9slDZsW7ZBJqSMyQ8CH/noHR46qjTjK5QBPH6awCxRieUFrJQ/ePy6f14cZfPgJxE7ctb8qwNgb6xkqGU2ou/7Bui8DH+mrAKaiJWSpO9AYKteBvGW0zeFBqbQh6M912Hz9m+SjW+l1bTif4LxOn+zDtNrW+QQmCCakcPUOOQhaB+Ml1RaEfu6NVTvCdrwA/1BWfpTb7XyBDvu3GXe4DPmuu0kGqUkUyWhLfFJ3oUNIgUlhXSj6gBP8Hus4ooTbQGNdfiNxBq2SHBdJVN3fVFFA1d+I5MOLlgemGm4g==",
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
      assert.are.equal("id-80", saml.doc_id(doc))
    end)

  end)

  describe(".create_post()", function()

    it("errors for bad sig algorithm", function()
      local html, err = binding.create_post(key, "SAMLRequest", "xml", "rsa", "/", "dest")
      assert.are.equal("invalid signature algorithm", err)
      assert.is_nil(html)
    end)

    it("errors for bad xml", function()
      local html, err = binding.create_post(key, "SAMLRequest", "xml", utils.xmlSecHrefRsaSha512, "/", "dest")
      assert.are.equal("content is not valid xml", err)
      assert.is_nil(html)
    end)

    it("errors for bad document", function()
      local html, err = binding.create_post(key, "SAMLRequest", "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\" Version=\"2.0\" ProviderName=\"SP test\" IssueInstant=\"2014-07-16T23:52:45Z\" Destination=\"http://idp.example.com/SSOService.php\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\"></samlp:AuthnRequest>", utils.xmlSecHrefRsaSha512, "/", "dest")
      assert.are.equal("document does not validate against schema", err)
      assert.is_nil(html)
    end)

    it("returns the form template", function()
      local html, err = binding.create_post(key, "SAMLRequest", "request", utils.xmlSecHrefRsaSha512, "/", "dest")
    end)

  end)


  describe(".parse_post()", function()
    local mngr, post_args, response
    local cb = function(doc) return mngr end
    local cb_error = function(doc) return nil end

    setup(function()
      response = assert(utils.readfile(TEST_DATA_DIR .. "response-signed.xml.b64"))
      mngr = saml.create_keys_manager({ cert })
    end)

    before_each(function()
      post_args = {
        SAMLResponse = response
      }
      ngx.req.get_method.returns("POST")
      ngx.req.get_post_args.returns(post_args, nil)
    end)

    it("errors for non-POST method", function()
      ngx.req.get_method.returns("GET")
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("method not allowed", err)
      assert.is_nil(doc)
      assert.is_nil(args)
    end)

    it("errors for argument retrieval", function()
      ngx.req.get_post_args.returns(nil, "bad request body")
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("bad request body", err)
      assert.is_nil(doc)
      assert.is_nil(args)
    end)

    it("errors for missing content", function()
      local doc, args, err = binding.parse_post("SAMLRequest", cb_error)
      assert.are.equal("no SAMLRequest", err)
      assert.is_nil(doc)
      assert.are.same(post_args, args)
    end)

    it("errors for invalid base64 content", function()
      post_args.SAMLResponse = "xml"
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("invalid base64 content", err)
      assert.is_nil(doc)
      assert.are.same(post_args, args)
    end)

    it("errors for invalid xml", function()
      post_args.SAMLResponse = saml.base64_encode("xml")
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("content is not valid xml", err)
      assert.is_nil(doc)
      assert.are.same(post_args, args)
    end)

    it("errors for invalid document", function()
      post_args.SAMLResponse = saml.base64_encode("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"></samlp:Response>")
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("document does not validate against schema", err)
      assert.is_not_nil(doc)
      assert.are.equal("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6", saml.doc_id(doc))
      assert.are.same(post_args, args)
    end)

    it("errors when no cert is found", function()
      local doc, args, err = binding.parse_post("SAMLResponse", cb_error)
      assert.are.equal("no cert", err)
      assert.is_not_nil(doc)
      assert.are.equal("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6", saml.doc_id(doc))
      assert.are.same(post_args, args)
    end)

    it("returns the parsed document", function()
      local doc, args, err = binding.parse_post("SAMLResponse", cb)
      assert.is_nil(err)
      assert.is_not_nil(doc)
      assert.are.equal("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6", saml.doc_id(doc))
      assert.are.same(post_args, args)
    end)
  end)

end)
