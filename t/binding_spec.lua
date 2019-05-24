local mime  = require "mime"
local utils = require "utils"

describe("binding", function()
  local binding, constants, xml

  local redirect_signature = ""

  setup(function()
    sig = {
      create_keys_manager = stub(),
      sign_binary         = stub(),
      verify_binary       = stub(),
      sign_xml            = stub(),
      verify_doc          = stub(),
    }
    package.loaded["resty.saml.sig"] = sig
    xml = {
      parse         = stub(),
      validate_doc  = stub(),
    }
    package.loaded["resty.saml.xml"] = xml

    binding   = require "resty.saml.binding"
    constants = require "resty.saml.constants"

    _G.ngx = {
      encode_base64 = function(x) return mime.b64(x) end,
      decode_base64 = function(x) return mime.unb64(x) end,
      escape_uri = function(x) return x end,
    }
  end)

  teardown(function()
    package.loaded["resty.saml.sig"] = nil
    _G.ngx = nil
  end)

  before_each(function()
    for _, m in pairs(sig) do
      m:clear()
    end
    for _, m in pairs(xml) do
      m:clear()
    end
  end)


  describe(".create_redirect()", function()

    it("constructs the query string for the signature", function()
      sig.sign_binary.returns(nil, "signature failed")
      binding.create_redirect("key", "alg", "xml", "relay_state")
      assert.spy(sig.sign_binary).was.called_with("key", "alg", match._)
      local args = sig.sign_binary.calls[1].vals
      assert.are.equal("SAMLRequest=eJxLdTcsBgADQgFR&RelayState=relay_state&SigAlg=alg", args[3])
    end)

    it("errors for signature failure", function()
      sig.sign_binary.returns(nil, "signature failed")
      local query_string, err = binding.create_redirect("key", "alg", "xml", "relay_state")
      assert.are.equal("signature failed", err)
      assert.is_nil(query_string)
    end)

    it("creates a full query string", function()
      sig.sign_binary.returns("signature", nil)
      local query_string, err = binding.create_redirect("key", "alg", "xml", "relay_state")
      assert.is_nil(err)
      assert.are.equal("SAMLRequest=eJxLdTcsBgADQgFR&RelayState=relay_state&SigAlg=alg&Signature=c2lnbmF0dXJl", query_string)
    end)

  end)


  describe(".parse_redirect()", function()
    local cb = function(doc) return "-----BEGIN CERTIFICATE-----" end
    local cb_error = function(doc) return nil end
    local parsed = "parsed document"

    before_each(function()
      sig.verify_binary.returns(true, nil)
      xml.parse.returns(parsed)
      xml.validate_doc.returns(nil)
    end)

    it("errors for invalid xml", function()
      xml.parse.returns(nil)
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb_error)
      assert.are.equal("unable to read xml", err)
      assert.is_nil(doc)
    end)

    it("errors for invalid document", function()
      xml.validate_doc.returns("invalid")
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb_error)
      assert.are.equal("invalid", err)
      assert.are.equal(parsed, doc)
    end)

    it("errors when no cert is found", function()
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb_error)
      assert.are.equal("no cert", err)
      assert.are.equal(parsed, doc)
    end)

    it("passes args to verify function", function()
      binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb)
      assert.spy(sig.verify_binary).was.called(1)
      local args = sig.verify_binary.calls[1].vals
      assert.are.equal(args[1], "-----BEGIN CERTIFICATE-----")
      assert.are.equal(args[2], "alg")
      assert.are.equal(args[3], "SAMLRequest=eJxLdTcsBgADQgFR&RelayState=relay_state&SigAlg=alg")
      assert.are.equal(args[4], "signature")
    end)

    it("errors for verify failure", function()
      sig.verify_binary.returns(false, "verify failed")
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb)
      assert.are.equal(err, "verify failed")
      assert.are.equal(parsed, doc)
    end)

    it("errors for invalid signature", function()
      sig.verify_binary.returns(false, nil)
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb)
      assert.are.equal(err, "invalid signature")
      assert.are.equal(parsed, doc)
    end)

    it("returns the parsed document", function()
      sig.verify_binary.returns(true, nil)
      local doc, err = binding.parse_redirect("alg", "eJxLdTcsBgADQgFR", "relay_state", "c2lnbmF0dXJl", cb)
      assert.is_nil(err)
      assert.are.equal(parsed, doc)
    end)

  end)

  describe(".create_post()", function()

    before_each(function()
      sig.sign_xml.returns("signed request", nil)
    end)

    it("signs a request", function()
      binding.create_post("key", "alg", "dest", { SAMLRequest = "request" })
      assert.spy(sig.sign_xml).was.called_with("key", "alg", "request")
    end)

    it("signs a response", function()
      binding.create_post("key", "alg", "dest", { SAMLResponse = "response" })
      assert.spy(sig.sign_xml).was.called_with("key", "alg", "response")
    end)

    it("aborts without a request or response", function()
      assert.has_error(function()
        binding.create_post("key", "alg", "dest", {})
      end, "no saml request or response")
    end)

    it("errors for signature failure", function()
      sig.sign_xml.returns(nil, "signature failed")
      local html, err = binding.create_post("key", "alg", "dest", { SAMLRequest = "request" })
      assert.are.equal("signature failed", err)
      assert.is_nil(html)
    end)

    it("passes the destination", function()
      local html, err = binding.create_post("key", "alg", "dest", { SAMLRequest = "request" })
      assert.is_nil(err)
      local action = html:match('action="(%w+)"')
      assert.are.equal("dest", action)
    end)

    it("passes a copy of the params", function()
      local params = { SAMLRequest = "request", RelayState = "relay" }
      local html, err = binding.create_post("key", "alg", "dest", params)
      assert.is_nil(err)
      assert.are.same({
        SAMLRequest = "request",
        RelayState = "relay",
      }, params)
    end)

    it("returns the form template", function()
      local html, err = binding.create_post("key", "alg", "dest", { SAMLRequest = "request" })
      assert.is_nil(err)
      assert.is_not_nil(html:find("<html>"))

      local name, value = html:match('name="([^"]+)" value="([^"]+)"')
      assert.are.equal("SAMLRequest", name)
      assert.are.equal("c2lnbmVkIHJlcXVlc3Q=", value)
    end)

  end)


  describe(".parse_post()", function()
    local cb = function(doc) return "-----BEGIN CERTIFICATE-----" end
    local cb_error = function(doc) return nil end
    local input_doc = "<Response>"
    local parsed = "parsed document"
    local mngr = { cert = "" }

    before_each(function()
      sig.create_keys_manager.returns(mngr)
      sig.verify_doc.returns(true, nil)
      xml.parse.returns(parsed)
      xml.validate_doc.returns(nil)
    end)

    it("errors for invalid xml", function()
      xml.parse.returns(nil)
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb_error)
      assert.spy(xml.parse).was.called_with("<Response>")
      assert.are.equal("unable to read xml", err)
      assert.is_nil(doc)
    end)

    it("errors for invalid document", function()
      xml.validate_doc.returns("invalid")
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb_error)
      assert.are.equal("invalid", err)
      assert.are.equal(parsed, doc)
    end)

    it("errors when no cert is found", function()
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb_error)
      assert.are.equal("no cert", err)
      assert.are.equal(parsed, doc)
    end)

    it("passes args to verify function", function()
      binding.parse_post("PFJlc3BvbnNlPg==", cb)
      assert.spy(sig.verify_doc).was.called(1)
      local args = sig.verify_doc.calls[1].vals
      assert.are.same(mngr, args[1])
      assert.are.equal(parsed, args[2])
    end)

    it("errors for verify failure", function()
      sig.verify_doc.returns(false, "verify failed")
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb)
      assert.are.equal(err, "verify failed")
      assert.are.equal(parsed, doc)
    end)

    it("errors for invalid signature", function()
      sig.verify_doc.returns(false, nil)
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb)
      assert.are.equal(err, "invalid signature")
      assert.are.equal(parsed, doc)
    end)

    it("returns the parsed document", function()
      sig.verify_doc.returns(true, nil)
      local doc, err = binding.parse_post("PFJlc3BvbnNlPg==", cb)
      assert.is_nil(err)
      assert.are.equal(parsed, doc)
    end)
  end)

end)
