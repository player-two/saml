local https = require "ssl.https"
local utils = require "utils"

local function form_encode(params)
  local result = {}
  for k, v in pairs(params) do
    table.insert(result, saml.uri_encode(k) .. "=" .. saml.uri_encode(v))
  end
  return table.concat(result, "&")
end

describe("saml integration", function()
  local key_text, cert_text, response

  setup(function()
    saml = require "saml"

    local err = saml.init({ data_dir=assert(os.getenv("DATA_DIR")) })
    if err then print(err) assert(nil) end

    key_text = assert(utils.readfile("data/sp.key"))
    cert_text = assert(utils.readfile("data/sp.crt"))
    response = assert(utils.readfile("data/response.xml"))
  end)

  describe("can verify a document signed", function()
    local doc, mngr

    setup(function()
      local cert = saml.key_read_memory(cert_text, saml.KeyDataFormatCertPem)
      mngr = saml.create_keys_manager({ cert })
    end)

    after_each(function()
      if doc ~= nil then
        saml.doc_free(doc)
      end
    end)

    it("via #samltool", function()
      local body, code, headers, status = https.request("https://www.samltool.com/sign_response.php", form_encode({
        xml = response,
        mode = "1",
        private_key = key_text,
        x509cert = cert_text,
        act_sign = "Sign XML",
      }))
      assert(body, code)
      assert.are.equal(code, 200)
      local result = body:match('id="xml_signed"[^>]*>(.+)</textarea>')
      assert.is_not_nil(result)

      doc = assert(saml.doc_read_memory(utils.html_entity_decode(result)))
      local valid, err = saml.verify_doc(mngr, doc, { id_attr = "ID" })
      assert.is_nil(err)
      assert.is_true(valid)
    end)

    it("via xmlsec1", function()
      local name = os.tmpname()
      local success, result_type, result_code = os.execute("xmlsec1 --sign --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --enabled-reference-uris same-doc --privkey-pem data/sp.key,data/sp.crt --output " .. name .. " data/response-template.xml")
      assert.is_true(success)
      assert.are.equal(result_type, "exit")
      assert.are.equal(result_code, 0)

      doc = assert(saml.doc_read_memory(assert(utils.readfile(name))))
      local valid, err = saml.verify_doc(mngr, doc, { id_attr = "ID" })
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)

  describe("can sign a document that is verified", function()
    local key, cert, signed

    setup(function()
      key = assert(saml.key_read_memory(key_text, saml.KeyDataFormatPem))
      local transform_id = assert(saml.find_transform_by_href(utils.xmlSecHrefRsaSha512))
      signed = assert(saml.sign_xml(key, transform_id, response, {
        id_attr = "ID",
        insert_after = { saml.XMLNS_ASSERTION, "Issuer", },
      }))
    end)

    it("via #samltool", function()
      local body, code, headers, status = https.request("https://www.samltool.com/validate_response.php", form_encode({
        xml = saml.base64_encode(signed),
        idp_entityid = "http://idp.example.com/metadata.php",
        sp_entityid = "http://sp.example.com/demo1/metadata.php",
        acs_url = "http://sp.example.com/demo1/index.php?acs",
        target = "http://sp.example.com/demo1/index.php?acs",
        request_id = "",
        private_key = "",
        act_validate_response = "Validate+SAML+Response",
        x509cert = cert_text,
        ignore_timing = "on",
      }))
      assert(body, code)
      assert.are.equal(code, 200)

      local result = body:match('<div class="alert alert%-%w+"><h3>([^<]+)</h3>')
      if result ~= "The SAML Response is valid." then
        -- this should always fail
        assert.are.equal("", body:match('<code class="language%-php">([^<]+)</code>'))
      end
    end)

    it("via xmlsec1", function()
      local name = utils.write_tmpfile(signed)
      local success, result_type, result_code = os.execute("xmlsec1 --verify --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --enabled-reference-uris same-doc --pubkey-cert-pem data/sp.crt " .. name .. " 2>/dev/null")
      assert.are.equal("exit", result_type)
      assert.are.equal(0, result_code)
      assert.is_true(success)
    end)

  end)

  describe("can create a redirect binding that is verified", function()
    local args = {}

    setup(function()
      local key = assert(saml.key_read_memory(key_text, saml.KeyDataFormatPem))
      local authn_request = assert(utils.readfile("data/authn_request.xml"))
      local query_string = assert(saml.binding_redirect_create(key, "SAMLRequest", authn_request, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "/"))
      for k, v in query_string:gmatch("&?([^=]+)=([^&]*)") do args[k] = assert(saml.uri_decode(v)) end
    end)

    it("via #samltool", function()
      local body, code, headers, status = https.request("https://www.samltool.com/validate_authn_req.php", form_encode({
        xml = assert(args.SAMLRequest),
        entityid = "http://sp.example.com/demo1/metadata.php",
        target = "http://idp.example.com/SSOService.php",
        private_key = "",
        x509cert = cert_text,
        signature = assert(args.Signature),
        relaystate = assert(args.RelayState),
        sign_algorithm = assert(args.SigAlg),
        act_validate_authn_req = "Validate SAML AuthN Request",
        ignore_timing = "on",
      }))
      assert(body, code)
      assert.are.equal(code, 200)

      local result = body:match('<div class="alert alert%-%w+"><h3>([^<]+)</h3>')
      if result ~= "The SAML AuthN Request is valid." then
        -- this should always fail
        assert.are.equal("", body:match('<code class="language%-php">([^<]+)</code>'))
      end
    end)

  end)

end)
