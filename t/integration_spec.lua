local https = require "ssl.https"
local url   = require "socket.url"
local utils = require "utils"

describe("saml integration", function()
  local constants
  local key_text, cert_text, response

  setup(function()
    constants = require "resty.saml.constants"
    saml      = require "saml"

    local err = saml.init({ rock_dir=assert(os.getenv("ROCK_DIR")) })
    if err then print(err) assert(nil) end

    key_text = assert(utils.readfile("/t/data/idp.key"))
    cert_text = assert(utils.readfile("/t/data/idp.crt"))
    response = assert(utils.readfile("/t/data/response.xml"))
  end)

  describe("can verify a document signed", function()
    local doc, mngr

    setup(function()
      local cert = saml.load_cert(cert_text)
      mngr = saml.create_keys_manager({ cert })
    end)

    after_each(function()
      if doc ~= nil then
        saml.free_doc(doc)
      end
    end)

    it("via #samltool", function()
      local body, code, headers, status = https.request("https://www.samltool.com/sign_response.php", table.concat({
        "xml=" .. url.escape(response),
        "mode=1",
        "private_key=" .. url.escape(key_text),
        "x509cert=" .. url.escape(cert_text),
        "act_sign=Sign+XML",
      }, "&"))
      assert(body, code)
      assert.are.equal(code, 200)
      local result = body:match('id="xml_signed"[^>]*>(.+)</textarea>')
      assert.is_not_nil(result)

      doc = assert(saml.parse(utils.html_entity_decode(result)))
      local valid, err = saml.verify_doc(mngr, doc, { id_attr = "ID" })
      assert.is_nil(err)
      assert.is_true(valid)
    end)

    it("via xmlsec1", function()
      local name = os.tmpname()
      local success, result_type, result_code = os.execute("xmlsec1 --sign --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --enabled-reference-uris same-doc --privkey-pem /t/data/idp.key,/t/data/idp.crt --output " .. name .. " /t/data/response-template.xml")
      assert.is_true(success)
      assert.are.equal(result_type, "exit")
      assert.are.equal(result_code, 0)

      doc = assert(saml.parse(assert(utils.readfile(name))))
      local valid, err = saml.verify_doc(mngr, doc, { id_attr = "ID" })
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)

  describe("can sign a document that is verified", function()
    local key, cert, signed

    setup(function()
      key = assert(saml.load_key(key_text))
      local transform_id = assert(saml.find_transform_by_href(constants.SIGNATURE_ALGORITHMS.RSA_SHA512))
      signed = assert(saml.sign_xml(key, transform_id, response, {
        id_attr = "ID",
        insert_after = { constants.XMLNS.ASSERTION, "Issuer", },
      }))
    end)

    it("via #samltool", function()
      local body, code, headers, status = https.request("https://www.samltool.com/validate_response.php", table.concat({
        "xml=" .. url.escape((mime.b64(signed))),
        "idp_entityid=http://idp.example.com/metadata.php",
        "sp_entityid=http://sp.example.com/demo1/metadata.php",
        "acs_url=http://sp.example.com/demo1/index.php?acs",
        "target=http://sp.example.com/demo1/index.php?acs",
        "request_id=",
        "private_key=",
        "act_validate_response=Validate+SAML+Response",
        "x509cert=" .. url.escape(cert_text),
        "ignore_timing=on",
      }, "&"))
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
      local success, result_type, result_code = os.execute("xmlsec1 --verify --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --enabled-reference-uris same-doc --pubkey-cert-pem /t/data/idp.crt " .. name .. " 2>/dev/null")
      assert.are.equal("exit", result_type)
      assert.are.equal(0, result_code)
      assert.is_true(success)
    end)

  end)

end)
