local mime  = require "mime"
local utils = require "utils"

describe("sig", function()
  local constants, sig, xml
  local key, cert

  local binary_data = "agBv0s1vhMpOxGbsoj1lMPCoYyUOAivpBxZlTyozJcgSmLwCWp1uijM2UTHo"
  local binary_signature_rsa_sha256 = "OEBg0Lv7V2aueh5HjiSQJh2Fw5lOm+HPocomlGepvcYAHDcSNXrFmCixOUqmCh9c5Pti3tQ0lOm5qCZ/aMJr7YkTiMYaNE7C3fjYYyDBCj0zoKZIo7UQ966DFe6ezZtBlVUtiuhTcNmeQ67Bk2BE5TRwzKWu0Ahy2LICzQC99gOtzfGgU+pWi+l4IcIrGq3v+aUGcVigWPKh3TVcVyhYr/V5qt+zoSxH6LDvE2Z49UKsuaOSQFhHnKb91SZOncWGh7K01JumAoq4ADyjTfDFExTXE0HVecgwbEI7xlnyVgI/I4OfqPHHDdLk3TuaWpfoq1rLFCJQwMjE+jlm1++kZA=="
  local binary_signature_rsa_sha512 = "OajQbB55E5B/heKbhcUaBvKiArrmYdfs4nJLU39rSk/3e5yvy9F9osnWAeJUu9xnThDnmBrvWSFeDnQIe2Y/hhypEHesdMsPG6R+RkFbQxv4icU+oEDh8wFetDEByuyueox/zqA+z6X9knt8+ufs6Mdfw0UIcxbg9rgNaB75JleI/ye9f97sAXc8K5lmZ6IHst200TX6Bw5Onpf2OLKOmsMdekLLdTmUew4ynNmeMlOdE20EUJvsH3y7WRBbW3JI8ffLBT4NHNyOfvt0CCOmynpmbEjfGg7jsq6J3bl4rZVrlDovMhuP3iyxjiwtj5gq44g++FYtYw8aQGXfBb28wA=="

  setup(function()
    constants = require "resty.saml.constants"
    sig       = require "resty.saml.sig"
    xml       = require "resty.saml.xml"

    xml.init({ rock_dir = "/" })
    local err = sig.init()
    if err then
      print(err)
      assert(nil)
    end

    key = assert(sig.load_key_file("/t/data/sp.key"))
    assert(sig.key_load_cert_file(key, "/t/data/sp.crt"))
    cert = assert(sig.load_cert_file("/t/data/sp.crt"))
  end)


  describe(".sign_binary()", function()

    it("errors for invalid algorithm", function()
      local result, err = sig.sign_binary(key, "sha-rsa256", binary_data)
      assert.are.equal(err, "transform not found")
      assert.is_nil(result)
    end)

    it("generates correct bytes using rsa-sha256", function()
      local result, err = sig.sign_binary(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, binary_data)
      assert.is_nil(err)
      assert.are.equal(mime.b64(result), binary_signature_rsa_sha256)
    end)

    it("generates correct bytes using rsa-sha512", function()
      local result, err = sig.sign_binary(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, binary_data)
      assert.is_nil(err)
      assert.are.equal(mime.b64(result), binary_signature_rsa_sha512)
    end)

  end)


  describe(".sign_xml()", function()
    local input

    setup(function()
      input = assert(utils.readfile("/t/data/simple-input.xml"))
    end)

    it("errors for invalid document", function()
      local result, err = sig.sign_xml(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, "plaintext")
      assert.are.equal(err, "unable to parse xml string")
      assert.is_nil(result)
    end)

    it("errors for empty document", function()
      local result, err = sig.sign_xml(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, '<?xml version="1.0" encoding="UTF-8"?>')
      assert.are.equal(err, "unable to parse xml string")
      assert.is_nil(result)
    end)

    it("errors for document with no id_attr", function()
      local result, err = sig.sign_xml(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, '<?xml version="1.0" encoding="UTF-8"?><Envelope xmlns="urn:envelope"></Envelope>', { id_attr = "ID" })
      assert.are.equal(err, "no ID property on document root")
      assert.is_nil(result)
    end)

    it("errors for invalid algorithm", function()
      local result, err = sig.sign_xml(key, "rsa-sha256", input)
      assert.are.equal(err, "transform not found")
      assert.is_nil(result)
    end)

    it("generates correct document using rsa-sha256", function()
      local expected = assert(utils.readfile("/t/data/simple-signed-rsa-sha256.xml"))
      local result, err = sig.sign_xml(key, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, input)
      assert.is_nil(err)
      assert.are.equal(expected, result)
    end)

  end)


  describe(".verify_binary()", function()

    it("errors for invalid algorithm", function()
      local valid, err = sig.verify_binary(cert, "rsa-sha256", "content")
      assert.are.equal(err, "transform not found")
      assert.is_false(valid)
    end)

    it("rejects incorrectly signed content", function()
      local valid, err = sig.verify_binary(cert, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, binary_data, "bogus signature")
      assert.is_nil(err)
      assert.is_false(valid)
    end)

    it("verifies correctly signed content using rsa-sha256", function()
      local valid, err = sig.verify_binary(cert, constants.SIGNATURE_ALGORITHMS.RSA_SHA256, binary_data, mime.unb64(binary_signature_rsa_sha256))
      assert.is_nil(err)
      assert.is_true(valid)
    end)

    it("verifies correctly signed content using rsa-sha512", function()
      local valid, err = sig.verify_binary(cert, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, binary_data, mime.unb64(binary_signature_rsa_sha512))
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)


  describe(".verify_doc()", function()
    local mngr

    setup(function()
      local err
      mngr, err = assert(sig.create_keys_manager({ cert }))
    end)

    it("rejects an incorrectly signed document", function()
      local doc = assert(xml.parse_file("/t/data/simple-bad-sig-rsa-sha256.xml"))
      local valid, err = sig.verify_doc(mngr, doc)
      assert.is_nil(err)
      assert.is_false(valid)
    end)

    it("verifies a correctly signed document", function()
      local doc = assert(xml.parse_file("/t/data/simple-signed-rsa-sha256.xml"))
      local valid, err = sig.verify_doc(mngr, doc)
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)

end)
