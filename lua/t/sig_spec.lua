local utils = require "utils"

local TEST_DATA_DIR = os.getenv("TEST_DATA_DIR")

describe("sig", function()
  local saml
  local key, cert, transform_sha256, transform_sha512

  local binary_data = "agBv0s1vhMpOxGbsoj1lMPCoYyUOAivpBxZlTyozJcgSmLwCWp1uijM2UTHo"
  local binary_signature_rsa_sha256 = "OEBg0Lv7V2aueh5HjiSQJh2Fw5lOm+HPocomlGepvcYAHDcSNXrFmCixOUqmCh9c5Pti3tQ0lOm5qCZ/aMJr7YkTiMYaNE7C3fjYYyDBCj0zoKZIo7UQ966DFe6ezZtBlVUtiuhTcNmeQ67Bk2BE5TRwzKWu0Ahy2LICzQC99gOtzfGgU+pWi+l4IcIrGq3v+aUGcVigWPKh3TVcVyhYr/V5qt+zoSxH6LDvE2Z49UKsuaOSQFhHnKb91SZOncWGh7K01JumAoq4ADyjTfDFExTXE0HVecgwbEI7xlnyVgI/I4OfqPHHDdLk3TuaWpfoq1rLFCJQwMjE+jlm1++kZA=="
  local binary_signature_rsa_sha512 = "OajQbB55E5B/heKbhcUaBvKiArrmYdfs4nJLU39rSk/3e5yvy9F9osnWAeJUu9xnThDnmBrvWSFeDnQIe2Y/hhypEHesdMsPG6R+RkFbQxv4icU+oEDh8wFetDEByuyueox/zqA+z6X9knt8+ufs6Mdfw0UIcxbg9rgNaB75JleI/ye9f97sAXc8K5lmZ6IHst200TX6Bw5Onpf2OLKOmsMdekLLdTmUew4ynNmeMlOdE20EUJvsH3y7WRBbW3JI8ffLBT4NHNyOfvt0CCOmynpmbEjfGg7jsq6J3bl4rZVrlDovMhuP3iyxjiwtj5gq44g++FYtYw8aQGXfBb28wA=="

  setup(function()
    saml = require "saml"

    local err = saml.init({ data_dir=assert(os.getenv("DATA_DIR")) })
    if err then print(err) assert(nil) end

    key = assert(saml.key_read_file(TEST_DATA_DIR .. "sp.key", saml.KeyDataFormatPem))
    assert(saml.key_add_cert_file(key, TEST_DATA_DIR .. "sp.crt", saml.KeyDataFormatCertPem))
    cert = assert(saml.key_read_file(TEST_DATA_DIR .. "sp.crt", saml.KeyDataFormatCertPem))

    transform_sha256 = assert(saml.find_transform_by_href(utils.xmlSecHrefRsaSha256))
    transform_sha512 = assert(saml.find_transform_by_href(utils.xmlSecHrefRsaSha512))
  end)


  describe(".sign_binary()", function()

    it("generates correct bytes using rsa-sha256", function()
      local result, err = saml.sign_binary(key, transform_sha256, binary_data)
      assert.is_nil(err)
      assert.are.equal(saml.base64_encode(result), binary_signature_rsa_sha256)
    end)

    it("generates correct bytes using rsa-sha512", function()
      local result, err = saml.sign_binary(key, transform_sha512, binary_data)
      assert.is_nil(err)
      assert.are.equal(saml.base64_encode(result), binary_signature_rsa_sha512)
    end)

  end)


  describe(".sign_xml()", function()
    local input

    setup(function()
      input = assert(utils.readfile(TEST_DATA_DIR .. "simple-input.xml"))
    end)

    it("errors for invalid document", function()
      local result, err = saml.sign_xml(key, transform_sha256, "plaintext")
      assert.are.equal(err, "unable to parse xml string")
      assert.is_nil(result)
    end)

    it("errors for empty document", function()
      local result, err = saml.sign_xml(key, transform_sha256, '<?xml version="1.0" encoding="UTF-8"?>')
      assert.are.equal(err, "unable to parse xml string")
      assert.is_nil(result)
    end)

    it("errors for document with no id_attr", function()
      local result, err = saml.sign_xml(key, transform_sha256, '<?xml version="1.0" encoding="UTF-8"?><Envelope xmlns="urn:envelope"></Envelope>', { id_attr = "ID" })
      assert.are.equal(err, "saml sign failed")
      assert.is_nil(result)
    end)

    it("generates correct document using rsa-sha256", function()
      local expected = assert(utils.readfile(TEST_DATA_DIR .. "simple-signed-rsa-sha256.xml"))
      local result, err = saml.sign_xml(key, transform_sha256, input)
      assert.is_nil(err)
      assert.are.equal(expected, result)
    end)

  end)


  describe(".verify_binary()", function()

    it("rejects incorrectly signed content", function()
      local valid, err = saml.verify_binary(cert, transform_sha256, binary_data, "bogus signature")
      assert.is_nil(err)
      assert.is_false(valid)
    end)

    it("verifies correctly signed content using rsa-sha256", function()
      local valid, err = saml.verify_binary(cert, transform_sha256, binary_data, saml.base64_decode(binary_signature_rsa_sha256))
      assert.is_nil(err)
      assert.is_true(valid)
    end)

    it("verifies correctly signed content using rsa-sha512", function()
      local valid, err = saml.verify_binary(cert, transform_sha512, binary_data, saml.base64_decode(binary_signature_rsa_sha512))
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)


  describe(".verify_doc()", function()
    local mngr

    setup(function()
      local err
      mngr, err = assert(saml.create_keys_manager({ cert }))
    end)

    it("rejects an incorrectly signed document", function()
      local doc = assert(saml.doc_read_file(TEST_DATA_DIR .. "simple-bad-sig-rsa-sha256.xml"))
      local valid, err = saml.verify_doc(mngr, doc)
      assert.is_nil(err)
      assert.is_false(valid)
    end)

    it("verifies a correctly signed document", function()
      local doc = assert(saml.doc_read_file(TEST_DATA_DIR .. "simple-signed-rsa-sha256.xml"))
      local valid, err = saml.verify_doc(mngr, doc)
      assert.is_nil(err)
      assert.is_true(valid)
    end)

  end)

end)
