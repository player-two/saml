describe("xml", function()
  local saml
  local response

  setup(function()
    saml = require "saml"
    local err = saml.init({ data_dir=assert(os.getenv("DATA_DIR")) })
    if err then print(err) assert(nil) end

    response = assert(saml.doc_read_file("data/response.xml"))
  end)

  teardown(function()
    saml.doc_free(response)
  end)

  describe(".doc_session_index()", function()
    local no_index

    setup(function()
      no_index = saml.doc_read_memory([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z">
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>]])
    end)

    teardown(function()
      saml.doc_free(no_index)
    end)

    it("returns nil if the attribute is not found", function()
      local index = saml.doc_session_index(no_index)
      assert.is_nil(index)
    end)

    it("returns the value of the attribute if present", function()
      local index = saml.doc_session_index(response)
      assert.are.equal("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93", index)
    end)
  end)

  describe(".doc_attrs()", function()
    local no_attrs

    setup(function()
      no_attrs = saml.doc_read_memory([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
    </saml:AttributeStatement>
  <saml:Assertion>
  </saml:Assertion>
</samlp:Response>]])
    end)

    teardown(function()
      saml.doc_free(no_attrs)
    end)

    it("returns an empty table if there are no attributes", function()
      local attrs = saml.doc_attrs(no_attrs)
      assert.are.same({}, attrs)
    end)

    it("returns the value of the attribute if present", function()
      local attrs = saml.doc_attrs(response)
      assert.are.same({
        uid = "test",
        mail = "test@example.com",
        eduPersonAffiliation = { "users", "examplerole1" }
      }, attrs)
    end)
  end)

  describe(".doc_issuer()", function()
    local no_issuer

    setup(function()
      no_issuer = saml.doc_read_memory([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>]])
    end)

    teardown(function()
      saml.doc_free(no_issuer)
    end)

    it("returns nil if the element is not found", function()
      local issuer = saml.doc_issuer(no_issuer)
      assert.is_nil(issuer)
    end)

    it("returns the value of the element if present", function()
      local issuer = saml.doc_issuer(response)
      assert.are.equal("http://idp.example.com/metadata.php", issuer)
    end)
  end)

end)
