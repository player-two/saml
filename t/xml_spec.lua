describe("xml", function()
  local xml
  local response

  setup(function()
    xml = require "resty.saml.xml"
    xml.init({ rock_dir = "/" })

    response = assert(xml.parse_file("/t/data/response.xml"))
  end)

  teardown(function()
    xml.free_doc(response)
  end)

  describe(".session_index()", function()
    local no_index

    setup(function()
      no_index = xml.parse([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z">
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>]])
    end)

    teardown(function()
      xml.free_doc(no_index)
    end)

    it("returns nil if the attribute is not found", function()
      local index = xml.session_index(no_index)
      assert.is_nil(index)
    end)

    it("returns the value of the attribute if present", function()
      local index = xml.session_index(response)
      assert.are.equal("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93", index)
    end)
  end)

  describe(".attrs()", function()
    local no_attrs

    setup(function()
      no_attrs = xml.parse([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
    </saml:AttributeStatement>
  <saml:Assertion>
  </saml:Assertion>
</samlp:Response>]])
    end)

    teardown(function()
      xml.free_doc(no_attrs)
    end)

    it("returns an empty table if there are no attributes", function()
      local attrs = xml.attrs(no_attrs)
      assert.are.same({}, attrs)
    end)

    it("returns the value of the attribute if present", function()
      local attrs = xml.attrs(response)
      assert.are.same({
        uid = "test",
        mail = "test@example.com",
        eduPersonAffiliation = { "users", "examplerole1" }
      }, attrs)
    end)
  end)

  describe(".issuer()", function()
    local no_issuer

    setup(function()
      no_issuer = xml.parse([[<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>]])
    end)

    teardown(function()
      xml.free_doc(no_issuer)
    end)

    it("returns nil if the element is not found", function()
      local issuer = xml.issuer(no_issuer)
      assert.is_nil(issuer)
    end)

    it("returns the value of the element if present", function()
      local issuer = xml.issuer(response)
      assert.are.equal("http://idp.example.com/metadata.php", issuer)
    end)
  end)

end)
