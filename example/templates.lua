local _M = {}

local function interp(s, tab)
  return s:gsub('($%b{})', function(w)
    local key = w:sub(3, -2)
    if not key:find(".", 2, true) then
      return tab[key] or ""
    else
      local t = tab
      for k in key:gmatch("%a+") do
        t = t[k]
        if not t then return "" end
      end
      return t
    end
  end)
end

local _AUTHN_REQUEST = [[
<?xml version="1.0" ?>
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="${uuid}" IssueInstant="${datetime}" Destination="${destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="${acs_url}" ProviderName="${name}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
</samlp:AuthnRequest>
]]

function _M.authn_request(params)
  return interp(_AUTHN_REQUEST, params)
end


local _RESPONSE = [[
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="${destination}" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>
]]

function _M.response(params)
  return interp(_RESPONSE, params)
end

local _METADATA = [[
<?xml version="1.0" ?>
<saml:EntityDescriptor entityID="${entity_id}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
  <saml:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:KeyDescriptor use="signing">
      <dsig:KeyInfo>
        <dsig:X509Data>
          <dsig:X509Certificate>${cert}</dsig:X509Certificate>
        </dsig:X509Data>
      </dsig:KeyInfo>
    </saml:KeyDescriptor>
    <saml:SingleSignOnService Binding="${sso.binding}" Location="${entity_id}${sso.location}"/>
    <saml:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${entity_id}${acs.location}"/>
    <saml:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${entity_id}${sls.location}"/>
  </saml:SPSSODescriptor>
</saml:EntityDescriptor>
]]

function _M.metadata(metadata)
  return interp(_METADATA, metadata)
end

return _M
