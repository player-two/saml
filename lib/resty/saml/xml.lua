--[[---
Functions for working with XML documents
]]

local ffi = require "ffi"
local xml = require "resty.saml.internal.xml"

local _M = {}

local _DATA_DIR = "/data/"

local xml_generic_no_error = ffi.cast("xmlGenericErrorFunc", function(ctx, msg, ...) end)
local xml_structured_no_error = ffi.cast("xmlStructuredErrorFunc", function(ctx, err) end)


--[[---
Initialize the libxml2 parser
@tparam[opt={}] table options
@usage local err = sig.init({ debug = true })
]]
function _M.init(options)
  options = options or {
    debug = false,
  }

  xml.xmlInitParser()

  if not options.debug then
    -- silences stderr
    xml.xmlSetGenericErrorFunc(nil, xml_generic_no_error)
    xml.xmlSetStructuredErrorFunc(nil, xml_structured_no_error)
  end
end

--[[---
Cleanup memory allocated by the libxml2 parser
]]
function _M.cleanup()
  xmlCleanupParser()
end


--[[---
Parse xml text into a libxml2 document
@tparam string str
@treturn ?xmlDocPtr doc
]]
function _M.parse(str)
  return xml.xmlReadMemory(str, #str, "tmp.xml", nil, 0);
end

--[[---
Read a file with xml text and parse its contents into a libxml2 document
@tparam string name
@treturn ?xmlDocPtr doc
]]
function _M.parse_file(name)
  return xml.xmlParseFile(name)
end

--[[---
Convert a libxml2 document into a string
@tparam ?xmlDocPtr doc
@treturn string name
]]
function _M.serialize(doc)
  local buf = ffi.new("xmlChar*[1]")
  local buf_len = ffi.new("int[1]")
  xml.xmlDocDumpMemory(doc, buf, buf_len)
  return ffi.string(buf[0], buf_len[0])
end

--[[---
Free the memory of a libxml2 document
The return value of `parse` and `parse_file` should be freed
@tparam ?xmlDocPtr doc
@treturn nil
]]
function _M.free(doc)
  xml.xmlFreeDoc(doc)
end

--[[---
Determine if the libxml2 document is valid according to the SAML XSD
@tparam ?xmlDocPtr doc
@treturn ?string error
]]
function _M.validate_doc(doc)
  local parser_ctx = xml.xmlSchemaNewParserCtxt(_DATA_DIR .. "xsd/saml-schema-protocol-2.0.xsd")
  if parser_ctx == nil then
    return "could not create XSD schema parsing context"
  end

  local schema = xml.xmlSchemaParse(parser_ctx)
  if schema == nil then
    return "could not parse XSD schema"
  end

  local valid_ctx = xml.xmlSchemaNewValidCtxt(schema)
  if valid_ctx == nil then
    return "could not create XSD schema validation context"
  end

  local result = xml.xmlSchemaValidateDoc(valid_ctx, doc)
  if result ~= 0 then
    return "document does not validate against XSD schema"
  end
  return nil
end

--[[---
Get the map of attributes in the document's assertion
@tparam ?xmlDocPtr doc
@treturn ?table attributes
@treturn ?string error
]]
function _M.attrs(doc)
  local ctx = xml.xmlXPathNewContext(doc);
  if ctx == nil then
    return nil, "unable to create xpath context"
  end

  if xml.xmlXPathRegisterNs(ctx, "saml", "urn:oasis:names:tc:SAML:2.0:assertion") ~= 0 then
    xml.xmlXPathFreeContext(ctx)
    return nil, "error registering saml assertion namespace"
  end

  local obj = xml.xmlXPathEvalExpression("saml:Assertion/saml:AttributeStatement/saml:Attribute", ctx)
  if obj == nil then
    xml.xmlXPathFreeContext(ctx)
    return nil, "unable to evaluate xpath expression for assertion attributes"
  end

  local attrs = {}
  local node_set = obj[0].nodesetval
  local n = node_set[0].nodeNr
  for i=0,n do
    local node = node_set[0].nodeTab[i][0]
    if node.type ~= XML_ELEMENT_NODE then
      xml.xmlXPathFreeContext(ctx)
      return nil, "invalid attribute node"
    end
    attrs[node.name] = node.content
  end

  xml.xmlXPathFreeContext(ctx)
  return attrs, nil
end

--[[---
Get the text of the issuer node
@tparam ?xmlDocPtr doc
@treturn ?string issuer
]]
function _M.issuer(doc)
  local child = xml.xmlDocGetRootElement(doc)[0].children
  while child ~= nil do
    if xml.xmlStrEqual(child[0].name, "Issuer") == 1 then
      local content_ptr = xml.xmlNodeListGetString(doc, child[0].children, 1)
      if content_ptr == nil then
        return nil
      else
        -- xmlFree(content_ptr)
        return ffi.string(content_ptr)
      end
    end
    child = child[0].next
  end
  return nil
end

return _M
