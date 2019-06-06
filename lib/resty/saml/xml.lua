--[[---
Functions for working with XML documents
]]

local ffi       = require "ffi"
local constants = require "resty.saml.constants"
local xml       = require "resty.saml.internal.xml"

local _M = {}

local _DATA_DIR
local _XSD_MAIN = "xsd/saml-schema-protocol-2.0.xsd"

local _XPATH_ATTRIBUTES
local _XPATH_SESSION_INDEX

local xml_generic_no_error = ffi.cast("xmlGenericErrorFunc", function(ctx, msg, ...) end)
local xml_structured_no_error = ffi.cast("xmlStructuredErrorFunc", function(ctx, err) end)


--[[---
Initialize the libxml2 parser
@tparam[opt={}] table options
@usage local err = sig.init({ debug = true })
]]
function _M.init(options)
  options = options or {}
  if options.debug == nil then
    options.debug = false
  end
  _DATA_DIR = assert(options.rock_dir, "xml.init() options must include rock_dir") .. "data/"

  xml.xmlInitParser()

  if not options.debug then
    -- silences stderr
    xml.xmlSetGenericErrorFunc(nil, xml_generic_no_error)
    xml.xmlSetStructuredErrorFunc(nil, xml_structured_no_error)
  end

  _XPATH_ATTRIBUTES = xml.xmlXPathCompile("//samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute")
  _XPATH_SESSION_INDEX = xml.xmlXPathCompile("//samlp:Response/saml:Assertion/saml:AuthnStatement/@SessionIndex")
end

--[[---
Cleanup memory allocated by the libxml2 parser
]]
function _M.cleanup()
  xml.xmlXPathFreeCompExpr(_XPATH_ATTRIBUTES)
  xml.xmlXPathFreeCompExpr(_XPATH_SESSION_INDEX)
  xml.xmlCleanupParser()
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
@tparam xmlDocPtr doc
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
@tparam xmlDocPtr doc
]]
function _M.free_doc(doc)
  xml.xmlFreeDoc(doc)
end

--[[---
Determine if the libxml2 document is valid according to the SAML XSD
@tparam xmlDocPtr doc
@treturn ?string error
]]
function _M.validate_doc(doc)
  local parser_ctx = xml.xmlSchemaNewParserCtxt(_DATA_DIR .. _XSD_MAIN)
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

local function eval_xpath(doc, compiled_xpath)
  local ctx = xml.xmlXPathNewContext(doc);
  if ctx == nil then
    return nil, "unable to create xpath context"
  end

  if xml.xmlXPathRegisterNs(ctx, "saml", constants.XMLNS.ASSERTION) ~= 0 then
    xml.xmlXPathFreeContext(ctx)
    return nil, "error registering saml assertion namespace"
  end

  if xml.xmlXPathRegisterNs(ctx, "samlp", constants.XMLNS.PROTOCOL) ~= 0 then
    xml.xmlXPathFreeContext(ctx)
    return nil, "error registering saml protocol namespace"
  end

  local obj = xml.xmlXPathCompiledEval(compiled_xpath, ctx)
  xml.xmlXPathFreeContext(ctx)
  if obj == nil then
    return nil, "unable to evaluate xpath expression"
  end

  return obj, nil
end

--[[---
Get the value of the AuthnStatement[SessionIndex] attribute in the document
@tparam xmlDocPtr doc
@treturn ?string session_index
]]
function _M.session_index(doc)
  local obj = assert(eval_xpath(doc, _XPATH_SESSION_INDEX))

  local node_set = obj[0].nodesetval
  -- derived from xmlXPathNodeSetIsEmpty macro
  if node_set == nil or node_set[0].nodeNr == 0 or node_set[0].nodeTab == nil then
    xml.xmlXPathFreeObject(obj)
    return nil
  end

  local node = node_set[0].nodeTab[0][0]
  if node.type ~= xml.XML_ATTRIBUTE_NODE then
    xml.xmlXPathFreeObject(obj)
    return nil
  end

  local content_ptr = xml.xmlNodeListGetString(doc, node.children, 1)
  if content_ptr == nil then
    xml.xmlXPathFreeObject(obj)
    return nil
  end

  local content = ffi.string(content_ptr)
  xml.xmlFree(content_ptr)
  xml.xmlXPathFreeObject(obj)
  return content, nil
end

--[[---
Get the map of attributes in the document's assertion
@tparam xmlDocPtr doc
@treturn table attributes
]]
function _M.attrs(doc)
  local obj = assert(eval_xpath(doc, _XPATH_ATTRIBUTES))

  local attrs = {}
  local node_set = obj[0].nodesetval
  -- derived from xmlXPathNodeSetIsEmpty macro
  if node_set == nil or node_set[0].nodeNr == 0 or node_set[0].nodeTab == nil then
    xml.xmlXPathFreeObject(obj)
    return attrs
  end

  local n = node_set[0].nodeNr
  for i=0,n-1 do
    local node = node_set[0].nodeTab[i][0]
    local name_ptr = xml.xmlGetProp(node, "Name")
    if name_ptr ~= nil then
      local child = node.children
      local content = {}
      while child ~= nil do
        if child.type == xml.XML_ELEMENT_NODE then
          local content_ptr = xml.xmlNodeListGetString(doc, child.children, 1)
          if content_ptr ~= nil then
            table.insert(content, ffi.string(content_ptr))
          end
          xml.xmlFree(content_ptr)
        end
        child = child.next
      end

      if #content == 1 then
        attrs[ffi.string(name_ptr)] = content[1]
      elseif #content ~= 0 then
        attrs[ffi.string(name_ptr)] = content
      end
      xml.xmlFree(name_ptr)
    end
  end

  xml.xmlXPathFreeObject(obj)
  return attrs
end

--[[---
Get the text of the issuer node
@tparam xmlDocPtr doc
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
        local content = ffi.string(content_ptr)
        xml.xmlFree(content_ptr)
        return content
      end
    end
    child = child[0].next
  end
  return nil
end

return _M
