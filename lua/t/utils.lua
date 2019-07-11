local _M = {
  xmlSecHrefRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  xmlSecHrefRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}

function _M.readfile(path)
  local file = io.open(path, "rb")
  if not file then return nil end
  local content = file:read("*a")
  file:close()
  return content
end

function _M.write_tmpfile(data)
  local name = os.tmpname()
  local f = assert(io.open(name, "w+"))
  assert(f:write(data))
  f:close()
  return name
end

local html_entities = {
  lt = "<",
  gt = ">",
  quot = '"',
}

function _M.html_entity_decode(html)
  return html:gsub("&(%w-);", function(code)
    return assert(html_entities[code])
  end)
end

return _M
