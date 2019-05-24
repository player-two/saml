--[[
The preprocessor outputs comments with the header filename before the actual symbol definitions.
This information can be used to filter the output for just the relevant headers.
--]]

local line = io.read("*line")
local header = nil
while line ~= nil do
  if line ~= "" then
    if line:sub(1, 1) == "#" then
      if line:find("xmlsec") and not line:find("openssl") then
        print("//" .. line:sub(2))
        header = line
      else
        header = nil
      end
    else
      local no_exports = line:gsub("XMLSEC_EXPORT ", "")
      if header then print(no_exports) end
    end
  end

  line = io.read("*line")
end
