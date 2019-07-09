local _M = {}

function _M.interp(s, tab)
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

return _M
