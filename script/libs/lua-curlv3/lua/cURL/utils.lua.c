static const char* curlutils_str =
"--\n"
"--  Author: Alexey Melnichuk <alexeymelnichuck@gmail.com>\n"
"--\n"
"--  Copyright (C) 2014-2016 Alexey Melnichuk <alexeymelnichuck@gmail.com>\n"
"--\n"
"--  Licensed according to the included 'LICENSE' document\n"
"--\n"
"--  This file is part of Lua-cURL library.\n"
"--\n"
"\n"
"--- Returns path to cURL ca bundle\n"
"--\n"
"-- @tparam[opt=\"curl-ca-bundle.crt\"] string name name of bundle\n"
"-- @treturn string path to file (CURLOPT_CAINFO)\n"
"-- @treturn string path to ssl dir path (CURLOPT_CAPATH)\n"
"--\n"
"-- @usage \n"
"--  local file, path = find_ca_bundle()\n"
"--  if file then e:setopt_cainfo(file) end\n"
"--  if path then e:setopt_capath(path) end\n"
"--\n"
"local function find_ca_bundle(name)\n"
"  name = name or \"curl-ca-bundle.crt\"\n"
"\n"
"  local path  = require \"path\"\n"
"  local env   = setmetatable({},{__index = function(_, name) return os.getenv(name) end})\n"
"\n"
"  local function split(str, sep, plain)\n"
"    local b, res = 1, {}\n"
"    while b <= #str do\n"
"      local e, e2 = string.find(str, sep, b, plain)\n"
"      if e then\n"
"        table.insert(res, (string.sub(str, b, e-1)))\n"
"        b = e2 + 1\n"
"      else\n"
"        table.insert(res, (string.sub(str, b)))\n"
"        break\n"
"      end\n"
"    end\n"
"    return res\n"
"  end\n"
"\n"
"  if env.CURL_CA_BUNDLE and path.isfile(env.CURL_CA_BUNDLE) then\n"
"    return env.CURL_CA_BUNDLE\n"
"  end\n"
"\n"
"  if env.SSL_CERT_DIR and path.isdir(env.SSL_CERT_DIR) then\n"
"    return nil, env.SSL_CERT_DIR\n"
"  end\n"
"\n"
"  if env.SSL_CERT_FILE and path.isfile(env.SSL_CERT_FILE) then\n"
"    return env.SSL_CERT_FILE\n"
"  end\n"
"\n"
"  if not path.IS_WINDOWS then return end\n"
"\n"
"  local paths = {\n"
"    '.',\n"
"    path.join(env.windir, \"System32\"),\n"
"    path.join(env.windir, \"SysWOW64\"),\n"
"    env.windir,\n"
"  }\n"
"  for _, p in ipairs(split(env.path, ';')) do paths[#paths + 1] = p end\n"
"\n"
"  for _, p in ipairs(paths) do\n"
"    p = path.fullpath(p)\n"
"    if path.isdir(p) then\n"
"      p = path.join(p, name)\n"
"      if path.isfile(p) then\n"
"        return p\n"
"      end\n"
"    end\n"
"  end\n"
"end\n"
"\n"
"return {\n"
"  find_ca_bundle = find_ca_bundle;\n"
"}\n"
"\n"
;
