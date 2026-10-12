--
--  KotSafe Wireshark Lua Dissector Plugin
--  Dissects KotSafe PCAP / PCAPng dump extensions (App Name, Package Name, UID, Interface & Direction)
--
--  Installation:
--    Copy this file to your Wireshark personal plugins directory:
--      - Linux: ~/.local/lib/wireshark/plugins/ or ~/.config/wireshark/plugins/
--      - Windows: %APPDATA%\Wireshark\plugins\
--      - macOS: ~/.config/wireshark/plugins/
--    Then press Ctrl+Shift+L in Wireshark to reload Lua plugins.
--

kotsafe_proto = Proto("KotSafe", "KotSafe Mobile Security Data")

-- Constants
local KOTSAFE_PCAP_MAGIC = 0x01072021
local KOTSAFE_TRAILER_SIZE = 32
local KOTSAFE_PEN = 62652 -- PEN registered for custom PCAPng blocks

local block_types = {
  [1] = "UID Mapping",
}

-- ProtoFields for Wireshark filtering and column creation
local f = {}
f.magic          = ProtoField.uint32("kotsafe.magic", "Magic", base.HEX)
f.block_ver      = ProtoField.int32("kotsafe.block_version", "Block version", base.DEC)
f.block_type     = ProtoField.int32("kotsafe.block_type", "Block type", base.DEC, block_types)
f.uid            = ProtoField.int32("kotsafe.uid", "UID", base.DEC)
f.appname        = ProtoField.string("kotsafe.appname", "App Name", base.UNICODE)
f.appname_len    = ProtoField.uint8("kotsafe.appname_len", "App Name Length", base.DEC)
f.packagename    = ProtoField.string("kotsafe.packagename", "Package Name", base.UNICODE)
f.packagename_len= ProtoField.uint8("kotsafe.packagename_len", "Package Name Length", base.DEC)

kotsafe_proto.fields = f

local pen_field = Field.new("frame.cb_pen")
local comment_field = Field.new("frame.comment")
local uid_map = {}

-- Dissect legacy PCAP trailer (Appended Ethernet trailer)
local function dissect_pcap_trailer(buffer, pinfo, tree)
  local length = buffer:len()
  if length < KOTSAFE_TRAILER_SIZE then
    return false
  end

  -- Skip 4-byte FCS at the end
  local trailer = buffer(length - KOTSAFE_TRAILER_SIZE, KOTSAFE_TRAILER_SIZE - 4)
  local magic = trailer(0, 4):uint()

  if magic ~= KOTSAFE_PCAP_MAGIC then
    return false
  end

  local appname = trailer(8, 20):raw()
  -- Clean trailing nulls
  local clean_appname = string.gsub(appname, "%z.*", "")
  local uid_val = trailer(4, 4):int()

  local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Metadata: App [%s], UID [%d]", clean_appname, uid_val))
  subtree:add(f.magic, trailer(0, 4))
  subtree:add(f.uid, trailer(4, 4))
  subtree:add(f.appname, clean_appname)

  pinfo.cols.info:append(string.format(" [KotSafe: %s]", clean_appname))
  return true
end

-- Dissect PCAPng Custom Blocks & Enhanced Packet Block comments
local function dissect_pcapng(buffer, pinfo, tree)
  local pen_fields = { pen_field() }

  if pen_fields[1] then
    local pen = pen_fields[1].value

    if (pen == KOTSAFE_PEN) and (buffer:len() >= 4) then
      local get_uint
      local block_ver

      if (buffer(0, 2):uint() == 1) then
        block_ver = 1
        get_uint = function(buf) return buf:uint() end
      elseif (buffer(0, 2):le_uint() == 1) then
        block_ver = 1
        get_uint = function(buf) return buf:le_uint() end
      else
        return
      end

      local block_type = buffer(2, 1):uint()
      local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Custom Block: \"%s\" (%u)",
        block_types[block_type] or "Unknown", block_type))
      subtree:add(f.block_ver, buffer(0, 2), block_ver)
      subtree:add(f.block_type, buffer(2, 1))

      local block = buffer(4, buffer:len() - 4)

      if block_type == 1 then -- UID Mapping Block
        local uid = get_uint(block(0, 4))
        local packagename_len = block(4, 1):uint()
        local appname_len = block(5, 1):uint()
        local package_name = block(6, packagename_len):string()
        local app_name = block(6 + packagename_len, appname_len):string()

        subtree:set_text(string.format("KotSafe UID Mapping: UID %u -> %s (%s)", uid, package_name, app_name))
        subtree:add(f.uid, block(0, 4), uid)
        subtree:add(f.packagename_len, block(4, 1))
        subtree:add(f.appname_len, block(5, 1))
        subtree:add(f.packagename, block(6, packagename_len))
        subtree:add(f.appname, block(6 + packagename_len, appname_len))

        uid_map[uid] = {package_name, app_name}
      end
    end
  else
    local comment_fields = { comment_field() }

    if comment_fields[1] then
      local comment = comment_fields[1].value

      -- KotSafe encodes application UID in EPB comment option as "u-<uid>"
      if (string.sub(comment, 1, 2) == "u-") then
        local uid_str = string.sub(comment, 3)
        local uid = tonumber(uid_str)

        if uid ~= nil then
          local mapping = uid_map[uid]
          local package_name = mapping and mapping[1] or "Unknown"
          local app_name = mapping and mapping[2] or ("UID " .. uid_str)

          local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Metadata: App [%s], UID [%d]", app_name, uid))
          subtree:add(f.uid, uid)
          subtree:add(f.packagename, package_name)
          subtree:add(f.appname, app_name)
        end
      end
    end
  end
end

-- Post-dissector callback
function kotsafe_proto.dissector(buffer, pinfo, tree)
  if not dissect_pcap_trailer(buffer, pinfo, tree) then
    dissect_pcapng(buffer, pinfo, tree)
  end
end

-- Register as post-dissector to inspect all frames
register_postdissector(kotsafe_proto)
