citp_proto = Proto("citp","CITP")

function citp_proto.dissector(buffer,pinfo,tree)
local str=""
  pinfo.cols.protocol = "CITP"
  local subtree = tree:add(citp_proto,buffer(),"CITP ("..string.len(buffer():string())..")")
  subtree = subtree:add(buffer(0,20),"Descriptor Header (" .. string.len(buffer(0,20):string())..")")
  subtree:add(buffer(0,4), "ID: " .. buffer (0,4):string())
  subtree:add(buffer(4,2), "Version: " .. buffer (4,1):uint() .. "." .. buffer(5,1):uint())
  if buffer(6,2):uint() == 0 then
    str=" (Ignored)"
  end
  subtree:add(buffer(6,2), "Request/Response ID: " .. buffer(6,1):uint() + (buffer(7,1):uint()*256) ..str)
  subtree:add(buffer(8,4), "Message Size: " .. buffer(8,1):uint() + (buffer(9,1):uint()*256) + (buffer(10,1):uint()*512) + (buffer(11,1):uint()*1024))
  subtree:add(buffer(12,2), "Message Part Count: " .. buffer(12,1):uint()+ (buffer(13,1):uint()*16))
  subtree:add(buffer(14,2), "Message Part: " .. buffer(14,1):uint()+ (buffer(15,1):uint()*256))
  subtree:add(buffer(16,4), "Content Type: " .. buffer(16,4):string())

    -- PINF ------------------------------------------------------------------------
  if buffer(16,4):string() == "PINF" then
    subtree = subtree:add(buffer(20),"PINF ("..string.len(buffer(20):string())..")")
    subtree:add(buffer(20,4), "Content Type: " .. buffer(20,4):string())
    if buffer(20,4):string() == "PNam" then
      start = 26
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"State: ".. buffer(start):string())
    end
    if buffer(20,4):string() == "PLoc" then
      subtree:add(buffer(24,2), "Listeng Port: " .. (buffer(24,1):uint()) + (buffer(25,1):uint()*256))
      
      start = 26
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"Type: ".. buffer(start):string())

      start = start+count
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"Name: ".. buffer(start):string())

      start = start+count
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"State: ".. buffer(start):string())
    end
  end
 
    -- MSEX ------------------------------------------------------------------------
  if buffer (16,4):string() == "MSEX" then
    local str = ""
    
    local ct = {
      CInf = "Client Information Message",
      SInf = "Server Information Message",
      Nack = "Negative Acknowledge Message",
      LSta = "Layer Status Message",
    }
    str = ct[buffer(22,4):string()] or "(Unknown)"
    
    subtree = subtree:add(buffer(20), "MSEX ("..string.len(buffer(20):string())..")")
    version = buffer (20,1):uint() .. "." .. buffer(21,1):uint()
    subtree:add(buffer(20,2), "Version: " .. version)  
    subtree:add(buffer(22,4), "Content Type: " .. buffer(22,4):string().." - "..str)
    
    -- MSEX/CInf --------------------------------------------------------------------
    if buffer(22,4):string() == "CInf" then
      subtree:add(buffer(26,1), "Supported Version Count: ".. buffer(26,1):uint())
      subtree:add(buffer(27,2), "Supports -NYI-: ".. buffer(27,1))
    end

    -- MSEX/SInf 1.0 or 1.1 ---------------------------------------------------------
    if (buffer(22,4):string() == "SInf") and (version <= "1.1") then
      start = 26
      count = 0
      str=""
      while buffer(start+count,1):uint() ~= 0 do
        str = str .. buffer(start+count,1):string()
        count = count + 2
      end
      count = count + 2
      
      subtree:add(buffer(start, count),"Product Name (ASCII): ".. str)
      start = start + count

      count = 2
      subtree:add(buffer(start,count), "Version: " .. buffer (start,1):uint() .. "." .. buffer(start+1,1):uint())
      start = start + count
      
      count = 1
      layercount = buffer(start, count):uint()
      dmx = subtree:add(buffer(start,count), "Number of Layers: " .. layercount)
      start = start + count
      
      for i = 1, layercount do
        count = string.find(buffer(start):string(),"\0",1)
        dmx:add(buffer(start, count), "Layer ".. i .." DMX (proto/net/uni/chan.): " .. buffer(start):string())
        start = start + count
      end
    end
    -- MSEX/SInf 1.2 --------------------------------------------------------------
    if (buffer(22,4):string() == "SInf") and (version <= "1.1") then
      subtree:add("Version - NYI -")
    end

    -- MSEX/Nack ------------------------------------------------------------------
    if buffer(22,4):string() == "Nack" then
      subtree:add(buffer(22),"Received Content: " .. buffer(22):string())
    end

    -- MSEX/LSta ------------------------------------------------------------------
    if buffer(22,4):string() == "LSta" then
      start = 26
      count = 1
      layercount = buffer(start,count):uint() 
      subtree:add(buffer(start,count), "Layer Count: " .. layercount)
      
      LSta = {}
      LSta_status = {}
                  
      for i = 1, layercount do
        start = start + count
        
        count = 1
        LSta[i] = subtree:add(buffer(start,count), "Layer Number:" .. buffer(start,count):uint() .." (".. buffer(start+2,1):uint().."/"..buffer(start+3,1):uint()..")")
        start = start + count
        
        count = 1
        LSta[i]:add(buffer(start,count), "Physical Output: " .. buffer(start,count):uint())
        start = start + count

        count = 1
        LSta[i]:add(buffer(start,count), "Media Library: " .. buffer(start,count):uint())
        start = start + count

        count = 1
        LSta[i]:add(buffer(start,count), "Media Number: " .. buffer(start,count):uint())
        start = start + count
        
        count = 0
        str=""
        
        while buffer(start+count,1):uint() ~= 0 do
          str = str .. buffer(start+count,1):string()
          count = count + 2
        end
        count = count + 2
        
        LSta[i]:add(buffer(start,count), "Media Name: " .. str)
        start = start + count
        
        count = 4
        length = buffer(start,1):uint() + (buffer(start+1,1):uint()*256) + (buffer(start+2,1):uint()*512) + (buffer(start+3,1):uint()*1024)
        LSta[i]:add(buffer(start,count), "Media Position: " .. length)
        start = start + count

        count = 4
        length = buffer(start,1):uint() + (buffer(start+1,1):uint()*256) + (buffer(start+2,1):uint()*512) + (buffer(start+3,1):uint()*1024)
        LSta[i]:add(buffer(start,count), "Media Length: " .. length)
        start = start + count
        
        count = 1
        LSta[i]:add(buffer(start,count), "Media FPS: " .. buffer(start,1):uint())
        start = start + count
        
        count = 4
        str = ""
        current_stat = buffer(start+3,1) .. buffer(start+2,1).. buffer(start+1,1).. buffer(start,1)
        
        if bit.band(current_stat,00000001) > 0 then
          str = str .. "MediaPlaying, "
        end
        if bit.band(current_stat,00000002) > 0 then -- 1.2 Only
          str = str .. "MediaPlaybackReverse, "
        end
        if bit.band(current_stat,00000004) > 0 then -- 1.2 Only
          str = str .. "MediaPlaybackLooping, "
        end
        if bit.band(current_stat,00000008) > 0 then -- 1.2 Only
          str = str .. "MediaPlaybackBouncing, "
        end
        if bit.band(current_stat,00000010) > 0 then -- 1.2 Only
          str = str .. "MediaPlaybackRandom, "
        end
        if bit.band(current_stat,00000020) > 0 then -- 1.2 Only
          str = str .. "MediaPaused, "
        end
        if current_stat == "00000000" then
          str = "None, "
        end
        
        str = string.sub(str,1,-3)
        
        LSta[i]:add(buffer(start,count), "Layer Status: ".."("..current_stat..") "..str)
      end
    end
    
  end
  
  

end

udp_table = DissectorTable.get("udp.port")
udp_table:add(4809,citp_proto)

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(6436,citp_proto)
