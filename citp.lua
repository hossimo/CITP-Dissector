citp_proto = Proto("citp","CITP")

function citp_proto.dissector(buffer,pinfo,tree)

  citp_id = buffer (0,4):string()
  pinfo.cols.protocol = "CITP"
  local subtree = tree:add(citp_proto,buffer(),"CITP ("..string.len(buffer():string())..")")

  subtree = subtree:add(buffer(0,20),"Descriptor Header (" .. string.len(buffer(0,20):string())..")")
  subtree:add(buffer(0,4), "ID: " .. citp_id)
  citp_version = string.format("%d.%d",buffer (4,1):uint(),buffer (5,1):uint())
  subtree:add(buffer(4,2), "Version: " .. citp_version)
  if buffer(6,2):uint() == 0 then
    str=" (Ignored)"
  end
  subtree:add(buffer(6,2), "Request/Response ID: " .. buffer(6,2):le_uint())
  message_size = buffer(8,4):le_uint()
  subtree:add(buffer(8,4), "Message Size: " .. message_size)
  subtree:add(buffer(12,2), "Message Part Count: " .. buffer(12,2):le_uint())
  subtree:add(buffer(14,2), "Message Part: " .. buffer(14,2):le_uint())
  subtree:add(buffer(16,4), "Content Type: " .. buffer(16,4):string())
  pinfo.cols.info = string.format("CITP %s >",citp_version) -- info
  
  -- Calculate message size and reassemble PDUs if needed.
  if message_size > buffer:len() then
    pinfo.desegment_len = message_size - buffer:len()
    return
  end

    -- PINF ------------------------------------------------------------------------
    -- Peer Information layer
  if buffer(16,4):string() == "PINF" then
    pinfo.cols.info:append ("PINF >")   -- info
    subtree:add(buffer(20),"PINF ("..string.len(buffer(20):string())..")")
    subtree:add(buffer(20,4), "Content Type: " .. buffer(20,4):string())
    if buffer(20,4):string() == "PNam" then
      start = 26
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"State: ".. buffer(start):string())
    end
    if buffer(20,4):string() == "PLoc" then
      subtree:add(buffer(24,2), "Listeng Port: " .. (buffer(24,2):le_uint()))
      
      start = 26
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"Type: ".. buffer(start):string())
      start = start+count
      
      count = string.find(buffer(start):string(),"\0",1)
      name = buffer(start):string()
      subtree:add(buffer(start, count),"Name: ".. name)

      start = start+count
      count = string.find(buffer(start):string(),"\0",1)
      subtree:add(buffer(start, count),"State: ".. buffer(start):string())
    end
    pinfo.cols.info:append (name)   -- info    
  end
 
    -- MSEX ------------------------------------------------------------------------
  if buffer (16,4):string() == "MSEX" then
    local str = ""
    
    local ct = {
      CInf = "Client Information Message",
      SInf = "Server Information Message",
      Nack = "Negative Acknowledge Message",
      LSta = "Layer Status Message",
      StFr = "Stream Frame message",
      RqSt = "Request Stream message",
      GEIn = "Get Element Information message",
      MEIn = "Media Element Information message",
      GETh = "Get Element Thumbnail message",
      EThn = "Element Thumbnail message",
      ELIn = "Element Library Information message",
    }
    str = ct[buffer(22,4):string()] or "(Unknown)"
        
    subtree = subtree:add(buffer(20), "MSEX ("..string.len(buffer(20):string())..")")
    version = buffer (20,1):uint() .. "." .. buffer(21,1):uint()
    subtree:add(buffer(20,2), "Version: " .. version)  
    subtree:add(buffer(22,4), "Content Type: " .. buffer(22,4):string().." - "..str)
    
    pinfo.cols.info:append ("MSEX ".. version .." >") -- info
    -- MSEX/CInf --------------------------------------------------------------------
    if buffer(22,4):string() == "CInf" then
      pinfo.cols.info:append ("CInf >") -- info
      subtree:add(buffer(26,1), "Supported Version Count: ".. buffer(26,1):uint())
      subtree:add(buffer(27,2), "Supports -NYI-: ".. buffer(27,1))
    end

    -- MSEX/SInf 1.0 or 1.1 ---------------------------------------------------------
    -- Server Information message
    if (buffer(22,4):string() == "SInf") and (version <= "1.1") then
      pinfo.cols.info:append ("SInf >") -- info
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
      pinfo.cols.info:append (string.format("Server: %s Layers: %d", str, layercount))
    end
    -- MSEX/SInf 1.2 --------------------------------------------------------------
    if (buffer(22,4):string() == "SInf") and (version >= "1.2") then
      pinfo.cols.info:append ("SInf"..version.." >") -- info
      subtree:add("Version - NYI -")
    end

    -- MSEX/Nack ------------------------------------------------------------------
    if buffer(22,4):string() == "Nack" then
      pinfo.cols.info:append ("Nack >") -- info
      subtree:add(buffer(22),"Received Content: " .. buffer(22):string())
    end

   -- MSEX/StFr ------------------------------------------------------------------
    if buffer(22,4):string() == "StFr" then
      pinfo.cols.info:append ("StFr >") -- info
      start = 26
      
      count = 2
      sourceIdentifier = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"SourceIdentifier: " .. sourceIdentifier)
      start = start + count
      
      count = 4
      frameFormat = buffer(start,count):string()      
      subtree:add(buffer(start,count),"FrameFormat:  " .. frameFormat)
      start = start + count
      
      count = 2
      local frameWidth = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"FrameWidth: " .. frameWidth)
      start = start + count

      count = 2
      local frameHeight = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"FrameHeight: " .. frameHeight)
      start = start + count

      count = 2
      subtree:add(buffer(start,count),"BuferSize: " .. buffer(start,count):uint())
      bufferSize = buffer(start,count):le_uint()
      start = start + count
      
       pinfo.cols.info:append (string.format("SORCE:%d %s %dx%d",
       sourceIdentifier,
       frameFormat,
       frameWidth,
       frameHeight))


--      Remainder of packet is frame data, or part of frame data
    end
   -- MSEX/RqSt ------------------------------------------------------------------
    if buffer(22,4):string() == "RqSt" then
      pinfo.cols.info:append ("RqSt >") -- info

      start = 26
      
      count = 2
      local sourceIdentifier = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"SourceIdentifier: " .. sourceIdentifier)
      start = start + count
      
      count = 4
      local frameFormat = buffer(start,count):string()
      subtree:add(buffer(start,count),"FrameFormat:  " .. frameFormat)
      start = start + count
      
      count = 2
      local frameWidth = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"FrameWidth: " .. frameWidth)
      start = start + count

      count = 2
      local frameHeight = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"FrameHeight: " .. frameHeight)
      start = start + count

      count = 1
      local fps = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"FPS: " .. fps)
      start = start + count

      count = 1
      local timeout = buffer(start,count):le_uint()
      subtree:add(buffer(start,count),"Timeout: " .. timeout)
      start = start + count
      
      --info
       pinfo.cols.info:append (string.format("SORCE:%d %s %dx%d@%d %dSec",
       sourceIdentifier,
       frameFormat,
       frameWidth,
       frameHeight,
       fps,
       timeout))
    end
    
   -- MSEX 1.1/EThn ------------------------------------------------------------------
   -- Element Thumbnail message
    if (buffer(22,4):string() == "EThn") and (version == "1.1") then
      pinfo.cols.info:append ("EThn >") -- info
      start = 26
    
      count = 1
      local libraryType = buffer(start,count):uint()
      if (libraryType == 1) then libraryType_name = "Media" end
      if (libraryType == 2) then libraryType_name = "Effects"end
      subtree:add(buffer(start,count),string.format("Library Type: (%d) %s",libraryType,libraryType_name))
      start = start + count
      
      count = 4
      libraryId = string.format("%d,%d,%d,%d", 
        buffer(start,1):uint(),
        buffer(start+1,1):uint(),
        buffer(start+2,1):uint(),
        buffer(start+3,1):uint()
        )
      subtree:add(buffer(start,count),string.format("LibraryId: %s", libraryId))
      start = start + count

      count = 1
      element = buffer(start,count):uint()
      subtree:add(buffer(start,count),string.format("Element: %d", element))
      start = start + count


      count = 4
      subtree:add(buffer(start,count),string.format("Thumbnail Format: %s", buffer(start,count):string()))
      start = start + count

      count = 2
      width = buffer(start,count):le_uint()
      start = start + count

      count = 2
      height = buffer(start,count):le_uint()
      start = start + count

      subtree:add(buffer(start,count),string.format("Dimensions: %dx%d", width, height))

      count = 2
      subtree:add(buffer(start,count),string.format("Thumbs Buffer: %d", buffer(start,count):le_uint()))
      start = start + count

      --      Remainder of packet is frame data, or part of frame data
      subtree:add(buffer(start),"Data")
            
      --info
      pinfo.cols.info:append (string.format("LibraryID:%s Element:%s",
       libraryId,
       element))
    end

   -- MSEX 1.0/ELIn ------------------------------------------------------------------
   -- Element Library Information message
    if (buffer(22,4):string() == "ELIn") and (version == "1.0") then

    end
    
   -- MSEX 1.1/ELIn ------------------------------------------------------------------
   -- Element Library Information message
    if (buffer(22,4):string() == "ELIn") and (version == "1.1") then
      pinfo.cols.info:append ("ELIn >") -- info
      start = 26
    
      count = 1
      library_tupe = buffer(start,count):uint()
      subtree:add(buffer(start,count),string.format("LibraryType: %d", library_tupe))
      start = start + count

      count = 1
      element_count = buffer(start,count):uint()
      element_tree = subtree:add(buffer(start,count),string.format("Element Count: %d", element_count))
      start = start + count
      
      i = element_count

      for i = 1, element_count do
        count = 4
        libraryId = string.format("%d,%d,%d,%d", 
          buffer(start,1):uint(),
          buffer(start+1,1):uint(),
          buffer(start+2,1):uint(),
          buffer(start+3,1):uint()
        )
        lib_tree = element_tree:add(buffer(start,count),string.format("LibraryId: %s", libraryId))
        start = start + count

        count = 1
        lib_tree:add(buffer(start,count),string.format("DMX Min: %s", buffer(start,count):uint()))        
        start = start + count

        count = 1
        lib_tree:add(buffer(start,count),string.format("DMX Max: %s", buffer(start,count):uint()))        
        start = start + count
        
        count = 0
        str=""
       
        while buffer(start + count,1):uint() ~= 0 do
          str = str .. buffer(start+count,1):string()
          count = count + 2
        end
          count = count + 2

        lib_tree:add(buffer(start, count), string.format("Name: %s", str))
        start = start + count

        count = 1
        lib_tree:add(buffer(start,count),string.format("Sub Librarys: %d", buffer(start,count):uint()))        
        start = start + count

        count = 1
        lib_tree:add(buffer(start,count),string.format("Element Count: %d", buffer(start,count):uint()))        
        start = start + count
      end
      pinfo.cols.info:append (string.format("Elements: %d",element_count))

    end

   -- MSEX 1.2/ELIn ------------------------------------------------------------------
   -- Element Library Information message
    if (buffer(22,4):string() == "ELIn") and (version == "1.2") then

    end

    -- MSEX/LSta ------------------------------------------------------------------
    if buffer(22,4):string() == "LSta" then
      pinfo.cols.info:append ("LSta >") -- info

    
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
        length = buffer(start,count):le_uint()
        LSta[i]:add(buffer(start,count), "Media Position: " .. length)
        start = start + count

        count = 4
        length = buffer(start,count):le_uint()
        LSta[i]:add(buffer(start,count), "Media Length: " .. length)
        start = start + count
        
        count = 1
        LSta[i]:add(buffer(start,count), "Media FPS: " .. buffer(start,count):uint())
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
      end -- end for : Layer Count
      --info
      pinfo.cols.info:append (string.format("LAYER COUNT:%d",layercount))
    end -- end if : MSEX/LSta

    -- MSEX/MEIn1.0 ------------------------------------------------------------------
    if (buffer(22,4):string() == "MEIn") and (version == "1.0") then
      -- info
      pinfo.cols.info:append (string.format("MEIn >"))
      pinfo.cols.info:append ("-NYI-")

    end -- end if: MSEX/MEIn

    -- MSEX/MEIn1.1 ------------------------------------------------------------------
    if (buffer(22,4):string() == "MEIn") and (version == "1.1") then
      start = 26
    
      count = 4
        libraryId = string.format("%d,%d,%d,%d", 
          buffer(start,1):uint(),
          buffer(start+1,1):uint(),
          buffer(start+2,1):uint(),
          buffer(start+3,1):uint()
        )
        subtree:add(buffer(start,count),string.format("LibraryId: %s", libraryId))
        start = start + count
        
        count = 1
        element_count = buffer(start,count):uint()
        MEIn = subtree:add(buffer(start,count),string.format("Element Count: %d", element_count))
        start = start + count

        MEIn = {}
        for i = 1, element_count do
          count = 1
          MEIn[i] = subtree:add(buffer(start,count),string.format("Number: %d", buffer(start,count):uint()))
          start = start + count

          count = 1
          MEIn[i]:add(buffer(start,count),string.format("DMX Start: %d", buffer(start,count):uint()))
          start = start + count

          count = 1
          MEIn[i]:add(buffer(start,count),string.format("DMX End: %d", buffer(start,count):uint()))
          start = start + count
          
          count = 0
          str=""
          while buffer(start + count,1):uint() ~= 0 do --THIS IS BROKEN!!!!
            str = str .. buffer(start+count,1):string()
            count = count + 2
          end
          count = count +2
          MEIn[i]:add(buffer(start,count),string.format("Name: %s", str))
          start = start + count --debug
          
          -- This is a hack because le_uint64() returns the bigendian result
          count = 8
          epoch = 0
          mult = 1
          
          for j=0, count - 1 do
            epoch = epoch + (buffer(start+j, 1):uint() * mult)
            --debug
            --MEIn[i]:add(buffer(start,count),string.format("%02d: %sx%d=%s", j, buffer(start+j, 1):uint(), mult, buffer(start+j, 1):uint()*mult))  
            mult = mult * 256
          end
          
          -- The time OSX displays and the epoch caluclation is off by a number of minues.
          -- epoch and os.date seem to jive, but OSX time is wrong?
          MEIn[i]:add(buffer(start,count),string.format("Time: %s (epoch:%d)", os.date("%c", epoch), epoch))
                    
          start = start + count

          -- Calculate Dimensions
          count = 2
          width = buffer(start,count):le_uint()
          height = buffer(start+2,count):le_uint()
          MEIn[i]:add(buffer(start,4),string.format("Dimensions: %dx%d", width, height))
          start = start + 4
          
          count = 4
          MEIn[i]:add(buffer(start,count),string.format("Length (Frames): %d", buffer(start,count):le_uint()))
          start = start + count

          count = 1
          MEIn[i]:add(buffer(start,count),string.format("FPS: %d", buffer(start,count):uint()))
          start = start + count
          
        end

        
      
        -- info
        pinfo.cols.info:append (string.format("MEIn LibraryID: %s Elements: %d",libraryId ,element_count))
      end -- end if: MSEX/MEIn

    end -- end if : MSEX

end -- end function citp_proto.dissector

udp_table = DissectorTable.get("udp.port")
udp_table:add(4809,citp_proto)

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(6436,citp_proto)
