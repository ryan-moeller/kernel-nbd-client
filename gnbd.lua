-- Copyright (c) 2025 Ryan Moeller
-- SPDX-License-Identifier: BSD-2-Clause
--
-- For live debugging:
-- # lldb -c /dev/mem /boot/kernel/kernel
--
-- For post-mortem debugging:
-- # lldb -c /var/crash/vmcore.last /boot/kernel/kernel
--
-- Then at the (lldb) prompt:
-- (lldb) script dofile 'gnbd.lua'
--
-- Or what can be useful while editing this script in (neo)vim:
-- :!lldb -b -o "script -l lua -- dofile '%:p'" -c /dev/mem /boot/kernel/kernel

-- LLDB does this automatically in the REPL
lldb.debugger = lldb.SBDebugger.FindDebuggerWithID(1)
lldb.target = lldb.debugger:GetSelectedTarget()
lldb.process = lldb.target:GetProcess()

function error_str(value)
	local errno = (type(value) == "number") and value or value:GetValueAsSigned()
	local definitions = { "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO",
	    "E2BIG", "ENOEXEC", "EBADF", "ECHILD", "EDEADLK", "ENOMEM", "EACCES",
	    "EFAULT", "ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV", "ENOTDIR",
	    "EISDIR", "EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG",
	    "ENOSPC", "ESPIPE", "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE",
	    "EAGAIN", "EINPROGRESS", "EALREADY", "ENOTSOCK", "EDESTADDRREQ",
	    "EMSGSIZE", "EPROTOTYPE", "ENOPROTOOPT", "EPROTONOSUPPORT",
	    "ESOCKTNOSUPPORT", "EOPNOTSUPP", "EPFNOSUPPORT", "EAFNOSUPPORT",
	    "EADDRINUSE", "EADDRNOTAVAIL", "ENETDOWN", "ENETUNREACH", "ENETRESET",
	    "ECONNABORTED", "ECONNRESET", "ENOBUFS", "EISCONN", "ENOTCONN",
	    "ESHUTDOWN", "ETOOMANYREFS", "ETIMEDOUT", "ECONNREFUSED", "ELOOP",
	    "ENAMETOOLONG", "EHOSTDOWN", "EHOSTUNREACH", "ENOTEMPTY", "EPROCLIM",
	    "EUSERS", "EDQUOT", "ESTALE", "EREMOTE", "EBADRPC", "ERPCMISMATCH",
	    "EPROGUNAVAIL", "EPROGMISMATCH", "EPROCUNAVAIL", "ENOLCK", "ENOSYS",
	    "EFTYPE", "EAUTH", "ENEEDAUTH", "EIDRM", "ENOMSG", "EOVERFLOW",
	    "ECANCELED", "EILSEQ", "ENOATTR", "EDOOFUS", "EBADMSG", "EMULTIHOP",
	    "ENOLINK", "EPROTO", "ENOTCAPABLE", "ECAPMODE", "ENOTRECOVERABLE",
	    "EOWNERDEAD", "EINTEGRITY", [-1] = "ERESTART", [-2] = "EJUSTRETURN",
	    [-3] = "ENOIOCTL", [-4] = "EDIRIOCTL", [-5] = "ERELOOKUP" }
	return definitions[errno] or tostring(errno)
end

assert(error_str(0) == "0")
assert(error_str(97) == "EINTEGRITY")

function bits_str(value, definitions, sep)
	local nbytes = value:GetByteSize()
	local mask = (1 << (nbytes * 8)) - 1
	local bits = value:GetValueAsUnsigned() & mask
	local matches = {}
	local check = 0
	for name, value in pairs(definitions) do
		if (bits & value) ~= 0 then
			table.insert(matches, name)
			check = check | value
		end
	end
	check = bits & ~check
	if check ~= 0 then
		local unknown = string.format("0x%x", check)
		table.insert(matches, unknown)
	end
	if #matches == 0 then
		return "0"
	end
	return table.concat(matches, sep or ",")
end

-- Ordinary tables hash keys by the userdata pointer.
-- Two distinct SBValue userdata objects can represent
-- the same memory location in the target being debugged,
-- and we want them to be treated as equivalent keys in
-- a table.
function SBValueTable()
	-- Internally the table uses the address as the key
	-- for a pair of the key SBValue and whatever we want
	-- the value to be.  We hide these details behind a
	-- metatable.
	local function addr(k)
		return k:GetAddress():GetOffset()
	end
	local function lookup(t, k)
		local kv = rawget(t, k)
		if kv ~= nil then
			return kv[1], kv[2]
		end
	end
	local function nextpair(t, p)
		local k = next(t, p and addr(p))
		if k ~= nil then
			return lookup(t, k)
		end
	end
	local t = {}
	setmetatable(t, {
		__newindex = function (t, k, v)
			rawset(t, addr(k), {k,v})
		end,
		__index = function (t, k)
			local _k, v = lookup(t, addr(k))
			return v
		end,
		__pairs = function (t)
			return nextpair, t
		end,
	})
	return t
end

function find_gnbd_instances()
	local instances = SBValueTable()
	local function find_gnbd_connection(thread)
		for i = 0, thread:GetNumFrames() - 1 do
			local frame = thread:GetFrameAtIndex(i)
			local fn = frame:GetFunctionName()
			if fn == "nbd_conn_sender" then
				local nc = frame:FindVariable("nc")
				if nc:IsValid() then
					return nc:Dereference(), "sender", frame
				end
			elseif fn == "nbd_conn_receiver" then
				local nc = frame:FindVariable("nc")
				if nc:IsValid() then
					return nc:Dereference(), "receiver", frame
				end
			end
		end
	end
	for i = 0, lldb.process:GetNumThreads() - 1 do
		local thread = lldb.process:GetThreadAtIndex(i)
		local name = thread:GetName()
		if name and name:find("gnbd/gnbd") then
			local nc, key, frame = find_gnbd_connection(thread)
			if nc ~= nil then
				local sc = nc:GetChildMemberWithName("nc_softc"):Dereference()
				if instances[sc] == nil then
					instances[sc] = { connections = SBValueTable() }
				end
				if instances[sc].connections[nc] == nil then
					instances[sc].connections[nc] = {}
				end
				instances[sc].connections[nc][key] = frame
			end
		end
	end
	return instances
end

function iter_connections(sc)
	local head = sc:GetChildMemberWithName("sc_connections")
	local nc = head:GetChildMemberWithName("slh_first")
	return function ()
		while nc:GetValueAsSigned() ~= 0 do
			local link = nc:GetChildMemberWithName("nc_connections")
			local current = nc
			nc = link:GetChildMemberWithName("sle_next")
			return current
		end
		return nil
	end
end

function iter_inflight(nc)
	local head = nc:GetChildMemberWithName("nc_inflight")
	local ni = head:GetChildMemberWithName("tqh_first")
	return function ()
		while ni:GetValueAsSigned() ~= 0 do
			local link = ni:GetChildMemberWithName("ni_inflight")
			local current = ni
			ni = link:GetChildMemberWithName("tqe_next")
			return current
		end
		return nil
	end
end

function socket_options_str(so, sep)
	local options = so:GetChildMemberWithName("so_options")
	local definitions = {
		DEBUG        = 0x00000001,
		ACCEPTCONN   = 0x00000002,
		REUSEADDR    = 0x00000004,
		KEEPALIVE    = 0x00000008,
		DONTROUTE    = 0x00000010,
		BROADCAST    = 0x00000020,
		USELOOPBACK  = 0x00000040,
		LINGER       = 0x00000080,
		OOBINLINE    = 0x00000100,
		REUSEPORT    = 0x00000200,
		TIMESTAMP    = 0x00000400,
		NOSIGPIPE    = 0x00000800,
		ACCEPTFILTER = 0x00001000,
		BINTIME      = 0x00002000,
		NO_OFFLOAD   = 0x00004000,
		NO_DDP       = 0x00008000,
		REUSEPORT_LB = 0x00010000,
		RERROR       = 0x00020000,
	}
	return bits_str(options, definitions, sep)
end

function socket_state_str(so, sep)
	local state = so:GetChildMemberWithName("so_state")
	local definitions = {
		ISCONNECTED     = 0x0002,
		ISCONNECTING    = 0x0004,
		ISDISCONNECTING = 0x0008,
		NBIO            = 0x0100,
		ASYNC           = 0x0200,
		ISDISCONNECTED  = 0x2000,
	}
	return bits_str(state, definitions, sep)
end

function sockbuf_flags_str(sb, sep)
	local flags = sb:GetChildMemberWithName("sb_flags")
	local definitions = {
		TLS_RX         = 0x0001,
		TLS_RX_RUNNING = 0x0002,
		WAIT           = 0x0004,
		SEL            = 0x0008,
		ASYNC          = 0x0010,
		UPCALL         = 0x0020,
		-- was NOINTR
		AIO            = 0x0080,
		KNOTE          = 0x0100,
		NOCOALESCE     = 0x0200,
		IN_TOE         = 0x0400,
		AUTOSIZE       = 0x0800,
		STOP           = 0x1000,
		AIO_RUNNING    = 0x2000,
		SPLICED        = 0x4000,
		TLS_RX_RESYNC  = 0x8000,
	}
	return bits_str(flags, definitions, sep)
end

function sockbuf_state_str(sb, sep)
	local state = sb:GetChildMemberWithName("sb_state")
	local definitions = {
		CANTSENDMORE = 0x0010,
		CANTRCVMORE  = 0x0020,
		RCVATMARK    = 0x0040,
	}
	return bits_str(state, definitions, sep)
end

function sockbuf_summary(sb)
	local flags = sockbuf_flags_str(sb)
	local state = sockbuf_state_str(sb)
	local acc = sb:GetChildMemberWithName("sb_acc"):GetValueAsUnsigned()
	local ccc = sb:GetChildMemberWithName("sb_ccc"):GetValueAsUnsigned()
	local hiwat = sb:GetChildMemberWithName("sb_hiwat"):GetValueAsUnsigned()
	local lowat = sb:GetChildMemberWithName("sb_lowat"):GetValueAsUnsigned()
	return string.format("flags<%s>,state<%s>,acc<%d>,ccc<%d>,hiwat<%d>,lowat<%d>",
	    flags, state, acc, ccc, hiwat, lowat)
end

function socket_summary(so)
	local options = socket_options_str(so)
	local state = socket_state_str(so)
	local error = error_str(so:GetChildMemberWithName("so_error"))
	local rerror = error_str(so:GetChildMemberWithName("so_rerror"))
	local snd = sockbuf_summary(so:GetChildMemberWithName("so_snd"))
	local rcv = sockbuf_summary(so:GetChildMemberWithName("so_rcv"))
	return string.format([[
socket[
  options<%s>, state<%s>, error<%s>, rerror<%s>,
  snd<%s>,
  rcv<%s>
]] .. "]", options, state, error, rerror, snd, rcv)
end

function mbuf_type_str(m)
	local type = m:GetChildMemberWithName("m_type"):GetValueAsUnsigned()
	local definitions = { [0] = "NOTMBUF",
	    [1] = "DATA", -- 2, 3 not defined
	    [4] = "VENDOR1", [5] = "VENDOR2",
	    [6] = "VENDOR3", [7] = "VENDOR4",
	    [8] = "SONAME",
	    [9] = "EXP1", [10] = "EXP2",
	    [11] = "EXP3", [12] = "EXP4",
	    -- 13 not defined
	    [14] = "CONTROL", [15] = "EXTCONTROL",
	    [16] = "OOBDATA", [255] = "NOINIT",
	}
	return definitions[type] or tostring(type)
end

function mbuf_flags_str(m, sep)
	local flags = m:GetChildMemberWithName("m_flags")
	local definitions = {
		EXT         = 0x00000001,
		PKTHDR      = 0x00000002,
		EOR         = 0x00000004,
		RDONLY      = 0x00000008,
		BCAST       = 0x00000010,
		MCAST       = 0x00000020,
		PROMISC     = 0x00000040,
		VLANTAG     = 0x00000080,
		EXTPG       = 0x00000100,
		NOFREE      = 0x00000200,
		TSTMP       = 0x00000400,
		TSTMP_HPREC = 0x00000800,
		TSTMP_LRO   = 0x00001000,
		PROTO1      = 0x00002000,
		PROTO2      = 0x00004000,
		PROTO3      = 0x00008000,
		PROTO4      = 0x00010000,
		PROTO5      = 0x00020000,
		PROTO6      = 0x00040000,
		PROTO7      = 0x00080000,
		PROTO8      = 0x00100000,
		PROTO9      = 0x00200000,
		PROTO10     = 0x00400000,
		PROTO11     = 0x00800000,
	}
	return bits_str(flags, definitions, sep)
end

function m_ext_type_str(ext)
	local type = ext:GetChildMemberWithName("ext_type"):GetValueAsUnsigned()
	local definitions = { "CLUSTER", "SFBUF",
	    "JUMBOP", "JUMBO9", "JUMBO16",
	    "PACKET", "MBUF", "RXRING", "CTL",
	    [224] = "VENDOR1", [225] = "VENDOR2",
	    [226] = "VENDOR3", [227] = "VENDOR4",
	    [244] = "EXP1", [245] = "EXP2",
	    [246] = "EXP3", [247] = "EXP4",
	    [252] = "NET_DRV", [253] = "MOD_TYPE",
	    [254] = "DISPOSABLE", [255] = "EXTREF"
	}
	return definitions[type] or tostring(type)
end

function m_ext_flags_str(ext, sep)
	local flags = ext:GetChildMemberWithName("ext_flags")
	local definitions = {
		EMBREF  = 0x000001,
		EXTREF  = 0x000002,
		NOFREE  = 0x000010,
		VENDOR1 = 0x010000,
		VENDOR2 = 0x020000,
		VENDOR3 = 0x040000,
		VENDOR4 = 0x080000,
		EXP1    = 0x100000,
		EXP2    = 0x200000,
		EXP3    = 0x400000,
		EXP4    = 0x800000,
	}
	return bits_str(flags, definitions, sep)
end

function m_ext_summary(ext)
	local size = ext:GetChildMemberWithName("ext_size"):GetValueAsUnsigned()
	local type = m_ext_type_str(ext)
	local flags = m_ext_flags_str(ext, "|")
	return string.format("m_ext[size<%u>,type<%s>,flags<%s>]",
	    size, type, flags)
end

function mbuf_summary(m)
	local len = m:GetChildMemberWithName("m_len"):GetValueAsUnsigned()
	local type = mbuf_type_str(m)
	local flags = mbuf_flags_str(m, "|")
	if flags:find("EXT") then
		local ext = m:GetChildMemberWithName("m_ext")
		return string.format("mbuf[len<%u>,type<%s>,flags<%s>,ext<%s>]",
		    len, type, flags, m_ext_summary(ext))
	else
		return string.format("mbuf[len<%u>,type<%s>,flags<%s>]",
		    len, type, flags)
	end
end

function sockbuf_details(sb)
	local mbcnt = sb:GetChildMemberWithName("sb_mbcnt"):GetValueAsUnsigned()
	local mbmax = sb:GetChildMemberWithName("sb_mbmax"):GetValueAsUnsigned()
	local mb = sb:GetChildMemberWithName("sb_mb")
	local mbufs = {}
	while mb:GetAddress():GetOffset() ~= 0 do
		table.insert(mbufs, mbuf_summary(mb))
		mb = mb:GetChildMemberWithName("m_next")
	end
	return string.format("sockbuf[mbcnt<%u>,mbmax<%u>,#mb<%u>]\n%s",
	    mbcnt, mbmax, #mbufs, table.concat(mbufs, "\n"))
end

function bio_cmd_str(bp)
	local cmd = bp:GetChildMemberWithName("bio_cmd"):GetValueAsSigned()
	local definitions = {
		"READ",
		"WRITE",
		"DELETE",
		"GETATTR",
		"FLUSH",
		"CMD0",
		"CMD1",
		"CMD2",
		"ZONE",
		"SPEEDUP",
	}
	return definitions[cmd] or "(unknown)"
end

function bio_flags_str(bp, sep)
	local flags = bp:GetChildMemberWithName("bio_flags")
	local definitions = {
		ERROR             = 0x0001,
		DONE              = 0x0002,
		ONQUEUE           = 0x0004,
		ORDERED           = 0x0008,
		UNMAPPED          = 0x0010,
		TRANSIENT_MAPPING = 0x0020,
		VLIST             = 0x0040,
		SWAP              = 0x0200,
		SPEEDUP_WRITE     = 0x4000,
		SPEEDUP_TRIM      = 0x8000,
	}
	return bits_str(flags, definitions, sep)
end

function bio_summary(bp)
	local cmd = bio_cmd_str(bp)
	local flags = bio_flags_str(bp)
	local offset = bp:GetChildMemberWithName("bio_offset"):GetValueAsUnsigned()
	local length = bp:GetChildMemberWithName("bio_length"):GetValueAsUnsigned()
	return string.format("bio[%s<%s>%d:%d]", cmd, flags, offset, length)
end

function inflight_summary(ni)
	local cookie = ni:GetChildMemberWithName("ni_cookie"):GetValueAsUnsigned()
	local bio = ni:GetChildMemberWithName("ni_bio")
	return string.format("(nbd_inflight) cookie=%d %s", cookie, bio_summary(bio))
end

function thread_summary(frame)
	local thread = frame:GetThread()
	local lines = {}
	table.insert(lines, tostring(thread))
	table.insert(lines, tostring(frame))
	table.insert(lines, "Full Backtrace:")
	for i = 0, thread:GetNumFrames() - 1 do
		local frame = thread:GetFrameAtIndex(i)
		table.insert(lines, tostring(frame))
	end
	return table.concat(lines, "\n")
end

instances = find_gnbd_instances()
for sc, instance in pairs(instances) do
	print(sc)
	for nc, frames in pairs(instance.connections) do
		print(string.format("(nbd_conn *) %s", tostring(nc:GetAddress())))
		local state = nc:GetChildMemberWithName("nc_state")
		local seq = nc:GetChildMemberWithName("nc_seq")
		local socket = nc:GetChildMemberWithName("nc_socket")
		local snd = socket:GetChildMemberWithName("so_snd")
		local rcv = socket:GetChildMemberWithName("so_rcv")
		print(state, seq)
		if frames.sender then
			print(thread_summary(frames.sender))
		else
			print("no sender thread")
		end
		if frames.receiver then
			print(thread_summary(frames.receiver))
		else
			print("no receiver thread")
		end
		print("Socket summary:")
		print(socket_summary(socket))
		print("Send buffer details:")
		print(sockbuf_details(snd))
		print("Receive buffer details:")
		print(sockbuf_details(rcv))
		print("In-flight requests:")
		for ni in iter_inflight(nc) do
			print(inflight_summary(ni))
		end
	end
end
