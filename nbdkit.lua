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
-- (lldb) script dofile 'nbdkit.lua'
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

function uio_iov_str(uio)
	local iov = uio:GetChildMemberWithName("uio_iov")
	local iovcnt = uio:GetChildMemberWithName("uio_iovcnt"):GetValueAsUnsigned()
	local arraytype = iov:GetType():GetArrayType(iovcnt)
	local iovarray = iov:Cast(arraytype)
	local iovs = {}
	for i = 0, iovcnt - 1 do
		local iov_ = iovarray:GetChildAtIndex(i)
		local base = iov_:GetChildMemberWithName("iov_base"):GetValueAsUnsigned()
		local len = iov_:GetChildMemberWithName("iov_len"):GetValueAsUnsigned()
		table.insert(iovs, string.format("(0x%x:%d)", base, len))
	end
	return string.format("iov[%s]", table.concat(iovs, ","))
end

function uio_summary(uio)
	return string.format("%s\n%s", tostring(uio), uio_iov_str(uio))
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

function find_nbdkit()
	local nbdkit = SBValueTable()
	local function find_nbdkit_socket(thread)
		print(thread)
		local frame
		local so
		local uio
		for i = 0, thread:GetNumFrames() - 1 do
			local frame_ = thread:GetFrameAtIndex(i)
			print(frame_)
			local so_ = frame_:FindVariable("so")
			if so_:IsValid() and so_:IsInScope() then
				-- XXX: May be valid and in scope but not available in this frame.
				-- Work around by checking for valid contents.  We always read 0 when
				-- unavailable, and we know so_state must have SS_ISCONNECTED set.
				local state = so_:GetChildMemberWithName("so_state"):GetValueAsUnsigned()
				if state ~= 0 then
					so = so_:Dereference()
				end
			end
			local uio_ = frame_:FindVariable("uio")
			if uio_:IsValid() and uio_:IsInScope() then
				-- XXX: May be valid and in scope but not available in this frame.
				-- Work around by checking for valid contents.  We always read 0 when
				-- unavailable, and we know uio_iovcnt must be > 0.
				local iovcnt = uio_:GetChildMemberWithName("uio_iovcnt"):GetValueAsUnsigned()
				if iovcnt ~= 0 then
					uio = uio_:Dereference()
				end
			end
			local fn = frame_:GetFunctionName()
			if fn == "sosend_generic_locked" then
				frame = frame_
			elseif fn == "soreceive_generic_locked" then
				frame = frame_
			end
		end
		if so ~= nil then
			local snd = so:GetChildMemberWithName("so_snd")
			local rcv = so:GetChildMemberWithName("so_rcv")
			print("Socket summary:")
			print(socket_summary(so))
			print("Send buffer details:")
			print(sockbuf_details(snd))
			print("Receive buffer details:")
			print(sockbuf_details(rcv))
		end
		if uio ~= nil then
			print("Uio summary:")
			print(uio_summary(uio))
		end
		return frame, so, uio
	end
	for i = 0, lldb.process:GetNumThreads() - 1 do
		local thread = lldb.process:GetThreadAtIndex(i)
		local name = thread:GetName()
		if name and name:find("nbdkit") then
			local frame, so, uio = find_nbdkit_socket(thread)
			if so ~= nil then
				nbdkit[so] = { frame = frame, uio = uio }
			end
		end
	end
	return nbdkit
end

nbdkit = find_nbdkit()
