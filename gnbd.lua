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
	local bits = value:GetValueAsSigned()
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

instances = find_gnbd_instances()
for sc, instance in pairs(instances) do
	print(sc)
	for nc, frames in pairs(instance.connections) do
		print(string.format("(nbd_conn *) %s", tostring(nc:GetAddress())))
		local state = nc:GetChildMemberWithName("nc_state")
		local seq = nc:GetChildMemberWithName("nc_seq")
		local socket = nc:GetChildMemberWithName("nc_socket")
		print(state, seq)
		print(frames.sender:GetThread())
		print(frames.sender)
		print(frames.receiver:GetThread())
		print(frames.receiver)
		print(socket_summary(socket))
		for ni in iter_inflight(nc) do
			print(ni:Dereference())
			local bio = ni:GetChildMemberWithName("ni_bio")
			print(bio_summary(bio))
		end
	end
end
