--
-- Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License, version 2 only,
-- as published by the Free Software Foundation.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
-- more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--

local st = require "util.stanza";

-- Module option.
-- 
-- This tells the module policy which for now there is two choices.
--		mandatory: OTR will be enforced. MUC will not work.
--		optional:  Warn user to suggest OTR. (default)
--		mixed: OTR will be enforced in all but MUC.
local policy = module:get_option_string("otr_policy", "optional");

local mandatory;
local mandatory_msg = "For security reasons, OTR, OMEMO, or PGP encryption is required for conversations on this server";
local optional;
local optional_msg = "For security reasons, OTR, OMEMO, or PGP encryption is STRONGLY recommended for conversations on this server";
local mixed;
local muc_msg = "Beware, Multi-User Chat is not supported by OTR, but is supported by OMEMO or PGP in specific circumstances with some clients."

local messaged = {};

local log = module._log;

local function strip_full_jid(jid)
	local offset = string.find(jid, "/");
	if offset == nil then
		return jid;
	end

	return string.sub(jid, 0, offset - 1);
end

--
-- Check body message for the presence of the OTR tag.
local function check_message_otr(event)
	local session, stanza = event.origin, event.stanza;
    local body = stanza:get_child_text("body");
	local is_otr, jid;

	-- No origin for the message, well it's not supposed to happen
	-- to we stop the message right away.
	if stanza.attr.from == nil then
		return true;
	end
	jid = strip_full_jid(stanza.attr.from);

	-- Continue processing the signal if no body is found since we can't
	-- enforce OTR with an empty payload.
	if body == nil then
		return nil;
	end

	-- If message is OTR, just pass the signal.
	if body:sub(1,4) == "?OTR" then
		return nil;
	end

	-- check omemo https://xmpp.org/extensions/inbox/omemo.html
	if event.stanza:get_child("encrypted", "eu.siacs.conversations.axolotl") or event.stanza:get_child("encrypted", "urn:xmpp:omemo:0") then
		return nil;
	end

	-- check xep27 pgp https://xmpp.org/extensions/xep-0027.html
	if event.stanza:get_child("x", "jabber:x:encrypted") then
		return nil;
	end

	-- check xep373 pgp (OX) https://xmpp.org/extensions/xep-0373.html
	if event.stanza:get_child("openpgp", "urn:xmpp:openpgp:0") then
		return nil;
	end

	-- no valid encryption found

	-- Warn the user that OTR will not work on MUC but let the message pass.
	-- Available for optional and mixed mode.
	if stanza.attr.type == "groupchat" and not mandatory then
		-- Warn once.
		if messaged[jid] == nil then
			event.origin.send(st.message{ type = "chat", from = module.host, to = event.stanza.attr.from }:tag("body"):text(muc_msg));
			messaged[jid] = 1
		end
		return nil;
	end

	-- Force OTR on chats if policy is mandatory or mixed.
	if stanza.attr.type == "chat" and not optional then
		-- Inform client that OTR is mandatory and stop signal.
		event.origin.send(st.message{ type = "chat", from = module.host, to = event.stanza.attr.from }:tag("body"):text(mandatory_msg));
		return true;
	end

	-- Warn if NO otr is detected and if we've NOT warned before the user.
	if optional and messaged[jid] == nil then
		event.origin.send(st.message{ type = "chat", from = module.host, to = event.stanza.attr.from }:tag("body"):text(optional_msg));
		messaged[jid] = 1
		return nil;
	end
end

--
-- Handle presence signal. This function will nullify the JID that
-- becomes unavailable so next time the user connects, the message will
-- be displayes again.
local function handle_presence(event)
	local jid;

	-- Continue signal, mandatory policy does not require us to 
	-- remove the "messaged" entry.
	if mandatory then
		return nil;
	end

	if event.stanza.attr.type == "unavailable" then
		jid = strip_full_jid(event.stanza.attr.from);
		messaged[jid] = nil;
	end
end

-- Module load entry point.
function module.load()
	-- Validate policy option.
	if policy == "mandatory" then
		mandatory = 1;
	elseif policy == "optional" then
		optional = 1;
	elseif policy == "mixed" then
		mixed = 1;
	else
		-- Invalid policy, stop loading module.
		module:log("error", "Unknown policy %s", policy);
		return;
	end

	module:log("info", "OTR policy set to %s", policy);
end

module:hook("message/bare", check_message_otr, 1000);
module:hook("message/full", check_message_otr, 1000);
module:hook("message/host", check_message_otr, 1000);

module:hook("pre-message/bare", check_message_otr, 1000);
module:hook("pre-message/full", check_message_otr, 1000);

module:hook("presence/bare", handle_presence, 1000);
module:hook("presence/full", handle_presence, 1000);
module:hook("presence/host", handle_presence, 1000);
