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
--		mandatory: OTR will be enforced
--		optional:  Warn user to suggest OTR. (default)
local policy = module:get_option_string("otr_policy", "optional");

local mandatory;
local mandatory_msg = "For security reasons, OTR encryption is required for conversations on this server";
local optional;
local optional_msg = "For security reasons, OTR encryption is STRONGLY recommended for conversations on this server";

local messaged = {};

--
-- Check body message for the presence of the OTR tag.
local function check_message_otr(event)
    local body = event.stanza:get_child_text("body");
	local session = event.origin;
	local is_otr;

	-- Is this body is an OTR message?
	if body and body:sub(1,4) ~= "?OTR" then
		is_otr = 0;
	else
		is_otr = 1;
	end

	-- Force OTR if policy is mandatory.
	if mandatory and is_otr == 0 then
		event.origin.send(st.message{ type = "chat", from = module.host, to = event.stanza.attr.from }:tag("body"):text(mandatory_msg));
		return true;
	end

	-- Warn if NO otr is detected and if we've NOT warned before the user.
	if optional and messaged[session.full_jid] == nil and is_otr == 0 then
		event.origin.send(st.message{ type = "chat", from = module.host, to = event.stanza.attr.from }:tag("body"):text(optional_msg));
		messaged[session.full_jid] = 1
	end
end

-- Module load entry point.
function module.load()
	-- Validate policy option.
	if policy == "mandatory" then
		mandatory = 1;
	elseif policy == "optional" then
		optional = 1;
	else
		-- Invalid policy, stop loading module.
		module:log("error", "Unknown policy %s", policy);
		return;
	end

	module:log("info", "OTR policy set to %s", policy);
end

module:hook("message/bare", check_message_otr, 300);
module:hook("message/full", check_message_otr, 300);
module:hook("message/host", check_message_otr, 300);
