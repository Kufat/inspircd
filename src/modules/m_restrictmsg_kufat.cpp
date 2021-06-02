/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2015 Attila Molnar <attilamolnar@hush.com>
 *   Copyright (C) 2013, 2015, 2017, 2019-2020 Sadie Powell <sadie@witchery.services>
 *   Copyright (C) 2012, 2019 Robby <robby@chatbelgie.be>
 *   Copyright (C) 2009 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2006, 2010 Craig Edwards <brain@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "extensible.h"
#include "modules/account.h"
#include "modules/ctctags.h"

#include <algorithm>
#include <string>
#include <vector>

typedef std::vector<std::string> nickallowlist;

class LocalStringVecExt : public SimpleExtItem<nickallowlist>
{
 public:
	LocalStringVecExt(Module* Creator)
		: SimpleExtItem<nickallowlist>("msgallow", ExtensionItem::EXT_USER, Creator)
	{
		// empty
	}

	std::string ToInternal(const Extensible* container, void* item) const CXX11_OVERRIDE
	{
		nickallowlist* list = static_cast<nickallowlist*>(item);
		std::string buf;
		for (nickallowlist::const_iterator iter = list->cbegin(); iter != list->cend(); ++iter)
		{
			if (iter != list->begin())
				buf.push_back(' ');

			buf.append(*iter);
		}
		return buf;
	}

	void FromInternal(Extensible* container, const std::string& value) CXX11_OVERRIDE
	{
		LocalUser* user = IS_LOCAL(static_cast<User*>(container));
		if (!user)
			return;

		// Remove the old list and create a new one.
		unset(user);
		nickallowlist* list = new nickallowlist();

		irc::spacesepstream ts(value);
		while (!ts.StreamEnd())
		{
			std::string tmpStr;
			if (!ts.GetToken(tmpStr))
			{
				ServerInstance->Logs->Log(MODNAME, LOG_DEBUG, "Malformed nick allow list received for %s: %s",
					user->uuid.c_str(), value.c_str());
				delete list;
				return;
			}
			list->push_back(tmpStr);
		}
		// The value was well formed.
		set(user, list);
	}
};

// Could make this an account event listener and clear the allow list when a user registers with services,
// but the cost of the extra checks on each account change event outweigh the occasional benefits of 
// cleaning up an allow list slightly more quickly than would otherwise be the case.

class ModuleRestrictMsg
	: public Module
	, public CTCTags::EventListener
{
 private:
	LocalStringVecExt ext;

	// Return true iff the would-be recipient of the current message has previously
	// messaged the current message's sender.
	// In other words, is the sender replying to an existing conversation?
	bool RecipientHasMessagedSender(User* sender, User* recipient) const
	{
		nickallowlist* allowList(ext.get(sender));
		return ( allowList && (allowList->cend() != std::find(allowList->cbegin(), allowList->cend(), recipient->uuid)));
	}

	// We need to do two things here.
	// 1. If a sending user isn't allowed to send a message, block it.
	// 2. If a receiving user will now be allowed to reply to the sender,
	//    keep track of that.

	ModResult HandleMessage(User* sender, const MessageTarget& target)
	{
		if (target.type != MessageTarget::TYPE_USER)
		{
			// No action for channel messages.
			return MOD_RES_PASSTHRU;
		}

		const AccountExtItem* accountext = GetAccountExtItem();
		User* recipient = target.Get<User>();
		bool messageOK = false;

		// First, examine sender if they're local. If so, examine for Part 1.

		if (IS_LOCAL(sender))
		{
			// message allowed if:
			// (1) the recipient is opered
			// (2) the sender is opered
			// (3) the recipient is on a ulined server
			// (4) registration is unavailable
			// (5) the sender is registered
			// (6) the recipient had previously messaged the sender

			if (recipient->IsOper() || 
				sender->IsOper() || 
				recipient->server->IsULine() || 
				!accountext ||
				accountext->get(sender) ||
				RecipientHasMessagedSender(sender, recipient))
			{
				messageOK = true;
			}
		}
		else
		{
			// Some other server already checked this message when the sender was local to it,
			// or it's from services.
			messageOK = true;
		}

		if (messageOK)
		{
			// The message is allowable, so be sure that the recipient will now be able to reply.
			if (IS_LOCAL(recipient) && 
				!sender->server->IsULine() && // don't waste time/space with NickServ etc
				accountext && 
				!accountext->get(recipient)) // These allow lists are only needed for unregistered users
			{
				// An unregistered user on this server is receiving a message from a registered user.
				nickallowlist* allowList(ext.get(recipient));
				if (!allowList)
				{
					allowList = new nickallowlist();
					ext.set(recipient, allowList);
				}
				// Add the sender to the list of users the recipient is allowed to message, if not already present
				if (allowList->cend() == std::find(allowList->cbegin(), allowList->cend(), sender->uuid))
				{
					allowList->push_back(sender->uuid);
				}
			}
		}
		else
		{
			sender->WriteNumeric(Numerics::CannotSendTo(sender, 
				"Unregistered users may not initiate PMs on this network. "
				"Please register your nick with NickServ."));
			return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}

 public:
	ModuleRestrictMsg()
		: CTCTags::EventListener(this)
		, ext(this)
	{
	}

	ModResult OnUserPreMessage(User* user, const MessageTarget& target, MessageDetails& details) CXX11_OVERRIDE
	{
		return HandleMessage(user, target);
	}

	ModResult OnUserPreTagMessage(User* user, const MessageTarget& target, CTCTags::TagMessageDetails& details) CXX11_OVERRIDE
	{
		return HandleMessage(user, target);
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Limits ability of users without accounts to start PM conversations.", VF_COMMON);
	}
};

MODULE_INIT(ModuleRestrictMsg)
