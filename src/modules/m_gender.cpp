/**
 * Author: Kufat
 * Loosely based upon https://gist.github.com/alexwilson/95cbb8ad0f7969a6387571e51bc8bbfb (No license listed.)
 * and m_customtitle.
 */

#include "inspircd.h"
#include "modules/whois.h"

enum
{
	// From UnrealIRCd.
	RPL_WHOISSPECIAL = 320
};

class WhoisLine // is it anyway
{
    StringExtItem extItem;
    const std::string text;
    const bool useQuotes;

public:
    WhoisLine(const std::string& name, // Used for metadata lookup
              const std::string& descriptiveText, // Used on /whois line
              bool quotes,
              Module* parent) : 
        extItem(name, ExtensionItem::EXT_USER, parent),
        text(descriptiveText),
        useQuotes(quotes)
    {
    }

    void get(std::vector<std::string>& o_list, Whois::Context& whois) const
    {
        std::string* userStr = extItem.get(whois.GetTarget());
        if (userStr) {
            std::stringstream response;
            if(useQuotes)
            {
                response << text << " '" << userStr->c_str() << "'";
            }
            else
            {
                response << text << " " << userStr->c_str();
            }
            o_list.push_back(response.str());
        }
    }
};

class ModuleGenderSCP : public Module, public Whois::LineEventListener
{
	WhoisLine pronoun, pronounAccepted, pronounNotAccepted, gender;
    std::vector<WhoisLine*> lines;

 public:
	ModuleGenderSCP() : 
        Whois::LineEventListener(this),
        pronoun("pronoun", "uses the pronouns", true, this),
        pronounAccepted("pronounAccepted", "accepts the pronouns", true, this),
        pronounNotAccepted("pronounNotAccepted", "does NOT accept the pronouns", true, this),
        gender("gender", "identifies as", false, this),
        lines{&pronoun, &pronounAccepted, &pronounNotAccepted, &gender}
	{
	}

	ModResult OnWhoisLine(Whois::Context& whois, Numeric::Numeric& numeric) CXX11_OVERRIDE
	{
        if (numeric.GetNumeric() == 312)
        {
            std::vector<std::string> info;
            for (auto line : lines)
            {
                line->get(info, whois);
            }
            if(!info.empty())
            {
#ifdef GENDER_ONELINE
                std::stringstream out;
                for(size_t i = 0; i < info.size(); ++i)
                {
                    if(info.size() - 1 == i && i > 0) // last one and not only
                    {
                        out << "and ";
                    }
                    out << info[i];
                    if(i < info.size() - 1) // at least one left
                    {
                        out << "; ";
                    }
                }
                out << ".";
                whois.SendLine(RPL_WHOISSPECIAL, out.str());
#else
                for(auto i : info)
                {
                    whois.SendLine(RPL_WHOISSPECIAL, i);
                }
#endif
            }
        }
        //std::for_each(lines.begin(), lines.end(), [&](auto line){ line->print(whois);});
		return MOD_RES_PASSTHRU;
	}

	Version GetVersion()
	{
		return Version("Provides gender and pronouns in WHOIS.", VF_VENDOR);
	}
};

MODULE_INIT(ModuleGenderSCP)