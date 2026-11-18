#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    if (!lower_sni.empty() && lower_sni.back() == '.') lower_sni.pop_back();
    auto matches = [&](const char* domain) {
        std::string base(domain);
        return lower_sni == base || (lower_sni.size() > base.size() &&
            lower_sni.compare(lower_sni.size() - base.size(), base.size(), base) == 0 &&
            lower_sni[lower_sni.size() - base.size() - 1] == '.');
    };
    // Domain labels, never arbitrary substrings, identify applications.
    const std::pair<const char*, AppType> known[] = {
        {"youtube.com", AppType::YOUTUBE},
        {"youtube-nocookie.com", AppType::YOUTUBE},
        {"googlevideo.com", AppType::YOUTUBE},
        {"ytimg.com", AppType::YOUTUBE},
        {"youtu.be", AppType::YOUTUBE},
        {"yt3.ggpht.com", AppType::YOUTUBE},
        {"google.com", AppType::GOOGLE},
        {"gstatic.com", AppType::GOOGLE},
        {"googleapis.com", AppType::GOOGLE},
        {"ggpht.com", AppType::GOOGLE},
        {"gvt1.com", AppType::GOOGLE},
        {"facebook.com", AppType::FACEBOOK},
        {"fbcdn.net", AppType::FACEBOOK},
        {"fb.com", AppType::FACEBOOK},
        {"fbsbx.com", AppType::FACEBOOK},
        {"meta.com", AppType::FACEBOOK},
        {"instagram.com", AppType::INSTAGRAM},
        {"cdninstagram.com", AppType::INSTAGRAM},
        {"whatsapp.com", AppType::WHATSAPP},
        {"whatsapp.net", AppType::WHATSAPP},
        {"wa.me", AppType::WHATSAPP},
        {"twitter.com", AppType::TWITTER},
        {"twimg.com", AppType::TWITTER},
        {"x.com", AppType::TWITTER},
        {"t.co", AppType::TWITTER},
        {"netflix.com", AppType::NETFLIX},
        {"nflxvideo.net", AppType::NETFLIX},
        {"nflximg.net", AppType::NETFLIX},
        {"amazon.com", AppType::AMAZON},
        {"amazonaws.com", AppType::AMAZON},
        {"cloudfront.net", AppType::AMAZON},
        {"microsoft.com", AppType::MICROSOFT},
        {"msn.com", AppType::MICROSOFT},
        {"office.com", AppType::MICROSOFT},
        {"office365.com", AppType::MICROSOFT},
        {"azure.com", AppType::MICROSOFT},
        {"live.com", AppType::MICROSOFT},
        {"outlook.com", AppType::MICROSOFT},
        {"bing.com", AppType::MICROSOFT},
        {"windows.com", AppType::MICROSOFT},
        {"apple.com", AppType::APPLE},
        {"icloud.com", AppType::APPLE},
        {"mzstatic.com", AppType::APPLE},
        {"itunes.com", AppType::APPLE},
        {"telegram.org", AppType::TELEGRAM},
        {"t.me", AppType::TELEGRAM},
        {"tiktok.com", AppType::TIKTOK},
        {"tiktokcdn.com", AppType::TIKTOK},
        {"musical.ly", AppType::TIKTOK},
        {"bytedance.com", AppType::TIKTOK},
        {"spotify.com", AppType::SPOTIFY},
        {"scdn.co", AppType::SPOTIFY},
        {"zoom.us", AppType::ZOOM},
        {"discord.com", AppType::DISCORD},
        {"discordapp.com", AppType::DISCORD},
        {"discordapp.net", AppType::DISCORD},
        {"github.com", AppType::GITHUB},
        {"githubusercontent.com", AppType::GITHUB},
        {"cloudflare.com", AppType::CLOUDFLARE},
        {"cloudflare-dns.com", AppType::CLOUDFLARE},
    };
    for (const auto& entry : known) if (matches(entry.first)) return entry.second;

    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
