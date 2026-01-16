// Define the `main` function

const proxyName = "代理模式";

function main(params) {
    if (!params.proxies) return params;
    overwriteRules(params);
    overwriteProxyGroups(params);
    overwriteDns(params);
    return params;
}
// 覆写规则
function overwriteRules(params) {
    const customRules = [
        // 在此添加自定义规则，最高优先级。
        // 为了方便区分，可设置 全局代理模式 或 自定义代理组。
        // 示例 1 ：使用 全局代理模式
        //"DOMAIN-SUFFIX,linux.do," + proxyName,
        // 示例 2 ：使用 自定义代理组 1
        //"DOMAIN-SUFFIX,gstatic.com, 自定义代理组 1",
        // 示例 3 ：使用 自定义代理组 2
        //"DOMAIN-SUFFIX,googleapis.com, 自定义代理组 2",
        // ssh连接走直连
        "DOMAIN-SUFFIX,fengkongcloud.com,小红书",
        "DOMAIN-SUFFIX,xiaohongshu.com,小红书",
        "DOMAIN-SUFFIX,douyinvod.com,抖音",
        "DOMAIN-SUFFIX,amemv.com,抖音",
        "DOMAIN-SUFFIX,swdcmg.com,DIRECT",
        "IP-CIDR,10.0.0.0/24,回家节点"
    ];


    const rules = [
        ...customRules,
        "RULE-SET,myDirect,DIRECT,no-resolve",
        "RULE-SET,cncidr,DIRECT,no-resolve",
        "RULE-SET,private,DIRECT,no-resolve",
        "RULE-SET,lancidr,DIRECT,no-resolve",
        `RULE-SET,icloud,DIRECT,no-resolve`,
        `RULE-SET,apple,DIRECT,no-resolve`,
        //"RULE-SET,applications,DIRECT",
        "RULE-SET,openai,ChatGPT,no-resolve",
        "RULE-SET,metaAi,MetaAI,no-resolve",
        "RULE-SET,claude,Claude,no-resolve",
        "RULE-SET,gemini,Gemini,no-resolve",
        // "RULE-SET,youtube,YouTube,no-resolve",
        "RULE-SET,github,GitHub,no-resolve",
        "RULE-SET,spotify,Spotify,no-resolve",
        "RULE-SET,speedtest,Speedtest,no-resolve",
        "RULE-SET,reddit,Reddit,no-resolve",
        "RULE-SET,tiktok,TikTok,no-resolve",
        "RULE-SET,telegramcidr,电报消息,no-resolve",
        `RULE-SET,tldnotcn,${proxyName},no-resolve`,
        `RULE-SET,google,${proxyName},no-resolve`,
        `RULE-SET,apple,${proxyName},no-resolve`,
        `RULE-SET,gfw,${proxyName},no-resolve`,
        `RULE-SET,greatfire,${proxyName},no-resolve`,
        `RULE-SET,proxy,${proxyName},no-resolve`,
        "RULE-SET,reject, ⛔广告拦截,no-resolve",
        "RULE-SET,Advertising, ⛔广告拦截,no-resolve",
        "RULE-SET,direct,DIRECT,no-resolve",
        "GEOIP,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT,no-resolve",
        "MATCH, 🐟漏网之鱼",
    ];
    const domainRules = { type: "http", behavior: "domain", interval: 21600 };

    const githubProxy = "https://github.uitz.pro/";

    const ruleProviders = {
        reject: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
            path: "./ruleset/reject.yaml",
        },
        Advertising: {
            ...domainRules,
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml`,
            path: "./ruleset/Advertising.yaml",
        },
        myDirect: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/UiTz/proxy-rule/refs/heads/main/direct.yaml`,
            path: "./ruleset/custom/myDirect.yaml",
        },
        direct: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
            path: "./ruleset/direct.yaml",
        },
        private: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
            path: "./ruleset/private.yaml",
        },
        cncidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
            path: "./ruleset/cncidr.yaml",
        },
        lancidr: {
            type: "http",
            behavior: "ipcidr",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
            path: "./ruleset/lancidr.yaml",
        },
        tldnotcn: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
            path: "./ruleset/tldnotcn.yaml",
        },
        gfw: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
            path: "./ruleset/gfw.yaml",
        },
        greatfire: {
            ...domainRules,
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
            path: "./ruleset/greatfire.yaml",
        },
        proxy: {
            ...domainRules,
            url: `${githubProxy}https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt`,
            path: "./ruleset/proxy.yaml",
        },
        telegramcidr: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.yaml`,
            path: "./ruleset/custom/telegramcidr.yaml",
        },
        icloud: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/iCloud/iCloud.yaml`,
            path: "./ruleset/icloud.yaml",
        },
        apple: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Apple/Apple_Classical.yaml`,
            path: "./ruleset/apple.yaml",
        },
        google: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml`,
            path: "./ruleset/google.yaml",
        },
        github: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml`,
            path: "./ruleset/custom/github.yaml",
        },
        spotify: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml`,
            path: "./ruleset/custom/Spotify.yaml",
        },
        metaAi: {
            ...domainRules,
            format: "text",
            url: `${githubProxy}https://raw.githubusercontent.com/liandu2024/clash/refs/heads/main/list/MetaAi.list`,
            path: "./ruleset/custom/metaAi.list",
        },
        reddit: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Reddit/Reddit.yaml`,
            path: "./ruleset/custom/reddit.yaml",
        },
        speedtest: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Speedtest/Speedtest.yaml`,
            path: "./ruleset/custom/speedtest.yaml",
        },
        openai: {
            type: "http",
            behavior: "classical",
            url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml",
            path: "./ruleset/custom/openai.yaml",
        },
        youtube: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml`,
            path: "./ruleset/custom/youtube.yaml",
        },
        tiktok: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml`,
            path: "./ruleset/custom/tiktok.yaml",
        },
        claude: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml`,
            path: "./ruleset/custom/Claude.yaml",
        },
        gemini: {
            type: "http",
            behavior: "classical",
            url: `${githubProxy}https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.yaml`,
            path: "./ruleset/custom/Gemini.yaml",
        },
        applications: {
            type: "http",
            behavior: "classical",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
            path: "./ruleset/applications.yaml",
        },
    };

    // 注入缓存校验机制函数
    function injectCacheControl(ruleProviders) {
        Object.entries(ruleProviders).forEach(([key, rule]) => {
            // 优先保留已有 interval，否则默认 21600 (6小时)
            if (typeof rule.interval === "undefined") {
                rule.interval = 21600;
            }
            // 加上 etag 以启用缓存验证（Clash.Meta 支持）
            if (typeof rule.etag === "undefined") {
                rule.etag = "*";
            }
            // 你也可以根据需要加上 last-modified 支持
            // if (typeof rule["last-modified"] === "undefined") {
            //     rule["last-modified"] = true;
            // }
        });
    }

    // 立即注入
    injectCacheControl(ruleProviders);


    params["rule-providers"] = ruleProviders;
    params["rules"] = rules;
}
// 覆写代理组
function overwriteProxyGroups(params) {
    // 添加自用代理
    params.proxies.push(
        //  { name: '1 - 香港 - 示例 ', type: *, server: **, port: *, cipher: **, password: **, udp: true }

    );

    // 所有代理
    const allProxies = params["proxies"].map((e) => e.name);
    // 自动选择代理组，按地区分组选延迟最低
    const autoProxyGroupRegexs = [
        { name: "HK - 自动选择", regex: / 香港 | HK|Hong|🇭🇰/ },
        { name: "TW - 自动选择", regex: / 台湾 | TW|Taiwan|Wan|🇨🇳|🇹🇼/ },
        { name: "SG - 自动选择", regex: / 新加坡 | 狮城 | SG|Singapore|🇸🇬/ },
        { name: "JP - 自动选择", regex: / 日本 | JP|Japan|🇯🇵/ },
        { name: "KR - 自动选择", regex: / 韩国 | KR|Korea|🇰🇷/ },
        { name: "US - 自动选择", regex: / 美国 | US|United States|America|🇺🇸/ },
        { name: "其它 - 自动选择", regex: /(?!.*(?: 剩余 | 到期 | 主页 | 官网 | 游戏 | 关注))(.*)/ },
    ];

    // Smart 策略组，按地区分组智能选择
    const smartProxyGroupRegexs = [
        { name: "HK - 智能选择", regex: / 香港 | HK|Hong|🇭🇰/ },
        { name: "TW - 智能选择", regex: / 台湾 | TW|Taiwan|Wan|🇨🇳|🇹🇼/ },
        { name: "SG - 智能选择", regex: / 新加坡 | 狮城 | SG|Singapore|🇸🇬/ },
        { name: "JP - 智能选择", regex: / 日本 | JP|Japan|🇯🇵/ },
        { name: "KR - 智能选择", regex: / 韩国 | KR|Korea|🇰🇷/ },
        { name: "US - 智能选择", regex: / 美国 | US|United States|America|🇺🇸/ },
        { name: "其它 - 智能选择", regex: /(?!.*(?: 剩余 | 到期 | 主页 | 官网 | 游戏 | 关注))(.*)/ },
    ];

    const autoProxyGroups = autoProxyGroupRegexs
        .map((item) => ({
            name: item.name,
            type: "url-test",
            url: "http://www.google.com/generate_204",
            interval: 300,
            tolerance: 50,
            proxies: getProxiesByRegex(params, item.regex),
            hidden: false,
        }))
        .filter((item) => item.proxies.length > 0);

    // Smart 策略组配置
    const smartProxyGroups = smartProxyGroupRegexs
        .map((item) => ({
            name: item.name,
            type: "smart",
            uselightgbm: true,
            collectdata: true,
            "health-check": {
                enable: true,
                url: "https://www.gstatic.com/generate_204",
                interval: 60,
                tolerance: 2
            },
            strategy: "sticky-sessions",
            lazy: false,
            proxies: getProxiesByRegex(params, item.regex),
            hidden: false,
        }))
        .filter((item) => item.proxies.length > 0);

    // 手工选择代理组
    const manualProxyGroups = [
        { name: "HK - 手工选择", regex: / 香港 | HK|Hong|🇭🇰/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg" },
        { name: "TW - 手工选择", regex: / 台湾 | TW|Taiwan|Wan|🇨🇳|🇹🇼/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg" },
        { name: "SG - 手工选择", regex: / 新加坡 | 狮城 | SG|Singapore|🇸🇬/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg" },
        { name: "JP - 手工选择", regex: / 日本 | JP|Japan|🇯🇵/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg" },
        { name: "KR - 手工选择", regex: / 韩国 | KR|Korea|🇰🇷/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/kr.svg" },
        { name: "US - 手工选择", regex: / 美国 | US|United States|America|🇺🇸/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg" },
    ];

    const manualProxyGroupsConfig = manualProxyGroups
        .map((item) => ({
            name: item.name,
            type: "select",
            proxies: getManualProxiesByRegex(params, item.regex),
            icon: item.icon,
            hidden: false,
        }))
        .filter((item) => item.proxies.length > 0);

    // const GPTProxyRegex = getProxiesByRegex(params, /^(?!.*?(香港|HK|Hong|🇭🇰)).*$/)
    const GPTProxyRegex = getProxiesByRegex(params, /GPT/)
    
    // 定义常用代理组合
    const commonProxyGroups = [
        proxyName, 
        "HK - 自动选择", "TW - 自动选择", "SG - 自动选择", 
        "KR - 自动选择", "JP - 自动选择", "US - 自动选择", "其它 - 自动选择",
        "HK - 智能选择", "TW - 智能选择", "SG - 智能选择", 
        "KR - 智能选择", "JP - 智能选择", "US - 智能选择", "其它 - 智能选择",
        "HK - 手工选择", "TW - 手工选择", "SG - 手工选择", 
        "KR - 手工选择", "JP - 手工选择", "US - 手工选择"
    ];

      // --- 覆盖 '订阅二' ---
    // 如果你只使用一个订阅，可以注释或删除以下 '订阅二' 部分。
    // ↓↓↓ 用户配置区域 (订阅二) ↓↓↓
    const providerTwoConfig = {
      type: 'http',
      interval: 3600,
      'health-check': {
          enable: true,
          url: 'https://cp.cloudflare.com',
          interval: 300,
          timeout: 1000,
          tolerance: 100
      },
      // --- 你的订阅信息 (订阅二) ---
      url: "https://sub.uitz.pro/d33skXDsLRVsZqF0mTWM/download/home?target=ClashMeta", // <--- (必需) 第二个机场订阅链接
      path: "./proxy_provider/home.yaml", // <--- (必需) 缓存文件路径，与第一个不同
      //override: {
      //    'additional-prefix': "[机场二]" // (可选) 添加节点名称前缀
      //}
    };
    // ↑↑↑ 用户配置区域 (订阅二) ↑↑↑
    params['proxy-providers']['订阅二'] = providerTwoConfig; // 覆盖 '订阅二'
    console.log("JS 覆写：已覆盖 '订阅二'。");

    const groups = [
        {
            name: proxyName,
            type: "select",
            url: "http://www.google.com/generate_204",
            icon: "https://raw.githubusercontent.com/fmz200/wool_scripts/main/icons/Twoandz9/Xray.png",
            proxies: [
                "自动选择",
                "智能选择",
                "手动选择",
                "🔀负载均衡(散列)",
                "🔁负载均衡(轮询)",
                ...autoProxyGroups.map((item) => item.name),
                ...smartProxyGroups.map((item) => item.name),
                "DIRECT",
            ],
        },
        {
            name: "手动选择",
            type: "select",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg",
            proxies: allProxies,
        },
        {
            name: "自动选择",
            icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png",
            type: "url-test",
            url: "http://www.google.com/generate_204",
            interval: 120,
            tolerance: 10,
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "智能选择",
            icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Rocket.png",
            type: "smart",
            uselightgbm: true,
            collectdata: true,
            "health-check": {
              enable: true,
              url: "https://www.gstatic.com/generate_204",
              interval: 60,
              tolerance: 2
            },
            strategy: "sticky-sessions",
            lazy: false,
            proxies: allProxies,
        },
        {
            name: "回家节点",
            icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Back.png",
            type: "select",
            proxies: [
                "回家节点"
            ]
        },
        {
            name: "🔀负载均衡(散列)",
            type: "load-balance",
            url: "http://www.google.com/generate_204",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
            interval: 300,
            "max-failed-times": 3,
            strategy: "consistent-hashing",
            lazy: true,
            proxies: allProxies,
        },
        {
            name: "🔁负载均衡(轮询)",
            type: "load-balance",
            url: "http://www.google.com/generate_204",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
            interval: 300,
            "max-failed-times": 3,
            strategy: "round-robin",
            lazy: true,
            proxies: allProxies,
        },
        {
            name: "自定义代理组 1",
            type: "select",
            proxies: commonProxyGroups,
            "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/ambulance.svg"
        },
        {
            name: "自定义代理组 2",
            type: "select",
            proxies: commonProxyGroups,
            "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/ambulance.svg"
        },
        {
            name: "电报消息",
            type: "select",
            proxies: commonProxyGroups,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg"
        },
        {
            name: "Reddit",
            type: "url-test",
            interval: 600,
            tolerance: 20,
            url: "https://www.reddit.com",
            lazy: false,
            // "expected-status": "200",
            // proxies: [proxyName, "HK - 自动选择", "TW - 自动选择", "SG - 自动选择", "KR - 自动选择", "JP - 自动选择", "US - 自动选择", "其它 - 自动选择", "HK - 手工选择", "TW - 手工选择", "SG - 手工选择", "KR - 手工选择", "JP - 手工选择", "US - 手工选择"],
            proxies: [...allProxies],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/reddit.svg"
        },
        {
            name: "小红书",
            type: "select",
            url: "http://xiaohongshu.com",
            interval: 600,
            lazy: false, 
            proxies: ["DIRECT", ...allProxies],
            icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Fries.png"
        },
        {
            name: "抖音",
            type: "select",
            url: "http://amemv.com",
            interval: 600,
            lazy: false,
            proxies: ["DIRECT", ...allProxies],
            icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/TikTok_1.png"
        },
        {
            name: "Speedtest",
            type: "select",
            proxies: [proxyName, "DIRECT", "手动选择"],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg"
        },
        {
            name: "ChatGPT",
            type: "url-test",
            interval: 600,
            tolerance: 20,
            url: "http://chatgpt.com",
            lazy: false,
            // "expected-status": "200",
            // proxies: [proxyName, "HK - 自动选择", "TW - 自动选择", "SG - 自动选择", "KR - 自动选择", "JP - 自动选择", "US - 自动选择", "其它 - 自动选择", "HK - 手工选择", "TW - 手工选择", "SG - 手工选择", "KR - 手工选择", "JP - 手工选择", "US - 手工选择"],
            proxies: [...GPTProxyRegex],
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg"
        },
        {
            name: "MetaAI",
            type: "select",
            interval: 600,
            url: "http://meta.ai",
            lazy: false,
            proxies: [...GPTProxyRegex],
            icon: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNTYiIGhlaWdodD0iMTcxIiB2aWV3Qm94PSIwIDAgMjU2IDE3MSI+Cgk8ZGVmcz4KCQk8bGluZWFyR3JhZGllbnQgaWQ9ImxvZ29zTWV0YUljb24wIiB4MT0iMTMuODc4JSIgeDI9Ijg5LjE0NCUiIHkxPSI1NS45MzQlIiB5Mj0iNTguNjk0JSI+CgkJCTxzdG9wIG9mZnNldD0iMCUiIHN0b3AtY29sb3I9IiMwMDY0ZTEiIC8+CgkJCTxzdG9wIG9mZnNldD0iNDAlIiBzdG9wLWNvbG9yPSIjMDA2NGUxIiAvPgoJCQk8c3RvcCBvZmZzZXQ9IjgzJSIgc3RvcC1jb2xvcj0iIzAwNzNlZSIgLz4KCQkJPHN0b3Agb2Zmc2V0PSIxMDAlIiBzdG9wLWNvbG9yPSIjMDA4MmZiIiAvPgoJCTwvbGluZWFyR3JhZGllbnQ+CgkJPGxpbmVhckdyYWRpZW50IGlkPSJsb2dvc01ldGFJY29uMSIgeDE9IjU0LjMxNSUiIHgyPSI1NC4zMTUlIiB5MT0iODIuNzgyJSIgeTI9IjM5LjMwNyUiPgoJCQk8c3RvcCBvZmZzZXQ9IjAlIiBzdG9wLWNvbG9yPSIjMDA4MmZiIiAvPgoJCQk8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiMwMDY0ZTAiIC8+CgkJPC9saW5lYXJHcmFkaWVudD4KCTwvZGVmcz4KCTxwYXRoIGZpbGw9IiMwMDgxZmIiIGQ9Ik0yNy42NTEgMTEyLjEzNmMwIDkuNzc1IDIuMTQ2IDE3LjI4IDQuOTUgMjEuODJjMy42NzcgNS45NDcgOS4xNiA4LjQ2NiAxNC43NTEgOC40NjZjNy4yMTEgMCAxMy44MDgtMS43OSAyNi41Mi0xOS4zNzJjMTAuMTg1LTE0LjA5MiAyMi4xODYtMzMuODc0IDMwLjI2LTQ2LjI3NWwxMy42NzUtMjEuMDFjOS40OTktMTQuNTkxIDIwLjQ5My0zMC44MTEgMzMuMS00MS44MDZDMTYxLjE5NiA0Ljk4NSAxNzIuMjk4IDAgMTgzLjQ3IDBjMTguNzU4IDAgMzYuNjI1IDEwLjg3IDUwLjMgMzEuMjU3QzI0OC43MzUgNTMuNTg0IDI1NiA4MS43MDcgMjU2IDExMC43MjljMCAxNy4yNTMtMy40IDI5LjkzLTkuMTg3IDM5Ljk0NmMtNS41OTEgOS42ODYtMTYuNDg4IDE5LjM2My0zNC44MTggMTkuMzYzdi0yNy42MTZjMTUuNjk1IDAgMTkuNjEyLTE0LjQyMiAxOS42MTItMzAuOTI3YzAtMjMuNTItNS40ODQtNDkuNjIzLTE3LjU2NC02OC4yNzNjLTguNTc0LTEzLjIzLTE5LjY4NC0yMS4zMTMtMzEuOTA3LTIxLjMxM2MtMTMuMjIgMC0yMy44NTkgOS45Ny0zNS44MTUgMjcuNzVjLTYuMzU2IDkuNDQ1LTEyLjg4MiAyMC45NTYtMjAuMjA4IDMzLjk0NGwtOC4wNjYgMTQuMjg5Yy0xNi4yMDMgMjguNzI4LTIwLjMwNyAzNS4yNzEtMjguNDA4IDQ2LjA3Yy0xNC4yIDE4LjkxLTI2LjMyNCAyNi4wNzYtNDIuMjg3IDI2LjA3NmMtMTguOTM1IDAtMzAuOTEtOC4yLTM4LjMyNS0yMC41NTZDMi45NzMgMTM5LjQxMyAwIDEyNi4yMDIgMCAxMTEuMTQ4eiIgLz4KCTxwYXRoIGZpbGw9InVybCgjbG9nb3NNZXRhSWNvbjApIiBkPSJNMjEuODAyIDMzLjIwNkMzNC40OCAxMy42NjYgNTIuNzc0IDAgNzMuNzU3IDBDODUuOTEgMCA5Ny45OSAzLjU5NyAxMTAuNjA1IDEzLjg5N2MxMy43OTggMTEuMjYxIDI4LjUwNSAyOS44MDUgNDYuODUzIDYwLjM2OGw2LjU4IDEwLjk2N2MxNS44ODEgMjYuNDU5IDI0LjkxNyA0MC4wNyAzMC4yMDUgNDYuNDljNi44MDIgOC4yNDMgMTEuNTY1IDEwLjcgMTcuNzUyIDEwLjdjMTUuNjk1IDAgMTkuNjEyLTE0LjQyMiAxOS42MTItMzAuOTI3bDI0LjM5My0uNzY2YzAgMTcuMjUzLTMuNCAyOS45My05LjE4NyAzOS45NDZjLTUuNTkxIDkuNjg2LTE2LjQ4OCAxOS4zNjMtMzQuODE4IDE5LjM2M2MtMTEuMzk1IDAtMjEuNDktMi40NzUtMzIuNjU0LTEzLjAwN2MtOC41ODItOC4wODMtMTguNjE1LTIyLjQ0My0yNi4zMzQtMzUuMzUybC0yMi45Ni0zOC4zNTJDMTE4LjUyOCA2NC4wOCAxMDcuOTYgNDkuNzMgMTAxLjg0NSA0My4yM2MtNi41NzgtNi45ODgtMTUuMDM2LTE1LjQyOC0yOC41MzItMTUuNDI4Yy0xMC45MjMgMC0yMC4yIDcuNjY2LTI3Ljk2MyAxOS4zOXoiIC8+Cgk8cGF0aCBmaWxsPSJ1cmwoI2xvZ29zTWV0YUljb24xKSIgZD0iTTczLjMxMiAyNy44MDJjLTEwLjkyMyAwLTIwLjIgNy42NjYtMjcuOTYzIDE5LjM5Yy0xMC45NzYgMTYuNTY4LTE3LjY5OCA0MS4yNDUtMTcuNjk4IDY0Ljk0NGMwIDkuNzc1IDIuMTQ2IDE3LjI4IDQuOTUgMjEuODJMOS4wMjcgMTQ5LjQ4MkMyLjk3MyAxMzkuNDEzIDAgMTI2LjIwMiAwIDExMS4xNDhDMCA4My43NzIgNy41MTQgNTUuMjQgMjEuODAyIDMzLjIwNkMzNC40OCAxMy42NjYgNTIuNzc0IDAgNzMuNzU3IDB6IiAvPgo8L3N2Zz4="
        },
        {
            name: "GitHub",
            type: "url-test",
            interval: 600,
            tolerance: 20,
            url: "http://github.com",
            lazy: false,
            proxies: allProxies,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/github.svg"
        },
        // {
        //     name: "YouTube",
        //     type: "url-test",
        //     interval: 600,
        //     tolerance: 20,
        //     url: "http://youtube.com",
        //     lazy: false,
        //     proxies: allProxies,
        //     icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/youtube.svg"
        // },
        {
            name: "TikTok",
            type: "select",
            url: "http://tiktok.com",
            lazy: false,
            proxies: commonProxyGroups,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/tiktok.svg"
        },
        {
            name: "Claude",
            type: "url-test",
            interval: 600,
            tolerance: 50,
            url: "http://claude.ai",
            lazy: false,
            // 过滤掉包含“香港”或“HK”或“Hong”或“🇭🇰”的节点
            proxies: allProxies.filter(name => !/香港|HK|Hong|🇭🇰/i.test(name)),
            // "include-all": true,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/claude.svg"
        },
        {
            name: "Gemini",
            type: "url-test",
            interval: 600,
            tolerance: 50,
            url: "http://gemini.google.com",
            lazy: false,
            // 过滤掉包含"香港"或"HK"或"Hong"或"🇭🇰"的节点
            proxies: allProxies.filter(name => !/香港|HK|Hong|🇭🇰/i.test(name)),
            // "include-all": true,
            icon: "https://www.gstatic.com/lamda/images/gemini_sparkle_v002_d4735304ff6292a690345.svg"
        },
        {
            name: "Spotify",
            type: "select",
            proxies: commonProxyGroups,
            icon: "https://storage.googleapis.com/spotifynewsroom-jp.appspot.com/1/2020/12/Spotify_Icon_CMYK_Green.png"
        },
        {
            name: "🐟漏网之鱼",
            type: "select",
            proxies: [proxyName, "DIRECT"],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg"
        },
        {
            name: "⛔广告拦截",
            type: "select",
            proxies: ["REJECT", "DIRECT", proxyName],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/block.svg"
        },
    ];

    //autoProxyGroups.length &&
        //groups[2].proxies.push(...autoProxyGroups.map((item) => item.name));
    groups.push(...autoProxyGroups);
    groups.push(...smartProxyGroups);
    groups.push(...manualProxyGroupsConfig);
    params["proxy-groups"] = groups;

}
// 防止 dns 泄露
function overwriteDns(params) {
    const cnDnsList = [
        "https://223.5.5.5/dns-query",
    ];
    const trustDnsList = [
        "tls://1.0.0.1:853",
        "tls://8.8.8.8:853",
        "https://1.0.0.1/dns-query",
        "https://1.1.1.1/dns-query",
    ];

    const dnsOptions = {
        enable: true,
        "prefer-h3": true, // 如果 DNS 服务器支持 DoH3 会优先使用 h3
        //"default-nameserver": ["223.5.5.5", "114.114.114.114", "119.29.29.29"], // 用于解析其他 DNS 服务器、和节点的域名，必须为 IP, 可为加密 DNS。注意这个只用来解析节点和其他的 dns，其他网络请求不归他管
        //nameserver: trustDnsList, // 其他网络请求都归他管
        "cache-algorithm": "arc",
        // 这个用于覆盖上面的 nameserver
        "nameserver-policy": {
            //[combinedUrls]: notionDns,
            //"geosite:cn": cnDnsList,
            //"geo:cn": cnDnsList,
            //"geosite:geolocation-!cn": trustDnsList,
            // 如果你有一些内网使用的 DNS，应该定义在这里，多个域名用英文逗号分割
            // '+. 公司域名.com, www.4399.com, +.baidu.com': '10.0.0.1'
        },
        //fallback: trustDnsList,
        "fallback-filter": {
            geoip: true,
            // 除了 geoip-code 配置的国家 IP, 其他的 IP 结果会被视为污染 geoip-code 配置的国家的结果会直接采用，否则将采用 fallback 结果
            "geoip-code": "CN",
            //geosite 列表的内容被视为已污染，匹配到 geosite 的域名，将只使用 fallback 解析，不去使用 nameserver
            geosite: ["gfw", "geolocation-!cn"],
            ipcidr: ["240.0.0.0/4"],
            domain: ["+.google.com", "+.facebook.com", "+.youtube.com", "+.twitter.com", "+.github.com"],
        },
        "fake-ip-filter": [
            "+.lan",
            "+.local",
            "geosite:cn",
            "geoip:cn",
            "geosite:google",
            "geosite:apple",
            "+.uitz.cc",
            "+.vuitz.cc",
            "anyrouter.top"
        ],
    };

    // GitHub 加速前缀
    const githubPrefix = "https://github.uitz.pro/";
    // const githubPrefix = "";

    // GEO 数据 GitHub 资源原始下载地址
    const rawGeoxURLs = {
        geoip:
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
        geosite:
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
    };

    // 生成带有加速前缀的 GEO 数据资源对象
    const accelURLs = Object.fromEntries(
        Object.entries(rawGeoxURLs).map(([key, githubUrl]) => [
            key,
            `${githubPrefix}${githubUrl}`,
        ])
    );

    const otherOptions = {
        "unified-delay": true,
        "tcp-concurrent": true,
        profile: {
            "store-selected": true,
            "store-fake-ip": true,
        },
        sniffer: {
            enable: true,
            sniff: {
                TLS: {
                    ports: [443, 8443],
                },
                HTTP: {
                    ports: [80, "8080-8880"],
                    "override-destination": true,
                },
                QUIC: {
                    ports: [443, 8443],
                },
            },
        },
        "geodata-mode": true,
        "geox-url": accelURLs,
    };

    params.dns = { ...params.dns, ...dnsOptions };
    Object.keys(otherOptions).forEach((key) => {
        params[key] = otherOptions[key];
    });
}

function getProxiesByRegex(params, regex) {
    const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
    return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
}

function getManualProxiesByRegex(params, regex) {
    const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
    return matchedProxies.length > 0 ? matchedProxies : ["DIRECT", "手动选择", proxyName];
}
