const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const resolveAbsoluteAddress = (rootUrl, subPath) => {
    try {
        return new URL(subPath, rootUrl).href;
    } catch (e) {
        return null;
    }
};

app.post('/api/fetch-source', async (req, res) => {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: 'System processing aborted: Targeted system URI empty.' });

    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        const secureAxiosConfig = {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            timeout: 12000,
            maxRedirects: 5
        };

        const targetResponse = await axios.get(url, secureAxiosConfig);
        const htmlContext = targetResponse.data;
        const $ = cheerio.load(htmlContext);

        let scriptAssetsCollection = [];
        let styleAssetsCollection = [];
        let discoveredEndpoints = new Set();

        // Regex engine to extract dynamic strings that match API endpoint pattern paths
        const apiPatternRegex = /(https?:\/\/[^\s"'`<>]+|^\/[a-zA-ve-z0-9_-]+\/[a-zA-ve-z0-9_/-]+|\/api\/[a-zA-Z0-9_/-]+)/gi;

        // Scan the core HTML content first for server paths
        let htmlMatches = htmlContext.match(apiPatternRegex);
        if (htmlMatches) {
            htmlMatches.forEach(match => {
                if(match.length > 3 && match.length < 150) discoveredEndpoints.add(match);
            });
        }

        // Processing Scripts
        const DOMScriptTags = $('script[src]');
        for (let i = 0; i < DOMScriptTags.length; i++) {
            let assetSrc = $(DOMScriptTags[i]).attr('src');
            let completeAddress = resolveAbsoluteAddress(url, assetSrc);
            
            if (completeAddress && !assetSrc.startsWith('data:')) {
                try {
                    const inlineCodePayload = await axios.get(completeAddress, { timeout: 4000, headers: secureAxiosConfig.headers });
                    const scriptCode = inlineCodePayload.data;
                    
                    scriptAssetsCollection.push({ filename: assetSrc, code: scriptCode });

                    // Scan deep script content array stream for API signatures
                    let jsMatches = String(scriptCode).match(apiPatternRegex);
                    if(jsMatches) {
                        jsMatches.forEach(match => {
                            if(match.length > 3 && match.length < 150) discoveredEndpoints.add(match);
                        });
                    }
                } catch (err) {
                    scriptAssetsCollection.push({ filename: assetSrc, code: `// Failed secure code connection hook: ${err.message}` });
                }
            }
        }

        // Processing Stylesheets
        const DOMStyleLinks = $('link[rel="stylesheet"]');
        for (let i = 0; i < DOMStyleLinks.length; i++) {
            let assetHref = $(DOMStyleLinks[i]).attr('href');
            let completeAddress = resolveAbsoluteAddress(url, assetHref);
            
            if (completeAddress && !assetHref.startsWith('data:')) {
                try {
                    const inlineCssPayload = await axios.get(completeAddress, { timeout: 4000, headers: secureAxiosConfig.headers });
                    styleAssetsCollection.push({ filename: assetHref, code: inlineCssPayload.data });
                } catch (err) {
                    styleAssetsCollection.push({ filename: assetHref, code: `/* Failed secure layout connection hook: ${err.message} */` });
                }
            }
        }

        res.json({
            html: htmlContext,
            scripts: scriptAssetsCollection,
            styles: styleAssetsCollection,
            endpoints: Array.from(discoveredEndpoints)
        });

    } catch (ex) {
        res.status(500).json({ error: `Secure Scanner Pipeline Exception: ${ex.message}` });
    }
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`[DEVELOPER SYSTEM ACTIVE] Address: http://localhost:${PORT}`));
}

module.exports = app;
