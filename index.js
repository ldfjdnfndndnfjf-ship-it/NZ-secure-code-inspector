const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Serving professional workspace static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// URL Resolution Pipeline mapping absolute pathways
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

    // Enforce valid application protocol prefix structures
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        // High profile desktop User-Agent to bypass primitive bot blockers
        const secureAxiosConfig = {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            },
            timeout: 10000,
            maxRedirects: 5
        };

        // 1. Core DOM Manifest Extraction
        const targetResponse = await axios.get(url, secureAxiosConfig);
        const htmlContext = targetResponse.data;
        const $ = cheerio.load(htmlContext);

        let scriptAssetsCollection = [];
        let styleAssetsCollection = [];

        // 2. Automated Extraction for External JavaScript Assets
        const DOMScriptTags = $('script[src]');
        for (let i = 0; i < DOMScriptTags.length; i++) {
            let assetSrc = $(DOMScriptTags[i]).attr('src');
            let completeAddress = resolveAbsoluteAddress(url, assetSrc);
            
            if (completeAddress && !assetSrc.startsWith('data:')) {
                try {
                    const inlineCodePayload = await axios.get(completeAddress, { timeout: 4000, headers: secureAxiosConfig.headers });
                    scriptAssetsCollection.push({ filename: assetSrc, code: inlineCodePayload.data });
                } catch (err) {
                    scriptAssetsCollection.push({ filename: assetSrc, code: `// Failed secure code connection hook: ${err.message}` });
                }
            }
        }

        // 3. Automated Extraction for Layout CSS Documents
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

        // Returning pristine parsed arrays back to developer workspace frontend 
        res.json({
            html: htmlContext,
            scripts: scriptAssetsCollection,
            styles: styleAssetsCollection
        });

    } catch (ex) {
        res.status(500).json({ error: `Secure Scanner Pipeline Exception: ${ex.message}` });
    }
});

// Environment Listener Adapter configuration
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`[DEVELOPER SYSTEM ACTIVE] Internal Local Terminal Address: http://localhost:${PORT}`));
}

module.exports = app;
