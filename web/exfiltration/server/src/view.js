const puppeteer = require('puppeteer');

let url = "";
let auth = "";
if(process.argv.length === 4) {
    auth = process.argv[2];
    url = process.argv[3];
}

(async () => {
    try {
        const browser = await puppeteer.launch({args: ['--disable-extensions', '--no-sandbox', '--disable-setuid-sandbox']});
        const page = await browser.newPage();
        await page.setExtraHTTPHeaders({'Headless-Auth': auth});
        try {
            await page.goto(url, {timeout: 500});
        } catch(e) {
            console.log("JS timed out");
        }
        await page.close();
        await browser.close();
    } catch(e) {
        console.log("Puppeteer failed to run");
    }
})();
