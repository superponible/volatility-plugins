Volatility Plugins
==================

Plugins I've made:

uninstallinfo.py - Dumps HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall from memory

prefetch.py - scan memory for prefetch files and dump filename and timestamps

idxparser.py - scan memory Java IDX files and extract details

firefoxhistory.py - firefoxhistory, firefoxcookies, and firefoxdownloads plugins to extract the following firefox history data: 
moz_places, 
moz_cookies, and
moz_downloads 

chromehistory.py - chromehistory, chromevisits, chromesearchterms, chromedownloads, chromedownloadchains, and chromecookies plugins to extract Chrome SQLite artifacts

sqlite_help.py - supporting functions SQLite used in Firefox and Chrome plugins

trustrecords.py - extract Office TrustRecords registry key information

ssdeepscan.py - like yarascan, but searches for pages matching an ssdeep hash

malfinddeep.py - whitelist code found by malfind based on an ssdeep hash

apihooksdeep.py - whitelist code found by apihooks based on an ssdeep hash
