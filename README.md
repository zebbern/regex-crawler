<div align="center">

<a href="https://github.com/your-repo/BugBountyCrawler">
   <img src="https://github.com/user-attachments/assets/99f1a4d0-ac60-415c-a61b-4015da390a80" width="30%">
</a>

<kbd>Regex Web Crawler</kbd>

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

 **An advanced web crawler built for bug bounty hunters!**
 
 **Tool recursively crawls a target website, performs regex-based content searches, and saves results in structured YAML files.**
 
 **Includes optional security analysis for reconnaissance.**

---

### `Features:`
<h6>
   
Validate URLs before crawling to prevent errors.

Extract all internal links recursively up to a specified depth.

Perform regex-based searches on each page's content using a user-defined regex list.

Optionally enable advanced security checks such as scanning HTTP headers and HTML comments for potential leaks.

Store all crawled URLs and results in structured YAML format for easy analysis.</h6>

</div>

---

<kbd>How To Run</kbd>

**Step 1: Configure the `config.yaml` file to set up the target URL and crawling options.**  
**Step 2: Run the Python script and let it crawl the target website while extracting valuable information.**  
**Step 3: Review the structured results saved in `results.yaml`.**

## Requirements:
```
requests
beautifulsoup4
pyyaml
```
Install the required dependencies with:
```
pip install -r requirements.txt
```

## Usage:
1. Set up your configuration in `config.yaml`:
   ```yaml
   base_url: "https://example.com"
   crawl_depth: 1
   advanced: true
   regex_file: "regex_patterns.txt"
   output_file: "results.yaml"
   ```
2. Create or edit your regex patterns in `regex_patterns.txt` (one per line):
   ```txt
   (?i)password\s*[:=]\s*['"][^'"]+['"]
   (?i)secret\s*[:=]\s*['"][^'"]+['"]
   ```
3. Run the script:
   ```bash
   python para.py
   ```

## Contribute:
Feel free to suggest improvements or contribute by visiting [https://github.com/zebbern/regex-crawler](https://github.com/zebbern/regex-crawler).

<hr>

> [!WARNING]  
> This tool is intended for ethical hacking and bug bounty purposes only. Unauthorized scanning of third-party websites is illegal and unethical. Always obtain explicit permission before testing any target.

