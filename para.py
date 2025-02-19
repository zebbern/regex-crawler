#!/usr/bin/env python3
import os
import re
import sys
import yaml
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def load_config(filename):
    """Load configuration from a YAML file."""
    with open(filename, "r") as file:
        config = yaml.safe_load(file)
    return config

def load_regex_patterns(filename):
    """Load regex patterns from a file, one per line (ignoring comments and blank lines)."""
    patterns = []
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns

def validate_url(url):
    """Validate the URL ensuring it has http(s) scheme and a network location."""
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)

class Crawler:
    def __init__(self, base_url, max_depth, regex_patterns, advanced):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited = set()
        self.regex_patterns = regex_patterns
        self.results = {}         # Will store regex matches and any advanced info per URL
        self.crawled_urls = []    # List of all full URLs that were crawled
        self.advanced = advanced

    def crawl(self, url, depth=0):
        """Recursively crawl the given URL up to the maximum depth."""
        if depth > self.max_depth:
            return
        if url in self.visited:
            return

        print(f"[+] Crawling: {url} (depth: {depth})")
        self.visited.add(url)
        self.crawled_urls.append(url)

        try:
            response = requests.get(url, timeout=10)
            content = response.text
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return

        # Apply regex search on the page content.
        self.results[url] = self.search_regex(content)

        # If advanced analysis is enabled, collect additional information.
        if self.advanced:
            self.results[url]['advanced'] = self.advanced_analysis(url, response)

        # Extract links and crawl further if the current depth allows it.
        if depth < self.max_depth:
            for link in self.extract_links(url, content):
                self.crawl(link, depth + 1)

    def extract_links(self, base, content):
        """Extract and validate all links from the HTML content."""
        links = set()
        soup = BeautifulSoup(content, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            full_url = urljoin(base, href)
            if validate_url(full_url):
                links.add(full_url)
        return links

    def search_regex(self, content):
        """Search the content using each regex pattern and return the findings."""
        matches = {}
        for pattern in self.regex_patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as e:
                print(f"[-] Invalid regex pattern '{pattern}': {e}")
                continue
            found = compiled.findall(content)
            if found:
                matches[pattern] = found
        return matches

    def advanced_analysis(self, url, response):
        """
        Perform advanced analysis on the response.
        Example checks include:
          - Extracting the Server header
          - Searching for HTML comments that might leak sensitive information
        """
        advanced_info = {}
        # Check for the Server HTTP header.
        advanced_info["server_header"] = response.headers.get("Server", "Unknown")
        # Look for HTML comments.
        comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
        if comments:
            advanced_info["html_comments"] = comments
        return advanced_info

def main():
    # Load configuration.
    config_file = "config.yaml"
    if not os.path.exists(config_file):
        print("[-] Missing config.yaml file!")
        sys.exit(1)
    config = load_config(config_file)
    base_url = config.get("base_url")
    max_depth = config.get("crawl_depth", 1)
    advanced = config.get("advanced", False)
    regex_file = config.get("regex_file", "regex_patterns.txt")
    output_file = config.get("output_file", "results.yaml")

    # Validate the base URL.
    if not validate_url(base_url):
        print("[-] Invalid base_url in config file!")
        sys.exit(1)
    if not os.path.exists(regex_file):
        print(f"[-] Missing regex file: {regex_file}")
        sys.exit(1)

    # Load regex patterns.
    regex_patterns = load_regex_patterns(regex_file)

    # Initialize and start the crawler.
    crawler = Crawler(base_url, max_depth, regex_patterns, advanced)
    crawler.crawl(base_url)

    # Save the results in a structured YAML format.
    output_data = {
        "results": crawler.results,
        "crawled_urls": crawler.crawled_urls
    }
    with open(output_file, "w") as f:
        yaml.dump(output_data, f, default_flow_style=False)

    print(f"[+] Crawling finished. Results saved to {output_file}")

if __name__ == "__main__":
    main()
