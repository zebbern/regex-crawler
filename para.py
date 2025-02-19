#!/usr/bin/env python3
import os
import re
import sys
import yaml
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

def load_config(filename):
    """Load configuration from a YAML file."""
    with open(filename, "r") as file:
        config = yaml.safe_load(file)
    return config

def load_regex_patterns(filename):
    """Load regex patterns from a file (ignoring comments and blank lines)."""
    patterns = []
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns

def validate_url(url):
    """
    Validate the URL ensuring it has http(s) scheme and a network location.
    (This doesn't yet check the domain; see is_same_or_subdomain for domain scope.)
    """
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)

def is_same_or_subdomain(base_host, candidate_host):
    """
    Check if candidate_host is the same domain or a subdomain of base_host.

    Examples:
      base_host = "example.com"
      candidate_host = "sub.example.com"  -> True
      candidate_host = "example.com"      -> True
      candidate_host = "google.com"       -> False
    """
    base_host = base_host.lower()
    candidate_host = candidate_host.lower()
    return (candidate_host == base_host) or candidate_host.endswith("." + base_host)

def extract_query_params(url):
    """
    Extract query parameter keys from a URL.
    Useful for enumerating potential injection points (XSS, SQLi, etc.).
    """
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query)
    # parse_qs returns a dict {param_name: [value1, value2, ...], ...}
    return list(query_dict.keys())

class Crawler:
    def __init__(self, base_url, max_depth, regex_patterns, advanced):
        self.base_url = base_url
        self.max_depth = max_depth
        self.regex_patterns = regex_patterns
        self.advanced = advanced

        # Determine the base host domain from base_url
        self.base_host = urlparse(base_url).netloc.lower()

        self.visited = set()
        self.crawled_urls = []

        # results[url] = {
        #   "matches": {
        #       pattern: [found1, found2, ...],
        #       ...
        #   },
        #   "advanced": {
        #       "server_header": "...",
        #       "html_comments": [...],
        #       "query_params": [...]
        #   }
        # }
        self.results = {}

    def crawl(self, url, depth=0):
        """Recursively crawl the given URL up to the maximum depth."""
        if depth > self.max_depth:
            return
        if url in self.visited:
            return

        self.visited.add(url)
        self.crawled_urls.append(url)

        print(f"[+] Crawling: {url} (depth={depth})")

        try:
            response = requests.get(url, timeout=10)
            content = response.text
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return

        # Initialize result structure for this URL
        self.results[url] = {"matches": {}}

        # Apply regex search on the page content
        found_matches = self.search_regex(content)
        if found_matches:
            self.results[url]["matches"] = found_matches

        # If advanced analysis is enabled, collect additional information
        if self.advanced:
            adv_info = self.advanced_analysis(url, response)
            if adv_info:
                self.results[url]["advanced"] = adv_info

        # Extract links and crawl further if within allowed depth
        if depth < self.max_depth:
            for link in self.extract_links(url, content):
                self.crawl(link, depth + 1)

    def extract_links(self, base, content):
        """Extract and validate all links from the HTML content, restricting to base domain/subdomains."""
        soup = BeautifulSoup(content, "html.parser")
        raw_links = {a.get("href") for a in soup.find_all("a", href=True)}

        valid_links = set()
        for href in raw_links:
            full_url = urljoin(base, href)
            if validate_url(full_url):
                parsed = urlparse(full_url)
                # Check domain scope
                if is_same_or_subdomain(self.base_host, parsed.netloc):
                    valid_links.add(full_url)
        return valid_links

    def search_regex(self, content):
        """Search the content with each regex pattern and return the findings."""
        matches = {}
        for pattern in self.regex_patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as e:
                print(f"[-] Invalid regex '{pattern}': {e}")
                continue
            found = compiled.findall(content)
            if found:
                # Deduplicate and sort the found items
                unique_found = sorted(list(set(found)))
                matches[pattern] = unique_found
        return matches

    def advanced_analysis(self, url, response):
        """
        Perform advanced analysis on the response:
          - Extract the Server header
          - Search for HTML comments
          - List query parameters from the URL
        """
        advanced_info = {}
        # Check for the Server HTTP header
        advanced_info["server_header"] = response.headers.get("Server", "Unknown")

        # Look for HTML comments
        comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
        if comments:
            unique_comments = sorted(list({c.strip() for c in comments if c.strip()}))
            if unique_comments:
                advanced_info["html_comments"] = unique_comments

        # Potential injection points (query parameters)
        query_params = extract_query_params(url)
        if query_params:
            advanced_info["query_params"] = query_params

        return advanced_info

def generate_summary(results):
    """
    Generate a summary section that highlights:
      - URLs with any regex matches
      - Patterns found
      - Potentially interesting query parameters, etc.
    """
    summary = {"important_finds": []}

    for url, data in results.items():
        entry = {"url": url}

        # If we have matches
        if data.get("matches"):
            entry["regex_matches"] = data["matches"]

        # If we have advanced data
        if "advanced" in data:
            adv = data["advanced"]
            if adv.get("server_header") and adv["server_header"] != "Unknown":
                entry["server_header"] = adv["server_header"]
            if adv.get("html_comments"):
                entry["html_comments"] = adv["html_comments"]
            if adv.get("query_params"):
                entry["query_params"] = adv["query_params"]

        # Only add to the summary if there's something interesting
        if len(entry) > 1:
            summary["important_finds"].append(entry)

    return summary

def generate_sorted_results(results):
    """
    Create a structure that aggregates all regex matches by pattern (with URLs).

    sorted_output = {
      "patterns": [
        {
          "pattern": <pattern_str>,
          "total_unique_matches": <int>,
          "matches": {
            <found_string>: [url1, url2, ...],
            ...
          }
        },
        ...
      ]
    }
    """
    pattern_dict = {}

    for url, data in results.items():
        matches = data.get("matches", {})
        for pattern, found_list in matches.items():
            if pattern not in pattern_dict:
                pattern_dict[pattern] = {}
            for found_item in found_list:
                pattern_dict[pattern].setdefault(found_item, set())
                pattern_dict[pattern][found_item].add(url)

    # Build the final list structure
    sorted_output = []
    for pattern_str, found_map in pattern_dict.items():
        # Sort the found items
        sorted_found_items = sorted(found_map.keys())
        # Build the item structure
        pattern_entry = {
            "pattern": pattern_str,
            "total_unique_matches": len(found_map),
            "matches": {}
        }
        for item in sorted_found_items:
            pattern_entry["matches"][item] = sorted(list(found_map[item]))
        sorted_output.append(pattern_entry)

    # Sort patterns by pattern string
    sorted_output.sort(key=lambda x: x["pattern"])

    return {"patterns": sorted_output}

def generate_no_url_results(results):
    """
    Create a structure that aggregates all regex matches by pattern,
    but excludes URLs. (Deduplicates the matched strings across all pages.)

    Example structure:
    {
      "patterns": [
        {
          "pattern": <pattern_str>,
          "total_unique_matches": <int>,
          "matches": [foundString1, foundString2, ...]
        },
        ...
      ]
    }
    """
    pattern_dict = {}

    for url, data in results.items():
        matches = data.get("matches", {})
        for pattern, found_list in matches.items():
            # Collect all matched strings for each pattern (no URLs)
            if pattern not in pattern_dict:
                pattern_dict[pattern] = set()
            for found_item in found_list:
                pattern_dict[pattern].add(found_item)

    # Build the final list structure
    sorted_output = []
    for pattern_str, found_items in pattern_dict.items():
        # Sort the found items
        sorted_items = sorted(found_items)
        sorted_output.append({
            "pattern": pattern_str,
            "total_unique_matches": len(sorted_items),
            "matches": sorted_items
        })

    # Sort patterns by pattern string
    sorted_output.sort(key=lambda x: x["pattern"])

    return {"patterns": sorted_output}

def main():
    # Load configuration
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
    sorted_output_file = config.get("sorted_output_file", "results-sorted.yaml")
    nourl_output_file = config.get("nourl_output_file", "resultsnourl.yaml")  # new file

    # Validate the base URL
    if not validate_url(base_url):
        print("[-] Invalid base_url in config!")
        sys.exit(1)

    # Check if regex file exists
    if not os.path.exists(regex_file):
        print(f"[-] Missing regex file: {regex_file}")
        sys.exit(1)

    # Load regex patterns
    regex_patterns = load_regex_patterns(regex_file)

    # Initialize and start the crawler
    crawler = Crawler(base_url, max_depth, regex_patterns, advanced)
    crawler.crawl(base_url)

    # Deduplicate crawled URLs (and sort them)
    unique_crawled_urls = sorted(list(set(crawler.crawled_urls)))

    # 1) Generate normal summary for the main results.yaml
    summary = generate_summary(crawler.results)

    # 2) Prepare the main output data
    main_output_data = {
        "summary": summary,                # Quick overview
        "all_crawled_urls": unique_crawled_urls,
        "detailed_results": crawler.results
    }

    # Save the main output
    with open(output_file, "w") as f:
        yaml.dump(main_output_data, f, default_flow_style=False, sort_keys=False)
    print(f"[+] Detailed results saved to '{output_file}'.")

    # 3) Generate and save the sorted/aggregated regex results (with URLs)
    sorted_regex_data = generate_sorted_results(crawler.results)
    with open(sorted_output_file, "w") as f:
        yaml.dump(sorted_regex_data, f, default_flow_style=False, sort_keys=False)
    print(f"[+] Sorted/aggregated regex results saved to '{sorted_output_file}'.")

    # 4) Generate and save the NO-URL regex results (just patterns & unique matches)
    no_url_results = generate_no_url_results(crawler.results)
    with open(nourl_output_file, "w") as f:
        yaml.dump(no_url_results, f, default_flow_style=False, sort_keys=False)
    print(f"[+] No-URL regex results saved to '{nourl_output_file}'.")

if __name__ == "__main__":
    main()
