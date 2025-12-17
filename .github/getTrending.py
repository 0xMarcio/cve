#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import requests
import json
from datetime import datetime


def time_ago(datetime_str):
    datetime_obj = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%SZ")
    current_datetime = datetime.now()
    delta = current_datetime - datetime_obj
    if delta.days > 0:
        if delta.days == 1:
            return "1 day ago"
        else:
            return f"{delta.days} days ago"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        if hours == 1:
            return "1 hour ago"
        else:
            return f"{hours} hours ago"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        if minutes == 1:
            return "1 minute ago"
        else:
            return f"{minutes} minutes ago"
    else:
        return "just now"

current_year = datetime.now().year
total_repos_per_year = {}
#tz_header = {"Time-Zone": "Europe/Amsterdam"}

repositories_by_year = {}
for year in range(current_year, current_year - 5, -1):
    year_repositories = []
    print(f"Fetching data for {year}")
    response = requests.get(f'https://api.github.com/search/repositories?q=%22CVE-{year}%22%20in:name%20%20stars:>2%20language:Shell%20language:Go%20language:ASP%20language:WebAssembly%20language:R%20language:Lua%20language:Python%20%20%20language:C++%20language:C%20language:JavaScript%20language:Perl%20language:PowerShell%20language:Ruby%20language:Rust%20language:Java%20%20language:PHP&s=updated&o=desc&page=1&per_page=20')
    if response.status_code != 200:
        print(f"Failed to fetch data for year {year}: {response.status_code}")
        continue

    data = response.json()
    total_count = data.get("total_count", 0)
    print(f"Found: {total_count}")
    total_repos_per_year[year] = total_count
    if "items" in data:
        items = data["items"]
        if items:
            year_repositories.extend(items)
        else:
            print(f"No more items found for year {year}")

    if year_repositories:
        # Sort the repositories by stargazers_count in descending order
        #year_repositories.sort(key=lambda repo: repo['stargazers_count'], reverse=True)
        repositories_by_year[year] = year_repositories

# Define a class to handle repository information
class RepositoryInfo:
    def __init__(self, description, stargazers_count, name, html_url, updated_at):
        self.description = description
        self.stargazers_count = stargazers_count
        self.name = name
        self.html_url = html_url
        self.updated_at = updated_at

    def __hash__(self):
        return hash(self.name + self.html_url)

    def __eq__(self, other):
        return self.html_url == other.html_url and self.name == other.name

final_output = ['<h1 align="center">Recently updated Proof-of-Concepts</h1>']
for year in range(current_year, current_year - 5, -1):
    if year in repositories_by_year:
        year_repositories = repositories_by_year[year]
        year_repositories = [RepositoryInfo(repo["description"], repo["stargazers_count"], repo["name"], repo["html_url"], repo["updated_at"]) for repo in year_repositories]

        final_output.append(f"\n\n## {year}\n")
        final_output.append(f"### Latest 20 of {total_repos_per_year[year]} Repositories\n")
        final_output.append("| Stars | Updated | Name | Description |")
        final_output.append("| --- | --- | --- | --- |")

        for repo in year_repositories:
            try:
                description = repo.description or ""
                updated = time_ago(repo.updated_at)
                final_output.append(f"| {repo.stargazers_count}⭐ | {updated} | [{repo.name}]({repo.html_url}) | {description} |")
            except Exception as e:
                print(f"Error generating final output for repository {repo.name}: {e}")
                pass

if repositories_by_year:
    with open("README.md", "w", encoding="utf-8") as file:
        file.write("\n".join(final_output))
    print("Final output written to README.md")
