import requests
import csv
import time

# 🔐 GitHub Token (PUT NEW TOKEN HERE)
GITHUB_TOKEN = "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"

# 👤 Org name (FIX THIS)
ORG_NAME = "TMCC-TFS-HYD"

BASE_URL = "https://api.github.com"

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

output_file = "dependabot_cvss_report.csv"


# 📦 Get all repos
def get_repos():
    repos = []
    page = 1

    while True:
        url = f"{BASE_URL}/orgs/{ORG_NAME}/repos?per_page=100&page={page}"
        res = requests.get(url, headers=headers)

        if res.status_code != 200:
            print("❌ Error fetching repos:", res.text)
            break

        data = res.json()

        if not isinstance(data, list) or len(data) == 0:
            break

        repos.extend([repo["name"] for repo in data])
        page += 1

    return repos


# 🔍 Get Dependabot alerts
def get_dependabot_alerts(repo):
    alerts_data = []
    page = 1

    while True:
        url = f"{BASE_URL}/repos/{ORG_NAME}/{repo}/dependabot/alerts?per_page=100&page={page}"
        res = requests.get(url, headers=headers)

        if res.status_code == 404:
            break

        if res.status_code != 200:
            print(f"❌ Error in {repo}:", res.text)
            break

        data = res.json()

        if not isinstance(data, list) or len(data) == 0:
            break

        for alert in data:
            advisory = alert.get("security_advisory", {})
            cvss = advisory.get("cvss", {})

            alerts_data.append({
                "repo": repo,
                "package": alert.get("dependency", {}).get("package", {}).get("name"),
                "ecosystem": alert.get("dependency", {}).get("package", {}).get("ecosystem"),
                "severity": advisory.get("severity"),
                "cvss_score": cvss.get("score"),
                "cvss_vector": cvss.get("vector_string"),
                "summary": advisory.get("summary"),
                "state": alert.get("state")
            })

        page += 1
        time.sleep(0.5)

    return alerts_data


# 🚀 Main
def main():
    all_results = []

    repos = get_repos()
    print(f"Found {len(repos)} repositories")

    for repo in repos:
        print(f"Fetching alerts for {repo}...")
        alerts = get_dependabot_alerts(repo)
        all_results.extend(alerts)

    # Save CSV
    keys = ["repo", "package", "ecosystem", "severity", "cvss_score", "cvss_vector", "summary", "state"]

    with open(output_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"✅ Report saved to {output_file}")


if __name__ == "__main__":
    main()
    