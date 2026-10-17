# Publish on GitHub (one-time, about 15 minutes)

## 1. Create the repository

1. github.com → **+** → **New repository**
2. Name: **`rhel-cis-benchmark`** · Public · leave every "Add …" box unchecked → **Create repository**

## 2. Upload the code

On your computer, in the unzipped folder:

```bash
# put your GitHub username in the links (macOS: use  sed -i ''  )
grep -rl YOUR_GITHUB_USER . | xargs sed -i 's/YOUR_GITHUB_USER/your-username/g'
grep -rl YOUR_NAME . | xargs sed -i 's/YOUR_NAME/Your Name/g'

git init -b main
git add .
git commit -m "CIS Benchmark for RHEL 8, 9 and 10"
git remote add origin https://github.com/your-username/rhel-cis-benchmark.git
git push -u origin main
```

## 3. Publish the downloads (creates cis-rhel8/9/10.tar.gz)

```bash
git tag v1.0.0
git push origin v1.0.0
```

Wait about 1 minute. **Releases** now shows `v1.0.0` with the three downloads, and the download
links in the README work.

## 4. Make it easy to find on Google and GitHub

1. Repository page → ⚙ next to **About**:
   - **Description:** `CIS Benchmark hardening for RHEL 8, RHEL 9 and RHEL 10 (Rocky, Alma) - one-command Ansible playbook`
   - **Topics:** `cis-benchmark` `cis` `rhel` `rhel8` `rhel9` `rhel10` `red-hat` `rocky-linux` `almalinux` `ansible` `ansible-playbook` `hardening` `security` `compliance`
2. **Settings → General → Social preview:** upload a simple image with the text
   *"CIS Benchmark — RHEL 8 · 9 · 10"*.
3. Turn on a website for extra Google visibility: **Settings → Pages → Source: Deploy from branch → main / (root) → Save.**
   GitHub publishes the README at `https://your-username.github.io/rhel-cis-benchmark/`.
4. Submit that address in **Google Search Console** (search.google.com/search-console) →
   **URL inspection → Request indexing**.
5. Tell people: a short post on LinkedIn, Reddit (r/redhat, r/linuxadmin, r/ansible) and dev.to
   such as *"How to apply the CIS Benchmark to RHEL 9 in one command"* linking to the repo.
   Links from other sites are what push a page up in Google results.

> Google usually indexes a new repository within days to a few weeks. Ranking near the top for
> searches like "CIS benchmark RHEL 9" depends on stars, links and activity over time.

## 5. Each new version

Update, then:

```bash
git commit -am "Describe the change"
git tag v1.1.0 && git push && git push origin v1.1.0
```

The downloads in the README always point to the latest release automatically.
