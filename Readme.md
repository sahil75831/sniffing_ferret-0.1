<p align="center">
  <img src="https://github.com/sahil75831/sniffing_ferret-0.1/blob/main/logo.png" width="150" alt="Sniffing Ferret Logo" />
</p>


# 🕵️‍♂️ Sniffing Ferret

**Sniffing Ferret** is a security tool that scans codebases to detect high-entropy strings and potential secret credentials. It helps developers identify and prevent accidental exposure of sensitive information such as API keys, tokens, and passwords.

> 🐧 Currently supported on **Ubuntu**.

---

## 🔧 Features

* Scans directories file by file
* Detects high-entropy strings (suspicious or secret-like values)
* Saves results to a specified output directory
* Lightweight and Docker-based — no need for local installations

---

## 🚀 Getting Started

### 🐳 Pull the Docker Image

```bash
docker pull sahilsharma88765/sniffing_ferret:0.1
```

---

### 📁 Scan a Directory

```bash
input=<Path_of_directory_to_scan> && output=sniffing_ferret && mkdir -p "$output" && docker run --rm \
  -v "$PWD:/$(basename "$PWD")" \
  -v "$PWD/$output:/Sniffing_Ferret" \
  sahilsharma88765/sniffing_ferret:0.1 \
  --dir_path="/$(basename "$PWD")/$input" \
  --entropy=<threshold_value>
```

* `input`: Path to the directory you want to scan (relative to current working directory)
* `output`: Folder to store scan results (defaults to `sniffing_ferret`)
* `--entropy`: Entropy threshold (e.g., 4.5 or 5.0)

---

## 📂 Output

The results will be saved in the `sniffing_ferret/` folder in your working directory. It includes:

* File paths with detected secrets
* Line numbers
* Matching high-entropy strings

---

## 📌 Example

```bash
input=my_project
output=results
mkdir -p "$output"

docker run --rm \
  -v "$PWD:/project" \
  -v "$PWD/$output:/Sniffing_Ferret" \
  sahilsharma88765/sniffing_ferret:0.1 \
  --dir_path="/project/$input" \
  --entropy=4.5
```

---

## 🛠️ System Requirements

* **Ubuntu** (tested and supported)
* Docker installed

---

## 📫 Feedback or Issues?

Please open an issue in this repository for any bug reports, questions, or feature requests.

---

Let me know if you also want a `LICENSE` or `CONTRIBUTING.md` template added.
