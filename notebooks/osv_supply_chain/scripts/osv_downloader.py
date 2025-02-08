import requests
import zipfile
import os
from pathlib import Path
import logging

# Set up basic logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def create_directory(path: str) -> None:
    """
    Create a directory if it doesn't exist.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    logging.info(f"Directory ensured: {p}")


def download_file(url: str, local_path: str) -> None:
    """
    Download a file from the specified URL to a local path.
    """
    headers = {
        "User-Agent": "TypeError/vuln-data-science (https://github.com/TypeError/vuln-data-science)"
    }
    with requests.get(url, stream=True, headers=headers) as response:
        response.raise_for_status()
        with open(local_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    logging.info(f"Downloaded: {local_path}")


def extract_zip(zip_path: str, extract_to: str) -> None:
    """
    Extract a ZIP file to the specified directory and remove the ZIP file.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)
        os.remove(zip_path)
        logging.info(f"Extracted to: {extract_to} and removed ZIP file.")
    except zipfile.BadZipFile as e:
        logging.error(f"Bad ZIP file {zip_path}: {e}")
        raise


def download_and_extract_osv(ecosystem: str, base_dir: str = "./data") -> None:
    """
    Download and extract OSV data for a given ecosystem.
    """
    output_dir = Path(base_dir) / ecosystem
    create_directory(output_dir)

    url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    local_zip = output_dir / "all.zip"

    download_file(url, str(local_zip))
    extract_zip(str(local_zip), str(output_dir))


if __name__ == "__main__":
    base_data_dir = "./data/osv/raw"
    ecosystems = [
        "CRAN",  # R packages
        "crates.io",  # Rust packages
        "Go",  # Go modules
        "Hackage",  # Haskell packages
        "Hex",  # Elixir/Erlang packages
        "Maven",  # Java packages
        "npm",  # JavaScript/Node.js packages
        "NuGet",  # .NET packages
        "Packagist",  # PHP packages
        "Pub",  # Dart packages
        "PyPI",  # Python packages
        "RubyGems",  # Ruby packages
    ]

    create_directory(base_data_dir)

    for ecosystem in ecosystems:
        try:
            download_and_extract_osv(ecosystem, base_data_dir)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading {ecosystem}: {e}")
        except zipfile.BadZipFile as e:
            logging.error(f"Error extracting {ecosystem}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error for {ecosystem}: {e}")
