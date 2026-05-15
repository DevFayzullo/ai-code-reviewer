import httpx
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

async def github_request(method: str, url: str, **kwargs) -> dict:
    """
    GitHub API ga authenticated so'rov yuboradi.
    method: "GET", "POST" va h.k.
    url: to'liq API URL
    """
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            timeout=30.0,
            **kwargs
        )
        response.raise_for_status()
        return response.json()


async def get_pr_diff(owner: str, repo: str, pr_number: int) -> str:
    """
    PR dagi o'zgargan kodlarni (diff) olib beradi.
    
    owner: repo egasi (masalan: "microsoft")
    repo: repo nomi (masalan: "vscode")
    pr_number: PR raqami (masalan: 1234)
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    
    # diff format so'rash uchun maxsus header
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, timeout=30.0)
        response.raise_for_status()
        return response.text  # diff matn formatda keladi


async def get_pr_files(owner: str, repo: str, pr_number: int) -> list:
    """
    PR dagi o'zgargan fayllar ro'yxatini oladi.
    Har bir fayl haqida: nomi, qo'shilgan/o'chirilgan qatorlar soni.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
    return await github_request("GET", url)


async def post_pr_comment(owner: str, repo: str, pr_number: int, comment: str) -> dict:
    """
    PR ga review comment yozadi.
    Bu comment GitHub da ko'rinadi.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    return await github_request("POST", url, json={"body": comment})


async def get_repo_language(owner: str, repo: str) -> str:
    """
    Repo asosiy dasturlash tilini aniqlaydi.
    Masalan: "Python", "JavaScript", "Java"
    """
    url = f"https://api.github.com/repos/{owner}/{repo}"
    data = await github_request("GET", url)
    return data.get("language", "Unknown")