from pathlib import Path

from .shared import read_communities


def main():
    communities = read_communities(Path("communities.json"))
    for i, item in enumerate(communities):
        print(i, item["rent_id"], item["address"], item["price"])


if __name__ == "__main__":
    main()
