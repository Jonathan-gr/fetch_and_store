import matplotlib.pyplot as plt
from fastapi.responses import FileResponse


def draw_cvss_v3_distribution(df):
    plt.figure(figsize=(8,5))
    plt.hist(df["cvss_v3_score"].dropna(), bins=10, edgecolor="black")
    plt.xlabel("CVSS v3 Score")
    plt.ylabel("Count")
    plt.title("Distribution of CVSS v3 Scores")

    graph_path = "static/cvss_v3_distribution.png"
    plt.savefig(graph_path)
    plt.close()
    return FileResponse(graph_path)