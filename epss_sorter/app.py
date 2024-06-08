import requests
import json
import pandas as pd
import matplotlib.pyplot as plt
from flask import Flask, render_template, request
import random

app = Flask(__name__)

def fetch_descriptions(cves):
    descriptions = {}
    for cve in cves:
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        req = requests.get(url=api_url)
        if req.status_code == 200:
            data = json.loads(req.text)
            if data.get("vulnerabilities"):
                cve_desc = data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
                descriptions[cve] = cve_desc
            else:
                descriptions[cve] = "Description not found."
        else:
            descriptions[cve] = "Description could not be fetched."
    return descriptions

def fetch_epss_scores(cves):
    epss_scores = {}
    for cve in cves:
        response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve}")
        if response.status_code == 200:
            data = response.json()
            if data['data']:
                epss_scores[cve] = data['data'][0]['epss']
            else:
                epss_scores[cve] = 0.0
        else:
            epss_scores[cve] = 0.0
    return epss_scores

def plot_graph(df):
    plt.figure(figsize=(12, 8))
    colors = ['red', 'orange', 'yellow', 'green', 'blue', 'indigo', 'violet']
    for index, row in df.iterrows():
        plt.bar(row['cve'], row['epss'], color=random.choice(colors))
    plt.xlabel('CVE', fontsize=12)
    plt.ylabel('EPSS Score', fontsize=12)
    plt.title('Selected CVEs EPSS Scores', fontsize=14)
    plt.xticks(rotation=45, ha='right', fontsize=10)
    plt.yticks(fontsize=10)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('static/epss_scores.png')
    plt.close()

@app.route('/')
def index():
    cves = [f"CVE-2023-{str(i).zfill(4)}" for i in range(99, -1, -1)]
    return render_template('index.html', cves=cves)

@app.route('/get_scores', methods=['POST'])
def get_scores():
    selected_cves = request.form.getlist('cve')
    manual_cves = request.form.get('manual_cves').split(',')
    manual_cves = [cve.strip() for cve in manual_cves if cve.strip()]
    all_cves = selected_cves + manual_cves
    if not all_cves:
        return "No CVEs selected or entered manually."

    epss_data = fetch_epss_scores(all_cves)
    
    df = pd.DataFrame(list(epss_data.items()), columns=['cve', 'epss'])
    df['epss'] = df['epss'].astype(float)
    df_sorted = df.sort_values(by='epss', ascending=False)
    
    descriptions = fetch_descriptions(all_cves)
    df_sorted['description'] = df_sorted['cve'].map(descriptions)
    
    if not df_sorted.empty:
        plot_graph(df_sorted)
    
    return render_template('results.html', tables=[df_sorted.to_html(index=False, escape=False, classes='table table-striped table-hover', justify='center', border=2, col_space=100)], titles=df_sorted.columns.values)

if __name__ == '__main__':
    app.run(debug=True)
