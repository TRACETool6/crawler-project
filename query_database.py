import sqlite3
import json
from tabulate import tabulate

LABELING_DB_PATH = "labeling_db.sqlite"


def view_summary():
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print("LABELING PIPELINE SUMMARY")
    print("="*80)
    
    c.execute("SELECT COUNT(*) FROM RepositoryLabels")
    total_repos = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM RepositoryLabels WHERE is_malicious = 1")
    malicious_repos = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM RepositoryLabels WHERE is_malicious = 0")
    benign_repos = c.fetchone()[0]
    
    c.execute("SELECT SUM(total_files), SUM(malicious_files) FROM RepositoryLabels")
    total_files, total_malicious_files = c.fetchone()
    
    print(f"Total Repositories Labeled: {total_repos}")
    print(f"Malicious Repositories: {malicious_repos}")
    print(f"Benign Repositories: {benign_repos}")
    print(f"Total Files Scanned: {total_files or 0}")
    print(f"Total Malicious Files: {total_malicious_files or 0}")
    
    conn.close()


def view_all_repos():
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print("ALL REPOSITORY LABELS")
    print("="*80 + "\n")
    
    c.execute("""
        SELECT repo_name, total_files, malicious_files, suspicious_files, 
               file_level_score, final_consensus_score, is_malicious
        FROM RepositoryLabels
        ORDER BY file_level_score DESC
    """)
    
    rows = c.fetchall()
    headers = ["Repository", "Total Files", "Malicious", "Suspicious", 
               "File Score", "LLM Score", "Malicious?"]
    
    formatted_rows = []
    for row in rows:
        repo_name, total, mal, sus, file_score, llm_score, is_mal = row
        formatted_rows.append([
            repo_name[:40],
            total,
            mal,
            sus,
            f"{file_score:.2f}" if file_score else "N/A",
            f"{llm_score:.2f}" if llm_score else "N/A",
            "YES" if is_mal else "NO"
        ])
    
    print(tabulate(formatted_rows, headers=headers, tablefmt="grid"))
    
    conn.close()


def view_malicious_repos():
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print("MALICIOUS REPOSITORIES")
    print("="*80 + "\n")
    
    c.execute("""
        SELECT repo_name, malicious_files, total_files, file_level_score, 
               final_consensus_score
        FROM RepositoryLabels
        WHERE is_malicious = 1
        ORDER BY malicious_files DESC
    """)
    
    rows = c.fetchall()
    
    if not rows:
        print("No malicious repositories found.")
        conn.close()
        return
    
    headers = ["Repository", "Malicious Files", "Total Files", "File Score", "LLM Score"]
    
    formatted_rows = []
    for row in rows:
        repo_name, mal_files, total, file_score, llm_score = row
        formatted_rows.append([
            repo_name[:50],
            f"{mal_files}/{total}",
            total,
            f"{file_score:.2f}",
            f"{llm_score:.2f}" if llm_score else "N/A"
        ])
    
    print(tabulate(formatted_rows, headers=headers, tablefmt="grid"))
    
    conn.close()


def view_repo_details(repo_name):
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print(f"REPOSITORY DETAILS: {repo_name}")
    print("="*80 + "\n")
    
    c.execute("""
        SELECT total_files, malicious_files, suspicious_files, clean_files,
               file_level_score, llm_agent1_score, llm_agent2_score, 
               final_consensus_score, is_malicious, llm_agent1_reasoning,
               llm_agent2_reasoning, final_consensus_reasoning
        FROM RepositoryLabels
        WHERE repo_name = ?
    """, (repo_name,))
    
    repo_data = c.fetchone()
    
    if not repo_data:
        print(f"Repository '{repo_name}' not found.")
        conn.close()
        return
    
    (total, mal, sus, clean, file_score, agent1_score, agent2_score, 
     consensus_score, is_mal, agent1_reasoning, agent2_reasoning, consensus_reasoning) = repo_data
    
    print(f"Status: {'MALICIOUS' if is_mal else 'BENIGN'}")
    print(f"\nFile Statistics:")
    print(f"  Total Files: {total}")
    print(f"  Malicious Files: {mal}")
    print(f"  Suspicious Files: {sus}")
    print(f"  Clean Files: {clean}")
    print(f"\nScores:")
    print(f"  File-Level Score: {file_score:.2f}/10")
    if agent1_score:
        print(f"  LLM Agent 1 Score: {agent1_score:.2f}/10")
    if agent2_score:
        print(f"  LLM Agent 2 Score: {agent2_score:.2f}/10")
    if consensus_score:
        print(f"  Final Consensus Score: {consensus_score:.2f}/10")
    
    c.execute("""
        SELECT file_path, vt_malicious_count, vt_suspicious_count, 
               detection_names, is_malicious
        FROM FileLabels
        WHERE repo_name = ?
        ORDER BY vt_malicious_count DESC
    """, (repo_name,))
    
    file_data = c.fetchall()
    
    print(f"\nFile Scan Results ({len(file_data)} files):")
    
    malicious_files = [f for f in file_data if f[4]]
    
    if malicious_files:
        print("\n  Malicious Files:")
        for file_path, mal_count, sus_count, detections, _ in malicious_files[:10]:
            print(f"    - {file_path}")
            print(f"      Detections: {mal_count} malicious, {sus_count} suspicious")
            if detections:
                detection_list = json.loads(detections)[:3]
                for det in detection_list:
                    print(f"        {det}")
    
    if agent1_reasoning:
        print(f"\nLLM Agent 1 Analysis:")
        print(f"  {agent1_reasoning[:500]}...")
    
    if agent2_reasoning:
        print(f"\nLLM Agent 2 Analysis:")
        print(f"  {agent2_reasoning[:500]}...")
    
    if consensus_reasoning:
        print(f"\nFinal Consensus:")
        print(f"  {consensus_reasoning[:500]}...")
    
    conn.close()


def view_file_detections(limit=20):
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print(f"TOP {limit} MALICIOUS FILES")
    print("="*80 + "\n")
    
    c.execute("""
        SELECT repo_name, file_path, vt_malicious_count, vt_suspicious_count,
               detection_names
        FROM FileLabels
        WHERE is_malicious = 1
        ORDER BY vt_malicious_count DESC
        LIMIT ?
    """, (limit,))
    
    rows = c.fetchall()
    
    if not rows:
        print("No malicious files found.")
        conn.close()
        return
    
    for i, (repo, file_path, mal_count, sus_count, detections) in enumerate(rows, 1):
        print(f"{i}. {repo}/{file_path}")
        print(f"   Malicious: {mal_count}, Suspicious: {sus_count}")
        if detections:
            detection_list = json.loads(detections)[:3]
            print(f"   Detections: {', '.join(detection_list)}")
        print()
    
    conn.close()


def view_processing_status():
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*80)
    print("PROCESSING STATUS")
    print("="*80 + "\n")
    
    c.execute("""
        SELECT status, COUNT(*) 
        FROM ProcessingStatus 
        GROUP BY status
    """)
    
    status_counts = c.fetchall()
    
    for status, count in status_counts:
        print(f"{status}: {count}")
    
    c.execute("""
        SELECT repo_name, error_message 
        FROM ProcessingStatus 
        WHERE status = 'failed' AND error_message IS NOT NULL
        LIMIT 10
    """)
    
    failed = c.fetchall()
    
    if failed:
        print("\nRecent Failures:")
        for repo, error in failed:
            print(f"  - {repo}: {error[:80]}")
    
    conn.close()


def export_to_csv():
    import csv
    
    conn = sqlite3.connect(LABELING_DB_PATH)
    c = conn.cursor()
    
    c.execute("""
        SELECT repo_name, total_files, malicious_files, suspicious_files, 
               clean_files, file_level_score, final_consensus_score, is_malicious
        FROM RepositoryLabels
    """)
    
    rows = c.fetchall()
    
    with open('labeling_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Repository', 'Total Files', 'Malicious Files', 'Suspicious Files',
                        'Clean Files', 'File Score', 'LLM Score', 'Is Malicious'])
        writer.writerows(rows)
    
    print(f"\nExported {len(rows)} repositories to labeling_results.csv")
    
    conn.close()


def interactive_menu():
    while True:
        print("\n" + "="*80)
        print("LABELING RESULTS QUERY TOOL")
        print("="*80)
        print("\n1. View Summary")
        print("2. View All Repositories")
        print("3. View Malicious Repositories Only")
        print("4. View Repository Details (by name)")
        print("5. View Top Malicious Files")
        print("6. View Processing Status")
        print("7. Export Results to CSV")
        print("8. Exit")
        
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == '1':
            view_summary()
        elif choice == '2':
            view_all_repos()
        elif choice == '3':
            view_malicious_repos()
        elif choice == '4':
            repo_name = input("Enter repository name: ").strip()
            view_repo_details(repo_name)
        elif choice == '5':
            limit = input("How many files to show? (default 20): ").strip()
            limit = int(limit) if limit.isdigit() else 20
            view_file_detections(limit)
        elif choice == '6':
            view_processing_status()
        elif choice == '7':
            export_to_csv()
        elif choice == '8':
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")
