#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <string>
#include <cctype>

using namespace std;

static inline string trim(string s) {
    auto notspace = [](int ch){ return !isspace(ch); };
    s.erase(s.begin(), find_if(s.begin(), s.end(), notspace));
    s.erase(find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
    return s;
}
static inline string lower(string s){ for(char &c: s) c=(char)tolower(c); return s; }

void loadVotes(const string& path, map<string,int>& votes) {
    ifstream in(path);
    if (!in) return;
    string line;
    while (getline(in, line)) {
        auto comma = line.find(',');
        if (comma == string::npos) continue;
        string name = line.substr(0, comma);
        int count = stoi(line.substr(comma+1));
        votes[name] = count;
    }
}
void saveVotes(const string& path, const map<string,int>& votes) {
    ofstream out(path, ios::trunc);
    for (auto &p : votes) out << p.first << "," << p.second << "\n";
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    vector<string> candidates = {"Alice", "Bob", "Charlie"};

    map<string,int> votes;
    unordered_map<string,string> canonical;
    for (auto &c : candidates) {
        votes[c] = 0;
        canonical[lower(c)] = c;
    }

    // Load previous counts if any
    loadVotes("votes.csv", votes);

    set<string> voters;
    int numVoters;
    cout << "Enter number of voters: ";
    if (!(cin >> numVoters) || numVoters < 0) {
        cerr << "Invalid number.\n";
        return 1;
    }
    string dummy; getline(cin, dummy);

    for (int i = 0; i < numVoters; ++i) {
        cout << "\nEnter your Voter ID: ";
        string voterId; getline(cin, voterId);
        voterId = trim(voterId);
        if (voterId.empty()) { cout << "Invalid ID.\n"; --i; continue; }

        // In-memory duplicate prevention
        if (voters.count(voterId)) { cout << "⚠️  Already voted.\n"; continue; }

        cout << "Candidates: ";
        for (auto &c : candidates) cout << c << " ";
        cout << "\nEnter your chosen candidate: ";

        string choice; getline(cin, choice);
        choice = lower(trim(choice));

        if (canonical.count(choice)) {
            string original = canonical[choice];
            votes[original]++;
            voters.insert(voterId);
            cout << "✅ Vote recorded for " << original << ".\n";
        } else {
            cout << "❌ Invalid candidate.\n";
        }
    }

    cout << "\n🧾 Final Vote Count:\n";
    for (auto &p : votes) cout << p.first << " - " << p.second << " votes\n";

    vector<pair<string,int>> ranked(votes.begin(), votes.end());
    sort(ranked.begin(), ranked.end(),
         [](auto &a, auto &b){ return a.second > b.second; });

    if (!ranked.empty()) {
        cout << "\n🏅 Ranking:\n";
        for (size_t i = 0; i < ranked.size(); ++i)
            cout << i+1 << ". " << ranked[i].first << " (" << ranked[i].second << ")\n";
        cout << "\n🏆 Winner: " << ranked.front().first
             << " with " << ranked.front().second << " votes!\n";
    } else {
        cout << "\nNo votes cast.\n";
    }

    // Save counts
    saveVotes("votes.csv", votes);
    cout << "\n🗂  Saved vote totals to votes.csv\n";
    return 0;
}
