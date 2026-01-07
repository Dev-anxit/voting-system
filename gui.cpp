#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <map>

class VotingApp : public QWidget {
    Q_OBJECT

public:
    VotingApp(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("🗳️ Voting System");
        resize(350, 300);

        QVBoxLayout *layout = new QVBoxLayout(this);
        QLabel *title = new QLabel("<h2>Vote for your favorite candidate</h2>");
        layout->addWidget(title);

        candidates = {"Alice", "Bob", "Charlie"};

        for (const QString &name : candidates) {
            QPushButton *btn = new QPushButton(name);
            layout->addWidget(btn);
            connect(btn, &QPushButton::clicked, this, [=]() { voteFor(name); });
        }

        QPushButton *resultBtn = new QPushButton("Show Results");
        layout->addWidget(resultBtn);
        connect(resultBtn, &QPushButton::clicked, this, &VotingApp::showResults);
    }

private:
    QStringList candidates;
    std::map<QString, int> votes;

    void voteFor(const QString &name) {
        votes[name]++;
        QMessageBox::information(this, "Vote Recorded", "✅ Your vote for " + name + " has been recorded!");
        saveVotes();
    }

    void saveVotes() {
        QFile file("votes.csv");
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            QTextStream out(&file);
            for (auto &p : votes) {
                out << p.first << "," << p.second << "\n";
            }
        }
    }

    void showResults() {
        QString result = "🧾 Current Vote Count:\n\n";
        for (auto &p : votes)
            result += QString("%1 - %2 votes\n").arg(p.first).arg(p.second);
        QMessageBox::information(this, "Results", result);
    }
};

#include "moc_gui.cpp"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingApp window;
    window.show();
    return app.exec();
}

