const candidates = [
    { id: 'alice', name: 'Alice', icon: 'fa-user-tie' },
    { id: 'bob', name: 'Bob', icon: 'fa-user-astronaut' },
    { id: 'charlie', name: 'Charlie', icon: 'fa-user-ninja' },
    { id: 'david', name: 'David', icon: 'fa-user-secret' }
];

let votes = JSON.parse(localStorage.getItem('votingApp_votes')) || {};

// Initialize votes if empty
candidates.forEach(c => {
    if (typeof votes[c.id] === 'undefined') {
        votes[c.id] = 0;
    }
});

const candidatesGrid = document.getElementById('candidatesGrid');
const resultsContainer = document.getElementById('resultsContainer');
const votingSection = document.getElementById('votingSection');
const resultsSection = document.getElementById('resultsSection');
const showResultsBtn = document.getElementById('showResultsBtn');
const backBtn = document.getElementById('backBtn');
const resetBtn = document.getElementById('resetBtn');
const toastContainer = document.getElementById('toastContainer');

function saveVotes() {
    localStorage.setItem('votingApp_votes', JSON.stringify(votes));
}

function renderCandidates() {
    candidatesGrid.innerHTML = '';
    candidates.forEach((candidate, index) => {
        const card = document.createElement('div');
        card.className = 'candidate-card';
        card.style.animationDelay = `${index * 0.1}s`;
        card.classList.add('fade-in');
        
        card.innerHTML = `
            <i class="fas ${candidate.icon} candidate-icon"></i>
            <h3 class="candidate-name">${candidate.name}</h3>
        `;
        
        card.addEventListener('click', () => handleVote(candidate.id, candidate.name));
        candidatesGrid.appendChild(card);
    });
}

function handleVote(id, name) {
    votes[id]++;
    saveVotes();
    showToast(`Vote safely recorded for ${name}!`);
    
    // Add a quick pulse effect to the app container
    const appContainer = document.querySelector('.app-container');
    appContainer.style.transform = 'scale(0.98)';
    setTimeout(() => {
        appContainer.style.transform = 'scale(1)';
    }, 150);
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<i class="fas fa-check-circle"></i> <span>${message}</span>`;
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3500);
}

function renderResults() {
    resultsContainer.innerHTML = '';
    
    // Calculate total votes
    const totalVotes = Object.values(votes).reduce((a, b) => a + b, 0);
    
    // Sort candidates by votes (descending)
    const sortedCandidates = [...candidates].sort((a, b) => votes[b.id] - votes[a.id]);
    
    if (totalVotes === 0) {
        resultsContainer.innerHTML = '<p style="text-align:center; color: var(--text-secondary); margin-bottom: 2rem;">No votes cast yet.</p>';
        return;
    }

    sortedCandidates.forEach((candidate, index) => {
        const candidateVotes = votes[candidate.id];
        const percentage = totalVotes > 0 ? Math.round((candidateVotes / totalVotes) * 100) : 0;
        
        const resultItem = document.createElement('div');
        resultItem.className = 'result-item fade-in';
        resultItem.style.animationDelay = `${index * 0.1}s`;
        
        // Define colors based on rank
        let barColors = 'linear-gradient(90deg, var(--accent-primary), var(--accent-secondary))';
        if (index === 0 && candidateVotes > 0) {
            barColors = 'linear-gradient(90deg, #fbbf24, #f59e0b)'; // Gold for 1st
        }
        
        resultItem.innerHTML = `
            <div class="result-info">
                <span>${candidate.name}</span>
                <span>${candidateVotes} votes (${percentage}%)</span>
            </div>
            <div class="progress-bar-container">
                <div class="progress-bar" style="width: 0%; background: ${barColors}" data-target="${percentage}%"></div>
            </div>
        `;
        
        resultsContainer.appendChild(resultItem);
    });

    resultsContainer.style.marginBottom = '2rem';

    // Animate progress bars after a small delay
    setTimeout(() => {
        document.querySelectorAll('.progress-bar').forEach(bar => {
            bar.style.width = bar.getAttribute('data-target');
        });
    }, 100);
}

// Event Listeners
showResultsBtn.addEventListener('click', () => {
    votingSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');
    renderResults();
});

backBtn.addEventListener('click', () => {
    resultsSection.classList.add('hidden');
    votingSection.classList.remove('hidden');
});

resetBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to completely reset all votes? This action cannot be undone.')) {
        candidates.forEach(c => votes[c.id] = 0);
        saveVotes();
        renderResults();
        
        // Change toast momentarily to danger style to reflect reset
        const tempColor = document.documentElement.style.getPropertyValue('--success-color');
        document.documentElement.style.setProperty('--success-color', '#ef4444');
        showToast('All votes have been reset.');
        setTimeout(() => {
            document.documentElement.style.setProperty('--success-color', tempColor || '#10b981');
        }, 3500);
    }
});

// Initialize
renderCandidates();
