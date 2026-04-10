const scenarioSelect = document.getElementById("scenarioSelect");
const loadingState = document.getElementById("loadingState");
const errorState = document.getElementById("errorState");

const summaryCards = document.getElementById("summaryCards");
const journeyTimeline = document.getElementById("journeyTimeline");
const simulationMetrics = document.getElementById("simulationMetrics");
const predictionCards = document.getElementById("predictionCards");
const storyMode = document.getElementById("storyMode");
const simplifyList = document.getElementById("simplifyList");
const actionsList = document.getElementById("actionsList");

const state = {
  simpleView: true,
  latestData: null,
};

const scenarios = {
  suspicious_login: {
    type: "Suspicious Login",
    severity: "high",
    event: "Multiple failed login attempts followed by a successful login from an unusual location.",
    source_ip: "185.220.101.47",
    device: "Alice's Laptop",
    user: "alice",
    affected_user: "Alice",
  },
  lateral_movement: {
    type: "Lateral Movement Alert",
    severity: "critical",
    event: "An internal account attempted remote access across multiple servers in quick succession.",
    source_ip: "10.0.1.21",
    device: "App Server",
    user: "service-app",
    affected_user: "Service Account",
  },
  privilege_escalation: {
    type: "Privilege Escalation",
    severity: "critical",
    event: "A user account attempted to add itself to an administrator group.",
    source_ip: "10.0.1.30",
    device: "Active Directory",
    user: "bob",
    affected_user: "Bob",
  },
};

function setLoading(message, isVisible) {
  loadingState.textContent = message;
  loadingState.hidden = !isVisible;
}

function setError(message = "") {
  errorState.textContent = message || "We could not complete the simulation. Please try again.";
  errorState.hidden = !message;
}

function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function riskLabel(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return "Critical";
  if (value === "high") return "High";
  if (value === "medium") return "Watch";
  return "Low";
}

function renderSummary(data) {
  const topPrediction = data.prediction_cards[0];
  const cards = [
    {
      label: "Current Risk",
      value: riskLabel(data.severity),
      text: "A quick view of the current threat level.",
    },
    {
      label: "Likely Next Move",
      value: topPrediction.title,
      text: topPrediction.description,
    },
    {
      label: "Affected Area",
      value: data.source_asset,
      text: `Watching activity linked to ${data.affected_user}.`,
    },
    {
      label: "Recommended Action",
      value: "Lock Account",
      text: data.recommended_actions[0],
    },
  ];

  summaryCards.innerHTML = cards
    .map(
      (card) => `
        <article class="summary-card">
          <div class="metric-label">${card.label}</div>
          <div class="summary-value">${card.value}</div>
          <p>${card.text}</p>
        </article>
      `
    )
    .join("");
}

function renderJourney(data) {
  journeyTimeline.innerHTML = data.timeline
    .map(
      (item, index) => `
        <article class="journey-card ${item.status === "predicted" ? "predicted" : ""}">
          <span class="journey-dot" aria-hidden="true"></span>
          <div class="journey-meta">
            <span class="chip">${index === 0 ? "Detected" : "Predicted Next"}</span>
            <span>${item.simple_stage || item.label}</span>
            <span>${new Date(item.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
          </div>
          <h4>${item.simple_stage || item.label}</h4>
          <p>${item.event}</p>
        </article>
      `
    )
    .join("");
}

function renderMetrics(data) {
  const metrics = [
    ["Paths Tested", data.simulation_summary.paths_tested],
    ["High-Risk Paths", data.simulation_summary.high_risk_paths],
    ["Confidence Score", `${data.simulation_summary.confidence_score}%`],
    ["Next Move ETA", `${data.simulation_summary.time_to_next_move} min`],
  ];

  simulationMetrics.innerHTML = metrics
    .map(
      ([label, value]) => `
        <article class="metric-card">
          <div class="metric-label">${label}</div>
          <div class="metric-value">${value}</div>
        </article>
      `
    )
    .join("");
}

function renderPredictions(data) {
  predictionCards.innerHTML = data.prediction_cards
    .map(
      (card) => `
        <article class="prediction-card">
          <div class="prediction-meta">
            <span class="chip">${card.impact}</span>
            <span>${card.time_window}</span>
            <span title="Confidence Score">${formatPercent(card.probability)} likely</span>
          </div>
          <h4>${state.simpleView ? card.title : card.technical_title}</h4>
          <p>${card.description}</p>
          <div class="probability-bar" aria-hidden="true">
            <div class="probability-fill" style="width: ${formatPercent(card.probability)};"></div>
          </div>
          <p><strong>Why this is likely:</strong> ${card.why}</p>
          <p><strong>What to do:</strong> ${card.next_action}</p>
        </article>
      `
    )
    .join("");
}

function renderStory(data) {
  const chapters = data.story_mode.chapters
    .map(
      (chapter) => `
        <article class="story-card">
          <h4>${chapter.title}</h4>
          <p>${chapter.text}</p>
        </article>
      `
    )
    .join("");

  storyMode.innerHTML = `
    <div class="story-card">
      <div class="chip">Live Story</div>
      <p class="story-narrative">${data.story_mode.narrative}</p>
    </div>
    ${chapters}
  `;
}

function renderSimplify(data) {
  simplifyList.innerHTML = data.simplified_terms
    .map(
      (item) => `
        <article class="simple-card">
          <h4>${state.simpleView ? item.plain_english : item.term}</h4>
          <p>${state.simpleView ? item.analogy : item.plain_english}</p>
        </article>
      `
    )
    .join("");
}

function renderActions(data) {
  actionsList.innerHTML = data.recommended_actions
    .map(
      (action, index) => `
        <article class="action-card">
          <strong>Step ${index + 1}</strong>
          <p>${action}</p>
        </article>
      `
    )
    .join("");
}

function renderDashboard(data) {
  state.latestData = data;
  renderSummary(data);
  renderJourney(data);
  renderMetrics(data);
  renderPredictions(data);
  renderStory(data);
  renderSimplify(data);
  renderActions(data);
}

async function runScenario() {
  const scenario = scenarios[scenarioSelect.value];
  setError();
  setLoading("Scanning live activity...", true);

  try {
    const phases = [
      "Scanning live activity...",
      "Building digital twin simulation...",
      "Testing likely attacker paths...",
      "Turning alerts into plain language...",
    ];

    let phaseIndex = 0;
    const ticker = window.setInterval(() => {
      phaseIndex = (phaseIndex + 1) % phases.length;
      setLoading(phases[phaseIndex], true);
    }, 700);

    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scenario),
    });

    window.clearInterval(ticker);

    if (!response.ok) {
      throw new Error("Simulation failed");
    }

    const data = await response.json();
    renderDashboard(data);
    setLoading("Analysis complete. Threat path updated.", true);
    window.setTimeout(() => setLoading("", false), 1200);
  } catch (error) {
    setLoading("", false);
    setError("TwinShield lost connection to the demo environment.");
  }
}

function resetDemo() {
  summaryCards.innerHTML = `
    <article class="summary-card">
      <div class="metric-label">Current Risk</div>
      <div class="summary-value">Waiting</div>
      <p>No active threat detected right now.</p>
    </article>
    <article class="summary-card">
      <div class="metric-label">Likely Next Move</div>
      <div class="summary-value">No Prediction</div>
      <p>Run an analysis to simulate possible next steps.</p>
    </article>
    <article class="summary-card">
      <div class="metric-label">Affected Area</div>
      <div class="summary-value">Stable</div>
      <p>Your environment looks stable. TwinShield is still watching.</p>
    </article>
    <article class="summary-card">
      <div class="metric-label">Recommended Action</div>
      <div class="summary-value">Monitor</div>
      <p>No action needed right now, but monitoring continues.</p>
    </article>
  `;

  journeyTimeline.innerHTML = `
    <article class="journey-card">
      <span class="journey-dot" aria-hidden="true"></span>
      <div class="journey-meta"><span class="chip">Ready</span></div>
      <h4>No attacker movement detected yet.</h4>
      <p>TwinShield will map suspicious activity here once analysis begins.</p>
    </article>
  `;

  simulationMetrics.innerHTML = `
    <article class="metric-card"><div class="metric-label">Paths Tested</div><div class="metric-value">0</div></article>
    <article class="metric-card"><div class="metric-label">High-Risk Paths</div><div class="metric-value">0</div></article>
    <article class="metric-card"><div class="metric-label">Confidence Score</div><div class="metric-value">-</div></article>
    <article class="metric-card"><div class="metric-label">Next Move ETA</div><div class="metric-value">-</div></article>
  `;

  predictionCards.innerHTML = `
    <article class="prediction-card">
      <h4>No predictions yet.</h4>
      <p>TwinShield is ready to run attack paths through the digital twin.</p>
    </article>
  `;

  storyMode.innerHTML = `
    <article class="story-card">
      <div class="chip">Story Mode</div>
      <p class="story-narrative">This scenario shows how TwinShield turns a suspicious signal into a clear story, predicts what may happen next, and helps teams act early.</p>
    </article>
  `;

  simplifyList.innerHTML = `
    <article class="simple-card">
      <h4>Simple explanations will appear here.</h4>
      <p>Switch to Simple View any time you want plain-English guidance.</p>
    </article>
  `;

  actionsList.innerHTML = `
    <article class="action-card">
      <strong>Waiting for incident</strong>
      <p>Recommended actions will appear after analysis.</p>
    </article>
  `;
}

document.getElementById("runAnalysisBtn").addEventListener("click", runScenario);
document.getElementById("replayBtn").addEventListener("click", runScenario);
document.getElementById("resetBtn").addEventListener("click", () => {
  setLoading("", false);
  setError();
  resetDemo();
});
document.getElementById("storyModeBtn").addEventListener("click", () => {
  document.querySelector(".panel-story").scrollIntoView({ behavior: "smooth", block: "start" });
});
document.getElementById("simplifyBtn").addEventListener("click", () => {
  state.simpleView = true;
  if (state.latestData) renderDashboard(state.latestData);
  document.querySelector(".panel-simple").scrollIntoView({ behavior: "smooth", block: "start" });
});
document.getElementById("simpleViewBtn").addEventListener("click", () => {
  state.simpleView = true;
  if (state.latestData) renderDashboard(state.latestData);
});
document.getElementById("technicalViewBtn").addEventListener("click", () => {
  state.simpleView = false;
  if (state.latestData) renderDashboard(state.latestData);
});

resetDemo();
