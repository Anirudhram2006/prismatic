const scenarioSelect = document.getElementById("scenarioSelect");
const runBtn = document.getElementById("runBtn");
const loadingMessage = document.getElementById("loadingMessage");
const errorMessage = document.getElementById("errorMessage");

const snapshotCards = document.getElementById("snapshotCards");
const timeline = document.getElementById("timeline");
const predictions = document.getElementById("predictions");
const simulationSummary = document.getElementById("simulationSummary");
const storyMode = document.getElementById("storyMode");
const investigationSummary = document.getElementById("investigationSummary");
const chatWindow = document.getElementById("chatWindow");
const chatInput = document.getElementById("chatInput");
const sendChatBtn = document.getElementById("sendChatBtn");

const STAGE_SEQUENCE = [
  "suspicious_login",
  "malicious_execution",
  "persistence",
  "privilege_escalation",
  "lateral_movement",
  "data_access",
  "data_exfiltration",
];

const STAGE_VISUALS = {
  suspicious_login: { icon: "SL", hint: "A login happened in a risky way." },
  malicious_execution: { icon: "ME", hint: "A suspicious action may be running." },
  persistence: { icon: "PA", hint: "Someone may be trying to stay inside." },
  privilege_escalation: { icon: "PE", hint: "The path may move toward higher access." },
  lateral_movement: { icon: "LM", hint: "The incident may spread to nearby systems." },
  data_access: { icon: "DA", hint: "Sensitive information may now be reachable." },
  data_exfiltration: { icon: "DE", hint: "Important data could leave the environment." },
};

const SCENARIOS = {
  suspicious_login: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login",
    stages: STAGE_SEQUENCE,
    intro: "Suspicious login signals were grouped into one account compromise incident.",
  },
  lateral_movement: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login with later system movement",
    stages: ["suspicious_login", "malicious_execution", "persistence", "privilege_escalation", "lateral_movement", "data_access"],
    intro: "TwinShield is simulating an incident that has already started moving across systems.",
  },
  privilege_escalation: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login followed by access expansion",
    stages: ["suspicious_login", "malicious_execution", "persistence", "privilege_escalation", "lateral_movement", "data_access", "data_exfiltration"],
    intro: "TwinShield is simulating a path where a compromised account may try to gain stronger access.",
  },
};

const state = {
  simulation: null,
  latestSimulationStep: null,
  isRunning: false,
};

function setLoading(text = "", visible = false) {
  loadingMessage.textContent = text;
  loadingMessage.hidden = !visible;
}

function setError(text = "") {
  errorMessage.textContent = text;
  errorMessage.hidden = !text;
}

function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function renderSnapshot(stepData) {
  const cards = [
    {
      label: "Current Risk",
      value: stepData.security_snapshot.current_risk,
      text: "This is the current level of simulated risk in the virtual environment.",
    },
    {
      label: "Current Stage",
      value: stepData.security_snapshot.current_stage,
      text: "This is the active point in the incident journey.",
    },
    {
      label: "Likely Next Move",
      value: stepData.security_snapshot.likely_next_move,
      text: "This is the next step TwinShield believes is most likely.",
    },
    {
      label: "Best First Action",
      value: "Respond",
      text: stepData.security_snapshot.best_first_action,
    },
  ];

  snapshotCards.innerHTML = cards
    .map(
      (card) => `
        <article class="snapshot-card">
          <span class="mini-label">${card.label}</span>
          <div class="snapshot-value">${card.value}</div>
          <p>${card.text}</p>
        </article>
      `
    )
    .join("");
}

function renderTimeline(stepData) {
  const levelMap = new Map(stepData.timeline_levels.map((level) => [level.stage, level]));

  timeline.innerHTML = STAGE_SEQUENCE.map((stageKey) => {
    const visual = STAGE_VISUALS[stageKey];
    const level = levelMap.get(stageKey);
    const title = level ? level.title : stageKey;
    const description = level ? level.simple_explanation : visual.hint;
    const status = level ? level.status : "Waiting";
    const risk = level ? level.risk_indicator : "Low";
    const classes = [
      "timeline-card",
      status === "Active" ? "current" : "",
      status === "Waiting" ? "" : "predicted",
    ]
      .filter(Boolean)
      .join(" ");

    return `
      <article class="${classes}">
        <div class="stage-icon">${visual.icon}</div>
        <h3>${title}</h3>
        <p>${description}</p>
        <div class="timeline-status">${status}</div>
        <p><strong>Risk:</strong> ${risk}</p>
      </article>
    `;
  }).join("");
}

function renderPredictions(stepData) {
  predictions.innerHTML = stepData.predictions
    .map(
      (prediction) => `
        <article class="prediction-card">
          <span class="impact-pill">${stepData.risk_level}</span>
          <h3>${prediction.title}</h3>
          <p>${prediction.description}</p>
          <div class="probability-bar" aria-hidden="true">
            <div class="probability-fill" style="width: ${formatPercent(prediction.probability)};"></div>
          </div>
          <p><strong>${formatPercent(prediction.probability)} likely.</strong> Simulation indicates this is a high-interest path.</p>
          <p><strong>Suggested response:</strong> ${stepData.security_snapshot.best_first_action}</p>
        </article>
      `
    )
    .join("");
}

function renderSimulationSummary(stepData) {
  const items = [
    ["Paths Tested", stepData.simulation_summary.paths_tested],
    ["High-Risk Paths", stepData.simulation_summary.high_risk_paths],
    ["Next Move ETA", stepData.simulation_summary.next_move_eta],
    ["Confidence Level", stepData.simulation_summary.confidence_level],
  ];

  simulationSummary.innerHTML = items
    .map(
      ([label, value]) => `
        <article class="metric-card">
          <span class="mini-label">${label}</span>
          <strong>${value}</strong>
          <p>TwinShield updates these values as the simulation moves forward.</p>
        </article>
      `
    )
    .join("");
}

function renderStory(stepData) {
  storyMode.innerHTML = `
    <article class="story-card">
      <span class="mini-label">Narrative</span>
      <h3>Safe simulation in progress</h3>
      <p>${stepData.story}</p>
    </article>
    <article class="story-card">
      <span class="mini-label">Unified alert</span>
      <p>Suspicious login + unusual account activity + risky path expansion were grouped into one incident.</p>
    </article>
    <article class="story-card">
      <span class="mini-label">Current effect</span>
      <p>${stepData.effect}</p>
    </article>
  `;
}

function renderInvestigationSummary(stepData) {
  const summary = stepData.investigation_summary;
  const cards = [
    ["Incident Type", summary.incident_type],
    ["Root Cause", summary.root_cause],
    ["Current Stage", summary.current_stage],
    ["Predicted Outcome", summary.predicted_outcome],
    ["Risk Level", summary.risk_level],
    ["Recommended Action", summary.recommended_action],
  ];

  investigationSummary.innerHTML = cards
    .map(
      ([label, value]) => `
        <article class="snapshot-card">
          <span class="mini-label">${label}</span>
          <div class="snapshot-value">${value}</div>
        </article>
      `
    )
    .join("");
}

function addMessage(role, text) {
  const bubble = document.createElement("article");
  bubble.className = `chat-bubble ${role}`;
  bubble.innerHTML = `
    <div class="chat-role">${role === "assistant" ? "TwinShield Assistant" : "You"}</div>
    <p>${text}</p>
  `;
  chatWindow.appendChild(bubble);
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

function chatbotReply(question) {
  const lower = question.toLowerCase().trim();
  const stepData = state.latestSimulationStep;

  if (!stepData) {
    return "Run the safe simulation first. Then I can explain the incident in simple English.";
  }

  if (lower.includes("what is happening")) {
    return stepData.chatbot_context.what_is_happening;
  }

  if (lower.includes("danger")) {
    return stepData.chatbot_context.is_this_dangerous;
  }

  if (lower.includes("what should i do")) {
    return stepData.chatbot_context.what_should_i_do;
  }

  if (lower.includes("why")) {
    return stepData.chatbot_context.why_did_this_happen;
  }

  if (lower.includes("simple") || lower.includes("explain")) {
    return `${stepData.stage_label} means ${stepData.effect.toLowerCase()}`;
  }

  return "I can explain what is happening, why TwinShield flagged it, how risky it is, and what to do next.";
}

function handleChatSubmit(questionOverride = "") {
  const question = questionOverride || chatInput.value.trim();
  if (!question) {
    return;
  }

  addMessage("user", question);
  const answer = chatbotReply(question);
  window.setTimeout(() => addMessage("assistant", answer), 180);
  chatInput.value = "";
}

function renderInitialState() {
  snapshotCards.innerHTML = `
    <article class="snapshot-card">
      <span class="mini-label">Current Risk</span>
      <div class="snapshot-value">Waiting</div>
      <p>No active incident is being simulated.</p>
    </article>
    <article class="snapshot-card">
      <span class="mini-label">Current Stage</span>
      <div class="snapshot-value">Ready</div>
      <p>Run the simulation to begin the safe digital twin journey.</p>
    </article>
    <article class="snapshot-card">
      <span class="mini-label">Likely Next Move</span>
      <div class="snapshot-value">Unknown</div>
      <p>TwinShield will show the next likely step after the first stage.</p>
    </article>
    <article class="snapshot-card">
      <span class="mini-label">Best First Action</span>
      <div class="snapshot-value">Monitor</div>
      <p>The virtual environment is standing by.</p>
    </article>
  `;

  timeline.innerHTML = STAGE_SEQUENCE.map((stageKey) => `
    <article class="timeline-card">
      <div class="stage-icon">${STAGE_VISUALS[stageKey].icon}</div>
      <h3>${stageKey.replaceAll("_", " ")}</h3>
      <p>${STAGE_VISUALS[stageKey].hint}</p>
      <div class="timeline-status">Waiting</div>
      <p><strong>Risk:</strong> Pending</p>
    </article>
  `).join("");

  predictions.innerHTML = `
    <article class="prediction-card">
      <h3>No predictions yet</h3>
      <p>Run the simulation to see how the virtual incident may progress.</p>
    </article>
  `;

  simulationSummary.innerHTML = `
    <article class="metric-card"><span class="mini-label">Paths Tested</span><strong>0</strong><p>No simulation has been run yet.</p></article>
    <article class="metric-card"><span class="mini-label">High-Risk Paths</span><strong>0</strong><p>These values appear after stage execution.</p></article>
    <article class="metric-card"><span class="mini-label">Next Move ETA</span><strong>-</strong><p>Available during simulation.</p></article>
    <article class="metric-card"><span class="mini-label">Confidence Level</span><strong>-</strong><p>Available during simulation.</p></article>
  `;

  storyMode.innerHTML = `
    <article class="story-card">
      <span class="mini-label">Story</span>
      <h3>Waiting for simulation</h3>
      <p>TwinShield will explain the incident journey in calm, simple language.</p>
    </article>
  `;

  investigationSummary.innerHTML = `
    <article class="snapshot-card">
      <span class="mini-label">Incident Type</span>
      <div class="snapshot-value">Not started</div>
    </article>
    <article class="snapshot-card">
      <span class="mini-label">Root Cause</span>
      <div class="snapshot-value">Waiting for simulation</div>
    </article>
  `;

  chatWindow.innerHTML = "";
  addMessage("assistant", "Hello. I can explain this safe simulation in plain English. Run the simulation and ask me what is happening, whether it is dangerous, or what to do next.");
}

function delay(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function fetchSimulationStep(stage, scenario) {
  const response = await fetch("/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      stage,
      incident_type: scenario.incident_type,
    }),
  });

  if (!response.ok) {
    throw new Error("Failed to simulate stage");
  }

  return response.json();
}

function renderSimulationStep(stepData) {
  state.latestSimulationStep = stepData;
  renderSnapshot(stepData);
  renderTimeline(stepData);
  renderPredictions(stepData);
  renderSimulationSummary(stepData);
  renderStory(stepData);
  renderInvestigationSummary(stepData);
}

async function runSimulation() {
  if (state.isRunning) {
    return;
  }

  const scenario = SCENARIOS[scenarioSelect.value];
  state.isRunning = true;
  runBtn.disabled = true;
  setError("");
  chatWindow.innerHTML = "";
  addMessage("assistant", scenario.intro);

  try {
    for (const stage of scenario.stages) {
      setLoading(`Simulating ${stage.replaceAll("_", " ")} in the virtual environment...`, true);
      const stepData = await fetchSimulationStep(stage, scenario);
      renderSimulationStep(stepData);
      addMessage("assistant", stepData.story);
      await delay(850);
    }

    setLoading("Simulation complete. Final prediction is ready.", true);
    await delay(900);
    setLoading("", false);
  } catch (error) {
    setLoading("", false);
    setError("TwinShield could not complete the safe simulation.");
  } finally {
    runBtn.disabled = false;
    state.isRunning = false;
  }
}

runBtn.addEventListener("click", runSimulation);
sendChatBtn.addEventListener("click", () => handleChatSubmit());
chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    handleChatSubmit();
  }
});

document.querySelectorAll(".suggestion-btn").forEach((button) => {
  button.addEventListener("click", () => handleChatSubmit(button.dataset.question));
});

renderInitialState();
