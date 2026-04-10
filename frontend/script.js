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

const sceneTitle = document.getElementById("sceneTitle");
const sceneNarrative = document.getElementById("sceneNarrative");
const sceneStageCode = document.getElementById("sceneStageCode");
const liveFeed = document.getElementById("liveFeed");
const riskMeterFill = document.getElementById("riskMeterFill");
const riskMeterLabel = document.getElementById("riskMeterLabel");
const riskMeterScore = document.getElementById("riskMeterScore");
const simulationPulse = document.getElementById("simulationPulse");

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
  suspicious_login: { icon: "SL", hint: "A login happened in a risky way.", code: "SL", alert: "Credential use pattern changed", route: "Identity path exposed" },
  malicious_execution: { icon: "ME", hint: "A suspicious action may be running.", code: "ME", alert: "Potential tool execution detected", route: "Endpoint behavior changed" },
  persistence: { icon: "PA", hint: "Someone may be trying to stay inside.", code: "PA", alert: "Longer-term presence simulated", route: "Return path being prepared" },
  privilege_escalation: { icon: "PE", hint: "The path may move toward higher access.", code: "PE", alert: "Access level rising in simulation", route: "Privilege boundary under pressure" },
  lateral_movement: { icon: "LM", hint: "The incident may spread to nearby systems.", code: "LM", alert: "Connected systems now reachable", route: "Internal route expansion detected" },
  data_access: { icon: "DA", hint: "Sensitive information may now be reachable.", code: "DA", alert: "Potential access to sensitive data", route: "Data layer now in range" },
  data_exfiltration: { icon: "DE", hint: "Important data could leave the environment.", code: "DE", alert: "Exposure path near completion", route: "Outbound risk path created" },
};

const SCENARIOS = {
  suspicious_login: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login",
    stages: STAGE_SEQUENCE,
    intro: "TwinShield is constructing a safe simulation from the first suspicious login signal.",
  },
  lateral_movement: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login with later system movement",
    stages: ["suspicious_login", "malicious_execution", "persistence", "privilege_escalation", "lateral_movement", "data_access"],
    intro: "TwinShield is constructing a simulation where the incident has already started spreading across systems.",
  },
  privilege_escalation: {
    incident_type: "Account Compromise",
    root_cause: "Suspicious login followed by access expansion",
    stages: ["suspicious_login", "malicious_execution", "persistence", "privilege_escalation", "lateral_movement", "data_access", "data_exfiltration"],
    intro: "TwinShield is constructing a high-risk simulation where stronger access is being pursued.",
  },
};

const state = {
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

function stageLabel(stageKey) {
  return stageKey.replaceAll("_", " ");
}

function renderSnapshot(stepData) {
  const cards = [
    {
      label: "Current Risk",
      value: stepData.security_snapshot.current_risk,
      text: "Current level of simulated exposure inside the digital twin.",
    },
    {
      label: "Current Stage",
      value: stepData.security_snapshot.current_stage,
      text: "The live stage TwinShield is actively constructing.",
    },
    {
      label: "Likely Next Move",
      value: stepData.security_snapshot.likely_next_move,
      text: "Most likely continuation based on the tested paths.",
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
    const title = level ? level.title : stageLabel(stageKey);
    const description = level ? level.simple_explanation : visual.hint;
    const status = level ? level.status : "Waiting";
    const risk = level ? level.risk_indicator : "Pending";
    const classes = [
      "timeline-card",
      status === "Active" ? "current" : "",
      status !== "Waiting" ? "predicted" : "",
    ].filter(Boolean).join(" ");

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
          <p><strong>${formatPercent(prediction.probability)} likely.</strong> Simulation indicates this path is worth close attention.</p>
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
          <p>Updated as each stage is constructed and tested.</p>
        </article>
      `
    )
    .join("");
}

function renderStory(stepData) {
  storyMode.innerHTML = `
    <article class="story-card">
      <span class="mini-label">Narrative</span>
      <h3>Simulation in progress</h3>
      <p>${stepData.story}</p>
    </article>
    <article class="story-card">
      <span class="mini-label">Unified alert</span>
      <p>Suspicious login, unusual account activity, and route expansion signals were grouped into one guided incident path.</p>
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

function renderSimulationScene(stepData) {
  const visual = STAGE_VISUALS[stepData.stage];
  sceneTitle.textContent = `${stepData.stage_label} simulation active`;
  sceneNarrative.textContent = stepData.story;
  sceneStageCode.textContent = visual.code;

  liveFeed.innerHTML = `
    <article class="feed-item">
      <span class="mini-label">Constructed Signal</span>
      <strong>${visual.alert}</strong>
      <p>${stepData.effect}</p>
    </article>
    <article class="feed-item">
      <span class="mini-label">Route Status</span>
      <strong>${visual.route}</strong>
      <p>Next likely move: ${stepData.next_step_label}</p>
    </article>
    <article class="feed-item">
      <span class="mini-label">Affected Systems</span>
      <strong>${stepData.affected_systems.join(", ")}</strong>
      <p>These systems are currently inside the simulated risk path.</p>
    </article>
  `;

  const width = Math.max(12, Math.min(stepData.risk_score * 10, 98));
  riskMeterFill.style.width = `${width}%`;
  riskMeterLabel.textContent = `${stepData.risk_level} Risk`;
  riskMeterScore.textContent = `${stepData.risk_score.toFixed(1)} / 10`;
  simulationPulse.textContent = `${stepData.impact} Confidence is ${stepData.confidence}% for the current projected route.`;
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
      <h3>${stageLabel(stageKey)}</h3>
      <p>${STAGE_VISUALS[stageKey].hint}</p>
      <div class="timeline-status">Waiting</div>
      <p><strong>Risk:</strong> Pending</p>
    </article>
  `).join("");

  predictions.innerHTML = `
    <article class="prediction-card">
      <h3>No predictions yet</h3>
      <p>Run the simulation to see how the virtual incident may progress through the environment.</p>
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

  sceneTitle.textContent = "Awaiting simulation start";
  sceneNarrative.textContent = "TwinShield will correlate suspicious signals, construct an attack path, and project likely movement through the virtual environment.";
  sceneStageCode.textContent = "TS";
  liveFeed.innerHTML = `
    <article class="feed-item">
      <span class="mini-label">Constructed Signal</span>
      <strong>Idle</strong>
      <p>No incident path is being constructed yet.</p>
    </article>
    <article class="feed-item">
      <span class="mini-label">Route Status</span>
      <strong>Standby</strong>
      <p>The digital twin is ready to test possible attacker paths.</p>
    </article>
    <article class="feed-item">
      <span class="mini-label">Affected Systems</span>
      <strong>None</strong>
      <p>Systems will appear here once a simulation stage is active.</p>
    </article>
  `;
  riskMeterFill.style.width = "0%";
  riskMeterLabel.textContent = "Waiting";
  riskMeterScore.textContent = "0.0 / 10";
  simulationPulse.textContent = "No simulation activity yet.";

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
  renderSimulationScene(stepData);
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
      setLoading(`Constructing ${stageLabel(stage)} in the virtual environment...`, true);
      const stepData = await fetchSimulationStep(stage, scenario);
      renderSimulationStep(stepData);
      addMessage("assistant", stepData.story);
      await delay(900);
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
