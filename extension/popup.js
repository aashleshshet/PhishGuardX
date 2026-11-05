const urlInput = document.getElementById("url");
const result = document.getElementById("result");
const scan = document.getElementById("scan");
document.getElementById("current").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  urlInput.value = tab?.url || "";
  result.textContent = "Review the URL, then choose Analyze URL.";
});
scan.addEventListener("click", async () => {
  if (!urlInput.value.trim()) {
    result.textContent = "Enter a URL first.";
    return;
  }
  scan.disabled = true;
  result.textContent = "Analyzing without visiting the destination…";
  try {
    const response = await fetch("https://phishguardx-pi.vercel.app/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "url", content: urlInput.value }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await response.json();
    if (!response.ok)
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : "Analysis is unavailable.",
      );
    result.textContent =
      data.summary +
      "\n\n" +
      data.signals
        .map((s) => "• " + s.title + ": " + s.description)
        .join("\n\n") +
      "\n\nMissing checks: " +
      data.unavailable.join(", ");
  } catch (error) {
    result.textContent = error.message || "The scan failed. Try again.";
  } finally {
    scan.disabled = false;
  }
});
