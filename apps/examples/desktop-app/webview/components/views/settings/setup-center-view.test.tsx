// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { it, expect, vi } from "vitest";
const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: calls } }));
import { SetupCenter } from "./setup-center-view";
it("reads status only on open and installs only after explicit notice acceptance", async () => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  calls.mockResolvedValue({
    preferences: null,
    fullStatus: "Setup needed",
    features: [
      {
        id: "qbdi",
        label: "qbdi",
        status: "Setup needed",
        reason: "Owned execution required",
      },
    ],
    packs: [],
    limitations: [],
  });
  const element = document.createElement("div");
  document.body.append(element);
  const root = createRoot(element);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  try {
    await act(async () => root.render(<SetupCenter />));
    expect(calls).toHaveBeenCalledTimes(1);
    expect(calls.mock.calls[0][0]).toBe("setup_center_status");
    const button = [...element.querySelectorAll("button")].find(
      (b) => b.textContent === "Install all supported components",
    )!;
    await act(async () => button.click());
    expect(calls).toHaveBeenCalledTimes(1);
    confirm.mockReturnValue(true);
    await act(async () => button.click());
    expect(confirm.mock.calls.at(-1)?.[0]).toContain("reviewed and accept");
    expect(calls).toHaveBeenCalledWith(
      "setup_center_install_full",
      {
        environmentId: "local",
        confirmed: true,
        acceptedPlatformToolsLicense: true,
      },
      { timeoutMs: 300000 },
    );
    expect(element.textContent).toContain("qbdi: Setup needed");
  } finally {
    confirm.mockRestore();
    await act(async () => root.unmount());
    element.remove();
    calls.mockReset();
  }
});
